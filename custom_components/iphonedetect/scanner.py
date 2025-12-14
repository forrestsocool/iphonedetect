"""iPhone Detect Scanner."""

from __future__ import annotations

import asyncio
import logging
import socket
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Protocol, Sequence

from homeassistant.util import dt as dt_util
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from pyroute2 import IPRoute
import aiohttp
import json
import ssl

from .const import DOMAIN, CONF_OPNSENSE_URL, CONF_OPNSENSE_KEY, CONF_OPNSENSE_SECRET

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

CMD_IP_NEIGH = "ip -4 neigh show nud reachable"
CMD_ARP = "arp -ne"


@dataclass(slots=True, kw_only=True)
class DeviceData:
    ip_address: str
    consider_home: timedelta
    title: str
    _reachable: bool = False
    _last_seen: datetime | None = None


async def pinger(loop: asyncio.AbstractEventLoop, ip_addresses: list[str]) -> None:
    transport, _ = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), family=socket.AF_INET)
    for ip_address in ip_addresses:
        try:
            transport.sendto(b"ping", (ip_address, 5353))
        except Exception as e:
            _LOGGER.error(f"Failed to ping {ip_address}", e)

    transport.close()


async def get_arp_subprocess(cmd: Sequence) -> list[str]:
    """Return list of IPv4 devices reachable by the network."""
    response = []
    if isinstance(cmd, str):
        cmd = cmd.split()

    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, close_fds=False)

        async with asyncio.timeout(2):
            result, _ = await proc.communicate()
        if result:
            response = result.decode().splitlines()
    except Exception as exc:
        _LOGGER.debug("Exception on ARP lookup: %s", exc)

    return response


class ScannerException(Exception):
    """Scanner exception."""


class Scanner(Protocol):
    """Scanner class for getting ARP cache records."""

    async def get_arp_records(self, hass: HomeAssistant) -> list[str]:
        """Return list of IPv4 devices reachable by the network."""
        return []


class ScannerIPRoute:
    """Get ARP cache records using pyroute2."""

    def _get_arp_records(self) -> list[str]:
        """Return list of IPv4 devices reachable by the network."""
        response = []
        try:
            with closing(IPRoute()) as ipr:
                result = ipr.get_neighbours(family=socket.AF_INET, match=lambda x: x["state"] == 2)
            response = [dev["attrs"][0][1] for dev in result]
        except Exception as exc:
            _LOGGER.debug("Exception on ARP lookup: %s", exc)

        return response

    async def get_arp_records(self, hass: HomeAssistant) -> list[str]:
        """Return list of IPv4 devices reachable by the network."""
        response = await hass.async_add_executor_job(self._get_arp_records)
        return response


class ScannerIPNeigh:
    """Get ARP cache records using subprocess."""

    async def get_arp_records(self, hass: HomeAssistant = None) -> list[str]:
        """Return list of IPv4 devices reachable by the network."""
        response = []
        result = await get_arp_subprocess(CMD_IP_NEIGH.split())
        if result:
            response = [row.split()[0] for row in result if row.count(":") == 5]

        return response


class ScannerArp:
    """Get ARP cache records using subprocess."""

    async def get_arp_records(self, hass: HomeAssistant = None) -> list[str]:
        """Return list of IPv4 devices reachable by the network."""
        response = []
        result = await get_arp_subprocess(CMD_ARP.split())
        if result:
            response = [row.split()[0] for row in result if row.count(":") == 5]

        return response


async def async_update_devices(hass: HomeAssistant, scanner: Scanner, devices: dict[str, DeviceData]) -> None:
    """Update reachability for all tracked devices."""
    ip_addresses = [device.ip_address for device in devices.values()]

    # Ping devices
    _LOGGER.debug("Pinging devices: %s", ip_addresses)
    await pinger(hass.loop, ip_addresses)

    # Get devices found in ARP
    _LOGGER.debug("Fetching ARP records with %s", scanner.__class__.__name__)
    arp_records = await scanner.get_arp_records(hass)
    _LOGGER.debug("ARP response has %d records", len(arp_records))

    # Only keep reachable tracked devices
    reachable_ip = set(ip_addresses).intersection(arp_records)
    _LOGGER.debug("Matched %d tracked devices: %s", len(reachable_ip), reachable_ip)

    # Update reachable devices
    for device in devices.values():
        device._reachable = device.ip_address in reachable_ip
        if device._reachable:
            device._last_seen = dt_util.utcnow()


class ScannerOpnsense:
    """Get ARP cache records from OPNsense API."""

    def __init__(self, url: str, key: str, secret: str) -> None:
        self.url = url
        self.key = key
        self.secret = secret

    async def get_arp_records(self, hass: HomeAssistant) -> list[str]:
        """Return list of IPv4 devices reachable by the network."""
        response_ips = []
        try:
            session = async_get_clientsession(hass, verify_ssl=False)
            auth = aiohttp.BasicAuth(self.key, self.secret)
            async with session.get(self.url, auth=auth, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    # Parse OPNsense response
                    # Format: {"rows": [{"mac": "...", "ip": "...", ...}, ...]}
                    if "rows" in data:
                        response_ips = [item["ip"] for item in data["rows"] if "ip" in item]
                    else:
                        _LOGGER.debug("OPNsense response missing 'rows' key: %s", data)
                else:
                    _LOGGER.debug("OPNsense API returned status: %s", response.status)

        except Exception as exc:
            _LOGGER.debug("Exception on OPNsense ARP lookup: %s", exc)

        return response_ips


class ScannerSmart:
    """Scanner that tries OPNsense first, then falls back to local scanner."""

    def __init__(self, primary_scanner: Scanner | None, fallback_scanner: Scanner) -> None:
        self.primary_scanner = primary_scanner
        self.fallback_scanner = fallback_scanner

    async def get_arp_records(self, hass: HomeAssistant) -> list[str]:
        """Return list of IPv4 devices reachable by the network."""
        records = []
        
        if self.primary_scanner:
            records = await self.primary_scanner.get_arp_records(hass)
            if records:
                return records
            _LOGGER.debug("Primary scanner returned no records, falling back.")

        return await self.fallback_scanner.get_arp_records(hass)



async def async_get_scanner(hass: HomeAssistant) -> Scanner:
    """Return Scanner to use."""
    local_scanner = None

    if await ScannerIPRoute().get_arp_records(hass):
        local_scanner = ScannerIPRoute()

    elif await ScannerIPNeigh().get_arp_records():
        local_scanner = ScannerIPNeigh()

    elif await ScannerArp().get_arp_records():
        local_scanner = ScannerArp()
    
    if local_scanner is None:
        raise ScannerException("No local scanner tool available")

    # Check for OPNsense config
    opnsense_scanner = None
    entries = hass.config_entries.async_entries(DOMAIN)
    for entry in entries:
        options = entry.options
        if options.get(CONF_OPNSENSE_URL) and options.get(CONF_OPNSENSE_KEY) and options.get(CONF_OPNSENSE_SECRET):
            opnsense_scanner = ScannerOpnsense(
                options[CONF_OPNSENSE_URL],
                options[CONF_OPNSENSE_KEY],
                options[CONF_OPNSENSE_SECRET]
            )
            break
            
    return ScannerSmart(opnsense_scanner, local_scanner)

