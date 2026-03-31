"""Config flow for iPhone Device Tracker integration."""

import logging
import re
from ipaddress import AddressValueError, IPv4Address, IPv4Network, ip_interface
from typing import Any

import voluptuous as vol
from homeassistant.components import network
from homeassistant.components.device_tracker.const import (
    CONF_CONSIDER_HOME,
)
from homeassistant.components.network.const import MDNS_TARGET_IP
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    FlowResult,
)
from homeassistant.const import (
    CONF_IP_ADDRESS,
    CONF_NAME,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.schema_config_entry_flow import (
    SchemaFlowFormStep,
    SchemaOptionsFlowHandler,
)
from homeassistant.util import slugify

from .const import (
    DEFAULT_CONSIDER_HOME,
    DOMAIN,
    CONF_OPNSENSE_URL,
    CONF_OPNSENSE_KEY,
    CONF_OPNSENSE_SECRET,
    CONF_MAC_ADDRESS,
    CONF_MAC_ADDRESS_2,
    CONF_MAC_ADDRESS_3,
)


_LOGGER = logging.getLogger(__name__)

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


OPTIONS_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CONSIDER_HOME, default=DEFAULT_CONSIDER_HOME): int
    }
)

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_NAME, description={"suggested_value": "My iPhone"}): str,
        vol.Required(CONF_MAC_ADDRESS, description={"suggested_value": "00:11:22:33:44:55"}): str,
        vol.Optional(CONF_MAC_ADDRESS_2, description={"suggested_value": ""}): str,
        vol.Optional(CONF_MAC_ADDRESS_3, description={"suggested_value": ""}): str,
        vol.Optional(CONF_IP_ADDRESS, description={"suggested_value": "192.168.1.xx"}): str,
        **OPTIONS_SCHEMA.schema,
        vol.Optional("subnet_check", default=True): bool,
        vol.Optional(CONF_OPNSENSE_URL): str,
        vol.Optional(CONF_OPNSENSE_KEY): str,
        vol.Optional(CONF_OPNSENSE_SECRET): str,
    }
)

OPTIONS_FLOW = {
    "init": SchemaFlowFormStep(OPTIONS_SCHEMA),
}


async def async_get_networks(hass: HomeAssistant) -> list[IPv4Network]:
    """Search adapters for the networks."""
    networks = []
    local_ip = await network.async_get_source_ip(hass, MDNS_TARGET_IP)

    for adapter in await network.async_get_adapters(hass):
        for ipv4 in adapter["ipv4"]:
            if ipv4["address"] == local_ip or ipv4["address"] is not None:
                network_prefix = ipv4["network_prefix"]
                networks.append(ip_interface(f"{ipv4['address']}/{network_prefix}").network)

    return networks


async def _validate_input(
    hass: HomeAssistant,
    user_input: dict[str, Any],
    exclude_entry_id: str | None = None,
) -> dict[str, str] | None:
    """Try to validate user input.

    Args:
        exclude_entry_id: entry_id to exclude from uniqueness checks (used during reconfigure).
    """
    entries = [
        entry for entry in hass.config_entries.async_entries(DOMAIN)
        if entry.entry_id != exclude_entry_id
    ]
    mac = user_input.get(CONF_MAC_ADDRESS)
    mac2 = user_input.get(CONF_MAC_ADDRESS_2, "") or ""
    mac3 = user_input.get(CONF_MAC_ADDRESS_3, "") or ""
    ip = user_input.get(CONF_IP_ADDRESS)

    # Check if name already used for a clearer error
    if user_input.get(CONF_NAME, False):
        entries_id = [entry.unique_id for entry in entries]
        entry_id = f"{DOMAIN}_{slugify(user_input[CONF_NAME]).lower()}"
        if entry_id in entries_id:
            return {"base": "name_not_unique"}

    # Validate MAC format for primary MAC
    if mac and not MAC_REGEX.match(mac):
        return {"base": "mac_invalid"}

    # Validate MAC format for optional backup MACs
    if mac2 and not MAC_REGEX.match(mac2):
        return {"base": "mac2_invalid"}
    if mac3 and not MAC_REGEX.match(mac3):
        return {"base": "mac3_invalid"}

    # Collect all MACs from other entries for uniqueness check
    existing_macs: set[str] = set()
    for entry in entries:
        for key in (CONF_MAC_ADDRESS, CONF_MAC_ADDRESS_2, CONF_MAC_ADDRESS_3):
            val = (entry.options.get(key) or "").lower()
            if val:
                existing_macs.add(val)

    # Check uniqueness for all provided MACs
    for m in (mac, mac2, mac3):
        if m and m.lower() in existing_macs:
            return {"base": "mac_already_configured"}

    # Check if valid IP address
    if ip:
        try:
            IPv4Address(ip)
        except AddressValueError:
            return {"base": "ip_invalid"}

        # Check if device IP will be seen by ARP
        if user_input.get("subnet_check", True):
            subnets = await async_get_networks(hass)
            if not any(IPv4Address(ip) in subnet for subnet in subnets):
                return {"base": "ip_range"}


class IphoneDetectFlowHandler(ConfigFlow, domain=DOMAIN):  # type: ignore
    """Handle a config flow."""

    VERSION = 4

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> SchemaOptionsFlowHandler:
        return SchemaOptionsFlowHandler(config_entry, OPTIONS_FLOW)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle a flow initialized by the user."""
        errors = {}

        if user_input is not None:
            errors = await _validate_input(self.hass, user_input)

            if not errors:
                unique_id = slugify(user_input[CONF_NAME]).lower()
                await self.async_set_unique_id(f"{DOMAIN}_{unique_id}")
                self._abort_if_unique_id_configured()

                self._async_abort_entries_match({CONF_NAME: user_input[CONF_NAME]})

                return self.async_create_entry(
                    title=user_input[CONF_NAME],
                    data={},
                    options={
                        CONF_MAC_ADDRESS: user_input[CONF_MAC_ADDRESS].lower(),
                        CONF_MAC_ADDRESS_2: (user_input.get(CONF_MAC_ADDRESS_2) or "").lower(),
                        CONF_MAC_ADDRESS_3: (user_input.get(CONF_MAC_ADDRESS_3) or "").lower(),
                        CONF_IP_ADDRESS: user_input.get(CONF_IP_ADDRESS),
                        CONF_CONSIDER_HOME: user_input[CONF_CONSIDER_HOME],
                        CONF_OPNSENSE_URL: user_input.get(CONF_OPNSENSE_URL),
                        CONF_OPNSENSE_KEY: user_input.get(CONF_OPNSENSE_KEY),
                        CONF_OPNSENSE_SECRET: user_input.get(CONF_OPNSENSE_SECRET),
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(DATA_SCHEMA, user_input),
            errors=errors,
        )

    async def async_step_import(self, import_config) -> FlowResult:
        """Import from config."""
        _LOGGER.debug("Importing config '%s'", import_config)

        unique_id = slugify(import_config[CONF_NAME]).lower()
        await self.async_set_unique_id(f"{DOMAIN}_{unique_id}")
        self._abort_if_unique_id_configured()

        self._async_abort_entries_match({CONF_NAME: import_config[CONF_NAME]})

        return self.async_create_entry(
            title=import_config[CONF_NAME],
            data={},
            options={
                CONF_MAC_ADDRESS: import_config.get(CONF_MAC_ADDRESS, "").lower(),
                CONF_MAC_ADDRESS_2: (import_config.get(CONF_MAC_ADDRESS_2) or "").lower(),
                CONF_MAC_ADDRESS_3: (import_config.get(CONF_MAC_ADDRESS_3) or "").lower(),
                CONF_IP_ADDRESS: import_config.get(CONF_IP_ADDRESS),
                CONF_CONSIDER_HOME: import_config[CONF_CONSIDER_HOME],
                CONF_OPNSENSE_URL: import_config.get(CONF_OPNSENSE_URL),
                CONF_OPNSENSE_KEY: import_config.get(CONF_OPNSENSE_KEY),
                CONF_OPNSENSE_SECRET: import_config.get(CONF_OPNSENSE_SECRET),
            },
        )

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle options flow."""
        errors = {}
        entry = self._get_reconfigure_entry()

        if user_input is not None:
            # Pass exclude_entry_id so the current entry's MACs don't conflict with itself
            errors = await _validate_input(self.hass, user_input, exclude_entry_id=entry.entry_id)
            if not errors:
                await self.async_set_unique_id(entry.unique_id)
                self._abort_if_unique_id_mismatch()
                new_options = entry.options | {
                    CONF_MAC_ADDRESS: user_input[CONF_MAC_ADDRESS].lower(),
                    CONF_MAC_ADDRESS_2: (user_input.get(CONF_MAC_ADDRESS_2) or "").lower(),
                    CONF_MAC_ADDRESS_3: (user_input.get(CONF_MAC_ADDRESS_3) or "").lower(),
                    CONF_IP_ADDRESS: user_input.get(CONF_IP_ADDRESS),
                }

                return self.async_update_reload_and_abort(
                    entry,
                    options=new_options,
                )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema({
                vol.Required(CONF_MAC_ADDRESS, default=entry.options.get(CONF_MAC_ADDRESS, "")): str,
                vol.Optional(CONF_MAC_ADDRESS_2, default=entry.options.get(CONF_MAC_ADDRESS_2, "")): str,
                vol.Optional(CONF_MAC_ADDRESS_3, default=entry.options.get(CONF_MAC_ADDRESS_3, "")): str,
                vol.Optional(CONF_IP_ADDRESS, default=entry.options.get(CONF_IP_ADDRESS, "")): str,
                vol.Optional("subnet_check", default=True): bool,
                vol.Optional(CONF_OPNSENSE_URL, default=entry.options.get(CONF_OPNSENSE_URL)): str,
                vol.Optional(CONF_OPNSENSE_KEY, default=entry.options.get(CONF_OPNSENSE_KEY)): str,
                vol.Optional(CONF_OPNSENSE_SECRET, default=entry.options.get(CONF_OPNSENSE_SECRET)): str,
            }),
            description_placeholders={"device_name": entry.title},
            errors=errors,
        )
