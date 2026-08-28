"""Config flow for the TTLock BLE integration."""

from __future__ import annotations

from typing import Any

import ttlock
import voluptuous as vol
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import callback

from .const import (
    CONF_AES_KEY,
    CONF_COMMAND_TIMEOUT,
    CONF_CONNECT_ATTEMPTS,
    CONF_UNLOCK_KEY,
    DEFAULT_COMMAND_TIMEOUT,
    DEFAULT_CONNECT_ATTEMPTS,
    DOMAIN,
    MAX_COMMAND_TIMEOUT,
    MAX_CONNECT_ATTEMPTS,
    MIN_COMMAND_TIMEOUT,
    MIN_CONNECT_ATTEMPTS,
)


def _normalize_aes_key(value: object) -> str | None:
    """Return a 32-hex-char (16-byte) key, or ``None`` if invalid.

    Delegates to the protocol library rather than re-checking here. The same
    rules then apply to this form, to the MQTT daemon, and to the CLI, which is
    the point: the unlock-key bug that broke actuation existed because the only
    validation lived in this file and the daemon never had it.
    """
    try:
        return ttlock.normalize_aes_key(value)
    except ttlock.TtlockError:
        return None


def _normalize_unlock_key(value: object) -> int | None:
    """Return a usable unlock key, or ``None`` if it cannot be one.

    Zero is rejected deliberately, in the library. It is what an empty or
    unfilled field collapses to, and a lock accepts the resulting command
    *frame* and simply refuses it — so the only symptom is a rejected actuation
    long after the mistake, with nothing pointing back here.
    """
    try:
        return ttlock.normalize_unlock_key(value)
    except ttlock.TtlockError:
        return None


def _credentials_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    """The credentials form. `defaults` prefills it from an existing entry."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_AES_KEY, default=defaults.get(CONF_AES_KEY, "")): str,
            # `str` rather than `vol.Coerce(int)`: coercing here turns a typo into
            # a validation crash inside voluptuous instead of a field error the
            # form can show, and it is why an unusable key could reach the entry.
            vol.Required(
                CONF_UNLOCK_KEY,
                default=str(defaults.get(CONF_UNLOCK_KEY, "") or ""),
            ): str,
        }
    )


# `domain=` is Home Assistant's own ConfigFlow metaclass argument; a type
# checker cannot see it through the ignored `homeassistant` imports.
class TTLockConfigFlow(ConfigFlow, domain=DOMAIN):  # type: ignore[call-arg]
    """Handle a config flow for TTLock BLE."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovery: BluetoothServiceInfoBleak | None = None
        self._discovered: dict[str, BluetoothServiceInfoBleak] = {}

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> TTLockOptionsFlow:
        """Return the options flow for tuning BLE behaviour."""
        return TTLockOptionsFlow()

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle a lock discovered over Bluetooth."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._discovery = discovery_info
        self.context["title_placeholders"] = {
            "name": discovery_info.name or discovery_info.address
        }
        return await self.async_step_credentials()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a user-initiated flow: pick a discovered lock."""
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            self._discovery = self._discovered.get(address)
            return await self.async_step_credentials()

        current_addresses = self._async_current_ids()
        for info in async_discovered_service_info(self.hass, connectable=True):
            if info.address in current_addresses or info.address in self._discovered:
                continue
            self._discovered[info.address] = info

        if not self._discovered:
            return self.async_abort(reason="no_devices_found")

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): vol.In(
                        {
                            address: f"{info.name or 'TTLock'} ({address})"
                            for address, info in self._discovered.items()
                        }
                    )
                }
            ),
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect the lock credentials (AES key and unlock key)."""
        errors: dict[str, str] = {}
        if user_input is not None:
            aes_key = _normalize_aes_key(user_input[CONF_AES_KEY])
            unlock_key = _normalize_unlock_key(user_input[CONF_UNLOCK_KEY])
            if aes_key is None:
                errors[CONF_AES_KEY] = "invalid_aes_key"
            if unlock_key is None:
                errors[CONF_UNLOCK_KEY] = "invalid_unlock_key"
            if aes_key is not None and unlock_key is not None:
                address = self._discovery.address if self._discovery else self.unique_id
                name = (
                    self._discovery.name if self._discovery else None
                ) or f"TTLock {address}"
                return self.async_create_entry(
                    title=name,
                    data={
                        CONF_ADDRESS: address,
                        CONF_AES_KEY: aes_key,
                        CONF_UNLOCK_KEY: unlock_key,
                    },
                )

        name = (
            self._discovery.name if self._discovery else (self.unique_id or "the lock")
        )
        return self.async_show_form(
            step_id="credentials",
            data_schema=_credentials_schema(),
            errors=errors,
            description_placeholders={"name": name},
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Edit the credentials of an existing entry.

        Credentials live in entry data rather than options because changing them
        changes which lock the entry can talk to; this is the supported way to
        correct a mistyped key without deleting and re-adding the lock.
        """
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            aes_key = _normalize_aes_key(user_input[CONF_AES_KEY])
            unlock_key = _normalize_unlock_key(user_input[CONF_UNLOCK_KEY])
            if aes_key is None:
                errors[CONF_AES_KEY] = "invalid_aes_key"
            if unlock_key is None:
                errors[CONF_UNLOCK_KEY] = "invalid_unlock_key"
            if aes_key is not None and unlock_key is not None:
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_AES_KEY: aes_key,
                        CONF_UNLOCK_KEY: unlock_key,
                    },
                )

        # `add_suggested_values_to_schema` is Home Assistant's own mechanism for
        # showing what an entry currently holds. A schema `default=` is what
        # voluptuous falls back to when a field is *omitted*, which is not the
        # same thing and does not reliably reach the form.
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self.add_suggested_values_to_schema(
                _credentials_schema(), dict(entry.data)
            ),
            errors=errors,
            description_placeholders={"name": entry.title},
        )


class TTLockOptionsFlow(OptionsFlow):
    """Tunables for locks on a weak or busy Bluetooth link."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_CONNECT_ATTEMPTS,
                        default=options.get(
                            CONF_CONNECT_ATTEMPTS, DEFAULT_CONNECT_ATTEMPTS
                        ),
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=MIN_CONNECT_ATTEMPTS, max=MAX_CONNECT_ATTEMPTS),
                    ),
                    vol.Required(
                        CONF_COMMAND_TIMEOUT,
                        default=options.get(
                            CONF_COMMAND_TIMEOUT, DEFAULT_COMMAND_TIMEOUT
                        ),
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=MIN_COMMAND_TIMEOUT, max=MAX_COMMAND_TIMEOUT),
                    ),
                }
            ),
        )
