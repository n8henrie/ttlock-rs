"""The TTLock BLE integration."""

from __future__ import annotations

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    CONF_AES_KEY,
    CONF_COMMAND_TIMEOUT,
    CONF_CONNECT_ATTEMPTS,
    CONF_UNLOCK_KEY,
    DEFAULT_COMMAND_TIMEOUT,
    DEFAULT_CONNECT_ATTEMPTS,
    PLATFORMS,
)
from .coordinator import TTLockCoordinator

type TTLockConfigEntry = ConfigEntry[TTLockCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: TTLockConfigEntry) -> bool:
    """Set up TTLock BLE from a config entry."""
    address: str = entry.data[CONF_ADDRESS]
    if not bluetooth.async_address_present(hass, address, connectable=False):
        raise ConfigEntryNotReady(
            f"TTLock {address} not seen yet; waiting for an advertisement"
        )

    coordinator = TTLockCoordinator(
        hass,
        address,
        bytes.fromhex(entry.data[CONF_AES_KEY]),
        int(entry.data[CONF_UNLOCK_KEY]),
        connect_attempts=entry.options.get(
            CONF_CONNECT_ATTEMPTS, DEFAULT_CONNECT_ATTEMPTS
        ),
        command_timeout=entry.options.get(
            CONF_COMMAND_TIMEOUT, DEFAULT_COMMAND_TIMEOUT
        ),
    )
    entry.runtime_data = coordinator
    entry.async_on_unload(coordinator.async_start())
    # Options are read once above, so the entry has to reload to pick up changes.
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: TTLockConfigEntry) -> None:
    """Reload the entry when its options change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: TTLockConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
