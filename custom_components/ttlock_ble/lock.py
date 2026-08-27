"""Lock platform for TTLock BLE."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import TTLockCoordinator

if TYPE_CHECKING:
    from . import TTLockConfigEntry


async def async_setup_entry(
    hass: HomeAssistant,
    entry: TTLockConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the TTLock lock entity."""
    async_add_entities([TTLockLock(entry.runtime_data)])


class TTLockLock(LockEntity):
    """A TTLock exposed as a Home Assistant lock."""

    _attr_has_entity_name = True
    _attr_name = None

    # The lock advertises the state it was last *commanded* into, not the state
    # it is physically in. A key or thumbturn moves the bolt without the
    # firmware noticing: captured across two full manual lock/unlock cycles, 107
    # advertisements, the payload was byte-identical throughout, and a connected
    # `0x14` status query returned UNLOCKED while the bolt was demonstrably
    # thrown. The same is true of the other open-source implementation, so this
    # is the hardware, not this integration.
    #
    # `assumed_state` is the honest way to say that: Home Assistant stops
    # treating our answer as ground truth, and — the practical part — offers
    # both actions instead of only the one that contradicts the state we
    # reported. Without it, a lock manually opened while we believed it locked
    # cannot be locked again from the dashboard card.
    _attr_assumed_state = True

    def __init__(self, coordinator: TTLockCoordinator) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = coordinator.address
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, coordinator.address)},
            name=f"TTLock {coordinator.address}",
            manufacturer="TTLock",
        )

    @property
    def available(self) -> bool:
        return self._coordinator.tracker.available

    @property
    def is_locked(self) -> bool | None:
        # The last *observed* bolt position, which is deliberately unchanged
        # while a command is in flight — that is what `is_locking` is for.
        return self._coordinator.tracker.is_locked

    # Without these, Home Assistant has nothing to render while a command is in
    # flight, so the button click looks like it did nothing for several seconds.
    @property
    def is_locking(self) -> bool:
        return self._coordinator.tracker.pending == "lock"

    @property
    def is_unlocking(self) -> bool:
        return self._coordinator.tracker.pending == "unlock"

    async def async_lock(self, **kwargs: Any) -> None:
        await self._coordinator.async_lock()

    async def async_unlock(self, **kwargs: Any) -> None:
        await self._coordinator.async_unlock()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._coordinator.async_add_listener(self._handle_update))

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()
