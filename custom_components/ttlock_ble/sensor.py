"""Battery sensor platform for TTLock BLE."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory
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
    """Set up the TTLock battery sensor."""
    async_add_entities([TTLockBatterySensor(entry.runtime_data)])


class TTLockBatterySensor(SensorEntity):
    """Battery level reported in TTLock advertisements."""

    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: TTLockCoordinator) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = f"{coordinator.address}_battery"
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, coordinator.address)},
            name=f"TTLock {coordinator.address}",
            manufacturer="TTLock",
        )

    @property
    def available(self) -> bool:
        return (
            self._coordinator.tracker.available
            and self._coordinator.tracker.battery is not None
        )

    @property
    def native_value(self) -> int | None:
        return self._coordinator.tracker.battery

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._coordinator.async_add_listener(self._handle_update))

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()
