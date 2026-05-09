"""Number platform — per-device watering duration in minutes.

One NumberEntity per HT25 sprinkler. The user sets a duration in minutes;
valve.async_open_valve reads coordinator.preferred_duration_sec when the
valve is opened. State is restored across HA restarts.
"""
from __future__ import annotations

import logging

from homeassistant.components.number import (
    NumberMode,
    RestoreNumber,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEFAULT_DURATION, DEFAULT_DURATION, DOMAIN
from .coordinator import BHyveDeviceCoordinator
from .devices import BHyveHubDevice

_LOGGER = logging.getLogger(__name__)

MIN_MINUTES = 1
MAX_MINUTES = 1440  # 24h


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime = hass.data[DOMAIN][entry.entry_id]
    default_duration_sec = entry.options.get(CONF_DEFAULT_DURATION, DEFAULT_DURATION)
    entities: list[BHyveDurationNumber] = []
    for coord in runtime.coordinators.values():
        if isinstance(coord.device, BHyveHubDevice):
            continue
        entities.append(BHyveDurationNumber(coord, default_duration_sec))
    async_add_entities(entities)


class BHyveDurationNumber(CoordinatorEntity[BHyveDeviceCoordinator], RestoreNumber):
    _attr_has_entity_name = True
    _attr_name = "Watering duration"
    _attr_icon = "mdi:timer-outline"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_native_min_value = MIN_MINUTES
    _attr_native_max_value = MAX_MINUTES
    _attr_native_step = 1
    _attr_native_unit_of_measurement = UnitOfTime.MINUTES
    _attr_mode = NumberMode.BOX

    def __init__(self, coordinator: BHyveDeviceCoordinator, default_duration_sec: int):
        super().__init__(coordinator)
        device = coordinator.device
        self._attr_unique_id = f"{device.unique_id}_duration"
        initial_minutes = max(MIN_MINUTES, default_duration_sec // 60)
        self._attr_native_value = float(initial_minutes)
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device.cloud_id)},
            "name": device.name,
            "manufacturer": "Orbit Irrigation",
            "model": device.hardware,
            "sw_version": device.firmware,
            "connections": {("mac", device.mac)} if device.mac else set(),
        }
        # Seed coordinator immediately; async_added_to_hass may overwrite from
        # restored state, but until then valve.async_open_valve has a value.
        coordinator.preferred_duration_sec = initial_minutes * 60

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_number_data()
        if last is None or last.native_value is None:
            return
        minutes = max(MIN_MINUTES, min(MAX_MINUTES, int(last.native_value)))
        self._attr_native_value = float(minutes)
        self.coordinator.preferred_duration_sec = minutes * 60

    async def async_set_native_value(self, value: float) -> None:
        minutes = max(MIN_MINUTES, min(MAX_MINUTES, int(value)))
        self._attr_native_value = float(minutes)
        self.coordinator.preferred_duration_sec = minutes * 60
        self.async_write_ha_state()
