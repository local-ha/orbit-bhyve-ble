"""Sensor platform — battery percent, battery voltage, and BLE signal strength.

Both sensors are populated from the device's BLE info-ack response on
every connection: voltage in mV is read directly from payload bytes 4-5
(little-endian uint16), and percent is derived from it via a linear
discharge approximation (`devices.base._mv_to_pct`).
"""
from __future__ import annotations

from datetime import datetime

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    EntityCategory,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    UnitOfElectricPotential,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import BHyveDeviceCoordinator
from .devices.base import _mv_to_pct
from .devices.protobuf import BHyveProtobufDevice


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime = hass.data[DOMAIN][entry.entry_id]
    entities: list[SensorEntity] = []
    for coord in runtime.coordinators.values():
        device = coord.device
        # Every BLE device reports battery over RX; create both sensors so the
        # percent entity exists regardless of whether the cloud snapshot
        # happened to include a pct (the XD reports mv-only). Hubs / key-less
        # records have no BLE connection and no battery/signal to read.
        if device.connection is None:
            continue
        entities.append(BHyveBatterySensor(coord))
        entities.append(BHyveBatteryVoltageSensor(coord))
        entities.append(BHyveRssiSensor(coord))
        # Rain delay is a protobuf-family (HT34A/HT25G2) capability.
        if isinstance(device, BHyveProtobufDevice):
            entities.append(BHyveRainDelayEndsSensor(coord))
    async_add_entities(entities)


class _BHyveDeviceSensorBase(CoordinatorEntity[BHyveDeviceCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: BHyveDeviceCoordinator):
        super().__init__(coordinator)
        device = coordinator.device
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device.cloud_id)},
            "name": device.name,
            "manufacturer": "Orbit Irrigation",
            "model": device.hardware,
            "sw_version": device.firmware,
            "connections": {("mac", device.mac)} if device.mac else set(),
        }


class BHyveBatterySensor(_BHyveDeviceSensorBase):
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: BHyveDeviceCoordinator):
        super().__init__(coordinator)
        device = coordinator.device
        self._attr_unique_id = f"{device.unique_id}_battery"
        self._attr_name = "Battery"

    @property
    def native_value(self) -> int | None:
        device = self.coordinator.device
        if device.battery_pct is not None:
            return device.battery_pct
        if device.battery_mv is not None:
            return _mv_to_pct(device.battery_mv)
        return None


class BHyveBatteryVoltageSensor(_BHyveDeviceSensorBase):
    _attr_device_class = SensorDeviceClass.VOLTAGE
    _attr_native_unit_of_measurement = UnitOfElectricPotential.MILLIVOLT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: BHyveDeviceCoordinator):
        super().__init__(coordinator)
        device = coordinator.device
        self._attr_unique_id = f"{device.unique_id}_battery_mv"
        self._attr_name = "Battery voltage"

    @property
    def native_value(self) -> int | None:
        return self.coordinator.device.battery_mv


class BHyveRssiSensor(_BHyveDeviceSensorBase):
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: BHyveDeviceCoordinator):
        super().__init__(coordinator)
        device = coordinator.device
        self._attr_unique_id = f"{device.unique_id}_rssi"
        self._attr_name = "Signal strength"

    @property
    def native_value(self) -> int | None:
        return self.coordinator.device.rssi


class BHyveRainDelayEndsSensor(_BHyveDeviceSensorBase):
    """Timestamp when the active rain delay expires; None when off."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:weather-rainy"

    def __init__(self, coordinator: BHyveDeviceCoordinator):
        super().__init__(coordinator)
        device = coordinator.device
        self._attr_unique_id = f"{device.unique_id}_rain_delay_ends"
        self._attr_name = "Rain delay ends"

    @property
    def native_value(self) -> datetime | None:
        state = self.coordinator.data or self.coordinator.device.state
        return state.rain_delay_ends
