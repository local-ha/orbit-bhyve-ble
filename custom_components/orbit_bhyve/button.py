"""Button platform — per-device sync button.

One ButtonEntity per non-hub device. Pressing it forces a fresh BLE
connect + 8-step init; the info-ack notification that arrives during
init carries battery_mV (parsed by devices.base.BHyveBleDeviceBase
._observe_plaintext), and the coordinator refresh after the press
pushes the new value into HA.

Equivalent to calling the orbit_bhyve.probe_status service, but
attached to the device card so a non-technical user can refresh battery
without going through Developer Tools.
"""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import BHyveDeviceCoordinator
from .devices import BHyveHubDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    runtime = hass.data[DOMAIN][entry.entry_id]
    entities: list[ButtonEntity] = []
    for coord in runtime.coordinators.values():
        if isinstance(coord.device, BHyveHubDevice):
            continue
        if coord.device.connection is None:
            continue
        entities.append(BHyveSyncButton(coord))
    async_add_entities(entities)


class BHyveSyncButton(CoordinatorEntity[BHyveDeviceCoordinator], ButtonEntity):
    _attr_has_entity_name = True
    _attr_name = "Sync"
    _attr_icon = "mdi:sync"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: BHyveDeviceCoordinator):
        super().__init__(coordinator)
        device = coordinator.device
        self._attr_unique_id = f"{device.unique_id}_sync"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, device.cloud_id)},
            "name": device.name,
            "manufacturer": "Orbit Irrigation",
            "model": device.hardware,
            "sw_version": device.firmware,
            "connections": {("mac", device.mac)} if device.mac else set(),
        }

    async def async_press(self) -> None:
        device = self.coordinator.device
        conn = device.connection
        if conn is None:
            return
        _LOGGER.info("%s: sync requested via button", device.mac)
        await conn.disconnect()
        await conn.ensure_connected()
        await self.coordinator.async_request_refresh()
