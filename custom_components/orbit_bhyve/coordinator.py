"""Per-device DataUpdateCoordinator.

Polls each device for state on an interval that varies with watering state
(faster while watering, slower when idle). All polling is BLE-only; the
cloud is never touched at runtime.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DEFAULT_POLL_IDLE, DEFAULT_POLL_WATERING
from .devices import BHyveBleDeviceBase, DeviceState

_LOGGER = logging.getLogger(__name__)


class BHyveDeviceCoordinator(DataUpdateCoordinator[DeviceState]):
    """One per BHyve device."""

    def __init__(
        self,
        hass: HomeAssistant,
        device: BHyveBleDeviceBase,
        *,
        poll_idle_sec: int = DEFAULT_POLL_IDLE,
        poll_watering_sec: int = DEFAULT_POLL_WATERING,
    ):
        self.device = device
        self.poll_idle = poll_idle_sec
        self.poll_watering = poll_watering_sec
        # Set by the per-device NumberEntity (number.py) on first add and on
        # every UI change. Valve.async_open_valve reads this to decide the
        # watering duration. None until the NumberEntity registers.
        self.preferred_duration_sec: int | None = None
        super().__init__(
            hass,
            _LOGGER,
            name=f"orbit_bhyve {device.name}",
            update_interval=timedelta(seconds=poll_idle_sec),
        )

    async def _async_update_data(self) -> DeviceState:
        try:
            state = await self.device.refresh_state()
        except Exception as err:
            raise UpdateFailed(str(err)) from err
        # Adjust polling cadence based on observed state.
        target = self.poll_watering if state.is_watering else self.poll_idle
        new_interval = timedelta(seconds=target)
        if new_interval != self.update_interval:
            self.update_interval = new_interval
        return state
