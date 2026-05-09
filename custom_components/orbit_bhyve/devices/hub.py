"""Wi-Fi hub (BH1-0001) device class — connectivity diagnostics only.

Hubs share the BLE service UUID with timers but don't have valves and
shouldn't be opened over BLE from the integration. We expose them as a
device with a connectivity binary_sensor + firmware diagnostic so the user
can see them in the UI; no actuation methods.
"""
from __future__ import annotations

import logging

from .base import BHyveBleDeviceBase

_LOGGER = logging.getLogger(__name__)


class BHyveHubDevice(BHyveBleDeviceBase):
    """Cloud-only diagnostics for a B-Hyve Wi-Fi hub."""

    def __init__(self, hass, record, **kwargs):
        # Hubs intentionally don't open BLE connections — pass empty key to
        # short-circuit the connection-creation path in the base class.
        record = {**record, "network_key": ""}
        super().__init__(hass, record, **kwargs)

    async def start_watering(self, station: int, duration_sec: int) -> bool:
        raise NotImplementedError("hub devices have no valves")

    async def stop_watering(self, station: int | None = None) -> bool:
        raise NotImplementedError("hub devices have no valves")
