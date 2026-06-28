"""Abstract base for all per-model device classes."""
from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..connection import BHyveBleConnection

_LOGGER = logging.getLogger(__name__)


def _mv_to_pct(mv: int) -> int:
    """Linear approximation matching the cloud's discharge curve to within
    a few percent: 0% at 2400 mV, 100% at 3000 mV. Tuned against three
    live devices (Hill 33%/2602 mV, Corner 34%/2606 mV, Deck 65%/2771 mV)."""
    pct = round((mv - 2400) * 100 / 600)
    return max(0, min(100, pct))


@dataclass
class DeviceState:
    is_watering: bool = False
    active_zone: int | None = None
    seconds_remaining: int | None = None
    started_at: datetime | None = None
    expected_off_at: datetime | None = None
    last_command_at: datetime | None = None
    last_command_label: str | None = None
    is_connected: bool = False
    notifications_last_cmd: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


class BHyveBleDeviceBase(abc.ABC):
    """One per physical device. Owns the BLE connection."""

    # Per-class overrides — defaults are HT25's values.
    frame_magic: int = 0x10
    trailer_const: int = 0x10

    def __init__(
        self,
        hass,
        record: dict[str, Any],
        *,
        idle_disconnect_sec: int = 60,
    ):
        self.hass = hass
        self.cloud_id: str = record["cloud_id"]
        self.name: str = record["name"]
        self.mac: str = record["mac"]
        self.hardware: str = record["hardware"]
        self.firmware: str = record["firmware"]
        self.stations: int = record["stations"]
        self.mesh_id: str | None = record.get("mesh_id")
        self.mesh_device_id: int | None = record.get("mesh_device_id")
        self.bridge_device_id: str | None = record.get("bridge_device_id")
        self.hub_mesh_device_id: int | None = record.get("hub_mesh_device_id")
        self.battery_pct: int | None = record.get("battery_pct")
        self.battery_mv: int | None = record.get("battery_mv")
        self.network_key: str = record["network_key"]
        self.state = DeviceState()

        if self.network_key and self.mac:
            self.connection: BHyveBleConnection | None = BHyveBleConnection(
                hass,
                self.mac,
                self.network_key,
                frame_magic=self.frame_magic,
                trailer_const=self.trailer_const,
                idle_disconnect_sec=idle_disconnect_sec,
            )
            self.connection.set_post_handshake_hook(self._post_handshake)
            self.connection.set_plaintext_observer(self._observe_plaintext)
        else:
            # Hubs and key-less records (skip BLE entirely).
            self.connection = None

    @property
    def fw_int(self) -> int:
        try:
            return int(self.firmware)
        except (TypeError, ValueError):
            return 0

    @property
    def unique_id(self) -> str:
        return f"orbit_bhyve_{self.mac.replace(':', '').lower()}"

    async def async_setup(self) -> None:
        """Hook for device classes that want pre-warming. Default: no-op."""

    async def async_unload(self) -> None:
        if self.connection is not None:
            await self.connection.disconnect()

    async def _post_handshake(self, conn: BHyveBleConnection) -> None:
        """Override to send per-class init frames after the AES handshake."""

    def _observe_plaintext(self, pt: bytes) -> None:
        """Parse d7-47 mesh status replies: battery (seq 0x03) and watering
        state (seq 0x02).

        Frame layout: [mesh:2][type:1][seq:1][routing:1][payload:N]. Replies
        set the 0x40 reply bit in the type byte and carry routing=0x40 (TX
        echoes with the bit clear are skipped). Verified against fw0085 (Deck)
        and fw0041 (Hill, Corner) cross-checked with cloud snapshots."""
        if len(pt) < 6 or pt[4] != 0x40 or not (pt[2] & 0x40):
            return
        seq = pt[3]
        if seq == 0x03 and len(pt) >= 12:
            # Info-ack: payload bytes 4-5 (pt[9:11]) are battery mV, LE.
            mv = int.from_bytes(pt[9:11], "little")
            if 1500 <= mv <= 4000:  # out-of-band => malformed; don't poison state
                self.battery_mv = mv
                self.battery_pct = _mv_to_pct(mv)
        elif seq == 0x02 and len(pt) >= 6:
            # Status reply/push: payload[0] (pt[5]) is the watering mode —
            # 0x04 = watering, 0x01 = idle. Authoritative device state, used to
            # confirm an actuation actually took.
            mode = pt[5]
            if mode == 0x04:
                self.state.is_watering = True
            elif mode == 0x01:
                self.state.is_watering = False

    @abc.abstractmethod
    async def start_watering(self, station: int, duration_sec: int) -> bool:
        ...

    @abc.abstractmethod
    async def stop_watering(self, station: int | None = None) -> bool:
        ...

    async def refresh_state(self) -> DeviceState:
        """Default: only refresh BLE-connection liveness. Subclasses can extend
        with a status-request roundtrip."""
        if self.connection is not None:
            self.state.is_connected = self.connection.is_connected
        return self.state

    def _stamp_command(self, label: str, n_notifs: int) -> None:
        self.state.last_command_at = datetime.now(timezone.utc)
        self.state.last_command_label = label
        self.state.notifications_last_cmd = n_notifs


class UnsupportedModel(Exception):
    def __init__(self, hardware: str, firmware: str):
        super().__init__(f"no device class for hardware={hardware!r} firmware={firmware!r}")
        self.hardware = hardware
        self.firmware = firmware
