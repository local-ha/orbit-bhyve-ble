"""HT34A-0001 (4-port XD timer) device class.

Ported from upstream `wxfield/Orbit_B-Hyve_4Port_Controller` and
community-verified against firmware 0107 (2026-06): zone start/stop
actuate over BLE via Home Assistant, both through an ESPHome Bluetooth
proxy and a direct adapter. Cipher math is shared with the HT25 family.
"""
from __future__ import annotations

import logging
import struct

from .base import BHyveBleDeviceBase
from .status import apply_status_plaintext

_LOGGER = logging.getLogger(__name__)

MSG_HEADER = bytes([0xAA, 0x77, 0x5A, 0x0F])


def _crc16_ccitt(data: bytes, init: int = 0) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def _pb_varint(val: int) -> bytes:
    r = bytearray()
    while val > 0x7F:
        r.append((val & 0x7F) | 0x80)
        val >>= 7
    r.append(val & 0x7F)
    return bytes(r)


def _pb_field_varint(f: int, v: int) -> bytes:
    return _pb_varint((f << 3) | 0) + _pb_varint(v)


def _pb_field_bytes(f: int, d: bytes) -> bytes:
    return _pb_varint((f << 3) | 2) + _pb_varint(len(d)) + d


def _build_message(protobuf: bytes) -> bytes:
    payload_len = len(protobuf) + 2
    msg = MSG_HEADER + bytes([payload_len, 0x00]) + protobuf
    crc = struct.pack("<H", _crc16_ccitt(msg, 0))
    return msg + crc


def _build_start_pb(station_id: int, duration_sec: int) -> bytes:
    station_info = _pb_field_varint(1, station_id) + _pb_field_varint(2, duration_sec)
    manual_params = _pb_field_bytes(3, station_info)
    timer_mode = _pb_field_varint(1, 2) + _pb_field_bytes(2, manual_params)
    return _pb_field_bytes(14, timer_mode)


_STOP_PB = bytes.fromhex("720408021200")


class BHyveHT34ADevice(BHyveBleDeviceBase):
    """4-port XD timer. Ported from upstream; verified on fw0107 over BLE."""

    frame_magic = 0x11
    trailer_const = 0x11

    def _observe_plaintext(self, pt: bytes) -> None:
        # Protobuf-family status decode (live battery + real watering state),
        # not the d7-47 mesh battery parse the base class does.
        apply_status_plaintext(self, pt)

    async def start_watering(self, station: int, duration_sec: int) -> bool:
        if self.connection is None:
            return False
        # Upstream uses 0-indexed stations on the wire.
        plaintext = _build_message(_build_start_pb(station - 1, duration_sec))
        # The command reply carries the device status, which _observe_plaintext
        # (apply_status_plaintext) decodes into self.state.is_watering — so we
        # confirm the device actually started, and retry once with a fresh
        # session if it didn't.
        for attempt in range(2):
            notifs = await self.connection.send(plaintext, drain_ms=2000)
            self._stamp_command(f"start s={station} d={duration_sec}", len(notifs))
            if self.state.is_watering:
                self.state.active_zone = station
                self.state.seconds_remaining = duration_sec
                _LOGGER.debug("%s: HT34A START confirmed watering", self.mac)
                return True
            _LOGGER.warning(
                "%s: HT34A START not confirmed (attempt %d/2) — fresh session",
                self.mac, attempt + 1,
            )
            await self.connection.disconnect()
        _LOGGER.error("%s: HT34A START failed to actuate after retries", self.mac)
        return False

    async def stop_watering(self, station: int | None = None) -> bool:
        if self.connection is None:
            return False
        plaintext = _build_message(_STOP_PB)
        for attempt in range(2):
            notifs = await self.connection.send(plaintext, drain_ms=2000)
            self._stamp_command("stop", len(notifs))
            if not self.state.is_watering:
                self.state.active_zone = None
                self.state.seconds_remaining = None
                _LOGGER.debug("%s: HT34A STOP confirmed idle", self.mac)
                return True
            _LOGGER.warning(
                "%s: HT34A STOP not confirmed (attempt %d/2) — fresh session",
                self.mac, attempt + 1,
            )
            await self.connection.disconnect()
        _LOGGER.error("%s: HT34A STOP failed to close after retries", self.mac)
        return False
