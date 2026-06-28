"""Protobuf-protocol device family (frame magic 0x11): HT34A XD + HT25G2 Gen2.

These devices share one wire protocol end to end — the same framing, AES-CTR
cipher, `timerMode` start/stop messages, and protobuf RX status decode. The
only per-model differences are the human-readable log label and the station
count (already carried as `self.stations`), so the actuation logic lives once
here and the per-model modules (`ht34a.py`, `ht25g2.py`) are trivial subclasses.

Per-*protocol* device modules are justified (mesh vs protobuf vs hub); per-
*model* modules within a protocol are not — collapsing the two identical Gen2/XD
classes removes a confirm-and-retry implementation that had been written twice.

TX frame builders live here; the RX decode + CRC live in `status.py`. The CRC
and inner-message header are shared with the RX side, imported rather than
re-declared, so there is a single source for both directions.
"""
from __future__ import annotations

import logging
import struct

from .base import BHyveBleDeviceBase
from .status import MSG_HEADER, _crc16_ccitt, apply_status_plaintext

_LOGGER = logging.getLogger(__name__)


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


class BHyveProtobufDevice(BHyveBleDeviceBase):
    """Shared base for protobuf-protocol valves (frame magic 0x11).

    Subclasses set `log_label` for human-readable logging; station count comes
    from `self.stations` (1 for Gen2, 4 for the XD), so no other override is
    needed for single- vs multi-station addressing.
    """

    frame_magic = 0x11
    trailer_const = 0x11
    log_label = "protobuf"

    def _observe_plaintext(self, pt: bytes) -> None:
        # Protobuf-family status decode (live battery + real watering state),
        # not the d7-47 mesh battery parse the base class does.
        apply_status_plaintext(self, pt)

    async def start_watering(self, station: int, duration_sec: int) -> bool:
        if self.connection is None:
            return False
        # Stations are 0-indexed on the wire (station 1 -> 0).
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
                _LOGGER.debug("%s: %s START confirmed watering", self.mac, self.log_label)
                return True
            _LOGGER.warning(
                "%s: %s START not confirmed (attempt %d/2) — fresh session",
                self.mac, self.log_label, attempt + 1,
            )
            await self.connection.disconnect()
        _LOGGER.error(
            "%s: %s START failed to actuate after retries", self.mac, self.log_label
        )
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
                _LOGGER.debug("%s: %s STOP confirmed idle", self.mac, self.log_label)
                return True
            _LOGGER.warning(
                "%s: %s STOP not confirmed (attempt %d/2) — fresh session",
                self.mac, self.log_label, attempt + 1,
            )
            await self.connection.disconnect()
        _LOGGER.error(
            "%s: %s STOP failed to close after retries", self.mac, self.log_label
        )
        return False
