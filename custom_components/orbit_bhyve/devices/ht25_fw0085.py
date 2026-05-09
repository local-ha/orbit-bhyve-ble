"""HT25-0000 fw0085 — Deck's pre-fix code path.

This is the byte-for-byte pre-fix code that empirically actuated Deck on
2026-05-03. After the fix that parameterized frame addressing for fw0041
(Hill/Corner), Deck stopped physically actuating even though the new code
produces byte-identical frames (mesh_address=d747 = D747_MAGIC, hub_mesh
fallback=42eb). Splitting it back out as its own class so fw0085 keeps a
known-working code path independent of fw0041 evolution.

DO NOT touch this file unless you have a phone-app BTSnoop capture against
fw0085 to validate the change.
"""
from __future__ import annotations

import asyncio
import logging
import os

from ..connection import BHyveBleConnection
from .base import BHyveBleDeviceBase

_LOGGER = logging.getLogger(__name__)

D747_MAGIC = bytes([0xD7, 0x47])
D747_ROUTING = 0x40
SEQ_BIND = 0x05
SEQ_STATUS = 0x02
SEQ_INFO = 0x03
SEQ_SUBSYSTEM = 0x01
SEQ_MAGIC_CHECK = 0x00
SEQ_HEARTBEAT = 0x09
SEQ_WATER_CTRL = 0x0D

INIT_INTER_STEP_SEC = 0.15

BIND_TAIL = bytes.fromhex("f66910ff")


def _build(type_byte: int, seq: int, payload: bytes = b"") -> bytes:
    return D747_MAGIC + bytes([type_byte & 0xFF, seq & 0xFF, D747_ROUTING]) + payload


def _build_start(type_byte: int, duration_sec: int) -> bytes:
    if not 0 < duration_sec <= 0xFFFF:
        raise ValueError(f"duration_sec out of range (1..65535): {duration_sec}")
    payload = bytes([0x04]) + duration_sec.to_bytes(2, "little") + b"\x00\x00\x00\x00"
    return _build(type_byte, SEQ_WATER_CTRL, payload)


def _build_stop(type_byte: int) -> bytes:
    return _build(type_byte, SEQ_WATER_CTRL, b"\x02\x00\x00\x00")


class BHyveHT25Fw0085Device(BHyveBleDeviceBase):
    """HT25 single-station timer — pre-fix Deck code path (fw0085)."""

    frame_magic = 0x10
    trailer_const = 0x10

    async def _post_handshake(self, conn: BHyveBleConnection) -> None:
        sid = os.urandom(2)
        sid2 = ((int.from_bytes(sid, "little") + 3) & 0xFFFF).to_bytes(2, "little")

        steps: list[tuple[bytes, str]] = [
            (_build(0x81, SEQ_BIND, sid + BIND_TAIL), "bind"),
            (_build(0x02, SEQ_STATUS, b"\x00"), "status"),
            (_build(0x03, SEQ_INFO, b"\x00" * 7), "info"),
            (_build(0x04, SEQ_SUBSYSTEM, b"\x00" * 3), "subsystem"),
            (_build(0x85, SEQ_MAGIC_CHECK, bytes.fromhex("01d74700000000")), "magic1"),
            (_build(0x85, SEQ_MAGIC_CHECK, bytes.fromhex("0042eb00000000")), "magic2"),
            (_build(0x85, SEQ_HEARTBEAT, b"\x00"), "heartbeat"),
            (_build(0x86, SEQ_BIND, sid2 + BIND_TAIL), "rebind"),
        ]
        for plaintext, label in steps:
            _LOGGER.debug("%s: init → %s pt=%s", self.mac, label, plaintext.hex())
            await conn._write_locked(plaintext)
            await asyncio.sleep(INIT_INTER_STEP_SEC)
        await asyncio.sleep(0.3)

    async def start_watering(self, station: int, duration_sec: int) -> bool:
        if self.connection is None:
            return False
        plaintext = _build_start(0xB6, duration_sec)
        notifs = await self.connection.send(plaintext, drain_ms=1500)
        _LOGGER.debug("%s: START got %d notifications", self.mac, len(notifs))
        self._stamp_command(f"start s={station} d={duration_sec}", len(notifs))
        if notifs:
            self.state.is_watering = True
            self.state.active_zone = station
            self.state.seconds_remaining = duration_sec
        return bool(notifs)

    async def stop_watering(self, station: int | None = None) -> bool:
        if self.connection is None:
            return False
        plaintext = _build_stop(0xB7)
        notifs = await self.connection.send(plaintext, drain_ms=1500)
        _LOGGER.debug("%s: STOP got %d notifications", self.mac, len(notifs))
        self._stamp_command("stop", len(notifs))
        if notifs:
            self.state.is_watering = False
            self.state.active_zone = None
            self.state.seconds_remaining = None
        return bool(notifs)

    async def refresh_state(self):
        await super().refresh_state()
        return self.state
