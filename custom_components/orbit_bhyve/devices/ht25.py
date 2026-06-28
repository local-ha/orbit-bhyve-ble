"""HT25-0000 (single-station hose-tap) device class.

d7-47 protocol family. Verified against fw0085 (Deck) 2026-05-03 and
fw0041 (Hill) 2026-05-05 — same protocol, the 2-byte frame prefix is the
device's own mesh_device_id in little-endian (Deck's old "D747_MAGIC"
constant was just Deck's mesh_id 18391 = 0x47D7 LE).
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from ..connection import BHyveBleConnection
from .base import BHyveBleDeviceBase

_LOGGER = logging.getLogger(__name__)

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


class BHyveHT25Device(BHyveBleDeviceBase):
    """HT25 single-station timer."""

    frame_magic = 0x10
    trailer_const = 0x10

    @property
    def mesh_address(self) -> bytes:
        """The 2-byte device-address prefix on every command frame.
        It's the device's own mesh_device_id, little-endian."""
        if self.mesh_device_id is None:
            raise RuntimeError(
                f"{self.mac}: mesh_device_id missing from cloud record — "
                "cannot build HT25 frames"
            )
        return self.mesh_device_id.to_bytes(2, "little")

    @property
    def hub_mesh_address(self) -> bytes:
        """The 2-byte hub-address embedded in the magic2 init step, from the
        cloud record's hub mesh_device_id (0 when the cloud didn't surface it —
        the device still binds; magic2 just carries a null hub reference)."""
        return (self.hub_mesh_device_id or 0).to_bytes(2, "little")

    def _build(self, type_byte: int, seq: int, payload: bytes = b"") -> bytes:
        return self.mesh_address + bytes([type_byte & 0xFF, seq & 0xFF, D747_ROUTING]) + payload

    def _build_start(self, type_byte: int, duration_sec: int) -> bytes:
        if not 0 < duration_sec <= 0xFFFF:
            raise ValueError(f"duration_sec out of range (1..65535): {duration_sec}")
        payload = bytes([0x04]) + duration_sec.to_bytes(2, "little") + b"\x00\x00\x00\x00"
        return self._build(type_byte, SEQ_WATER_CTRL, payload)

    def _build_stop(self, type_byte: int) -> bytes:
        return self._build(type_byte, SEQ_WATER_CTRL, b"\x02\x00\x00\x00")

    async def _post_handshake(self, conn: BHyveBleConnection) -> None:
        """8-step init the phone runs after the AES handshake. Sending the
        watering command without it produces a silent drop. Only `bind`,
        `status`, and `info` are confirmed required; the others may be
        prunable but are kept for safety until empirically tested."""
        sid = os.urandom(2)
        # Rebind sid offset. fw0041 (Hill, BTSnoop 2026-05-05) uses +2; the old
        # hardcoded fw0085 (Deck) path used +3. All HT25 firmwares now route here
        # with +2 and rely on start/stop's confirm-and-retry to recover loudly
        # from any mismatch. If a fw0085 unit is shown (via BTSnoop) to require
        # +3, parameterize this per firmware then.
        sid2 = ((int.from_bytes(sid, "little") + 2) & 0xFFFF).to_bytes(2, "little")

        # magic1 payload: 0x01 || self mesh_id LE || 4 zero bytes
        # magic2 payload: 0x00 || hub  mesh_id LE || 4 zero bytes
        magic1_payload = b"\x01" + self.mesh_address + b"\x00\x00\x00\x00"
        magic2_payload = b"\x00" + self.hub_mesh_address + b"\x00\x00\x00\x00"

        steps: list[tuple[bytes, str]] = [
            (self._build(0x81, SEQ_BIND, sid + BIND_TAIL), "bind"),
            (self._build(0x02, SEQ_STATUS, b"\x00"), "status"),
            (self._build(0x03, SEQ_INFO, b"\x00" * 7), "info"),
            (self._build(0x04, SEQ_SUBSYSTEM, b"\x00" * 3), "subsystem"),
            (self._build(0x85, SEQ_MAGIC_CHECK, magic1_payload), "magic1"),
            (self._build(0x85, SEQ_MAGIC_CHECK, magic2_payload), "magic2"),
            (self._build(0x85, SEQ_HEARTBEAT, b"\x00"), "heartbeat"),
            (self._build(0x86, SEQ_BIND, sid2 + BIND_TAIL), "rebind"),
        ]
        for plaintext, label in steps:
            _LOGGER.debug("%s: init → %s pt=%s", self.mac, label, plaintext.hex())
            # _write_locked, not send_raw — we're already inside conn's lock
            # (post-handshake hook runs from _open() called by send()).
            await conn._write_locked(plaintext)
            await asyncio.sleep(INIT_INTER_STEP_SEC)
        await asyncio.sleep(0.3)

    async def _poll_watering(self) -> bool:
        """Request a status frame and return the device's reported watering
        state. The seq=0x02 reply is decoded in base._observe_plaintext, which
        sets self.state.is_watering from the device's own mode byte."""
        if self.connection is None:
            return False
        await self.connection.send(self._build(0x02, SEQ_STATUS, b"\x00"), drain_ms=700)
        return self.state.is_watering

    async def start_watering(self, station: int, duration_sec: int) -> bool:
        if self.connection is None:
            return False
        # HT25 is single-station; `station` is a no-op placeholder for API parity.
        # send_actuation re-runs the bind first — the device acks but silently
        # ignores a watering command on a stale pooled session. Then confirm via
        # a status poll; retry once with a fully fresh session.
        plaintext = self._build_start(0xB6, duration_sec)
        for attempt in range(2):
            notifs = await self.connection.send_actuation(plaintext, drain_ms=1500)
            self._stamp_command(f"start s={station} d={duration_sec}", len(notifs))
            if await self._poll_watering():
                now = datetime.now(timezone.utc)
                self.state.active_zone = station
                self.state.seconds_remaining = duration_sec
                self.state.started_at = now
                self.state.expected_off_at = now + timedelta(seconds=duration_sec)
                _LOGGER.debug("%s: START confirmed watering", self.mac)
                return True
            _LOGGER.warning(
                "%s: START acked but device not watering (attempt %d/2) — fresh session",
                self.mac, attempt + 1,
            )
            await self.connection.disconnect()
        _LOGGER.error("%s: START failed to actuate after retries", self.mac)
        return False

    async def stop_watering(self, station: int | None = None) -> bool:
        if self.connection is None:
            return False
        plaintext = self._build_stop(0xB7)
        for attempt in range(2):
            notifs = await self.connection.send_actuation(plaintext, drain_ms=1500)
            self._stamp_command("stop", len(notifs))
            if not await self._poll_watering():
                self.state.active_zone = None
                self.state.seconds_remaining = None
                self.state.started_at = None
                self.state.expected_off_at = None
                _LOGGER.debug("%s: STOP confirmed idle", self.mac)
                return True
            _LOGGER.warning(
                "%s: STOP acked but device still watering (attempt %d/2) — fresh session",
                self.mac, attempt + 1,
            )
            await self.connection.disconnect()
        _LOGGER.error("%s: STOP failed to close after retries", self.mac)
        return False

    async def refresh_state(self):
        """Probe the device for an idle/watering status. Best-effort: the
        watering-status response byte layout isn't fully decoded, so we only
        update is_connected here. Local optimism (set in start/stop) drives
        is_watering until full status decoding lands."""
        await super().refresh_state()
        return self.state
