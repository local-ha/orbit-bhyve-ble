"""Connection-layer tests: the send_actuation pooled-session fallback.

connection.py's only HA import is function-local, so it imports with just
bleak + cryptography (see conftest). These exercise the fix for the mesh STOP
crash ljmerza hit on hardware: over an ESPHome proxy the GATT link can be dead
while HA still believes the session is pooled, so the in-place bind-refresh or
write raises BleakError("Not connected") — send_actuation must recover on a
fresh session instead of propagating it to the service call.
"""
from __future__ import annotations

import asyncio

import pytest
from bleak.exc import BleakError

from orbit_bhyve.connection import BHyveBleConnection


class _FakeClient:
    def __init__(self, connected=True):
        self.is_connected = connected


def _make_conn():
    conn = BHyveBleConnection.__new__(BHyveBleConnection)
    conn.mac = "AA:BB:CC:DD:EE:FF"
    conn.hass = None
    conn._lock = asyncio.Lock()
    conn._notif_buf = []
    conn._post_handshake_hook = None
    conn._client = _FakeClient(connected=True)
    conn._handshaken = True
    return conn


def _patch_tail(conn, *, results):
    """Stub the terminal write+drain to pop from `results`, and record calls to
    disconnect / ensure_connected so a fallback is observable."""
    calls = {"disconnect": 0, "ensure_connected": 0, "write_and_drain": 0}

    async def _disconnect():
        calls["disconnect"] += 1
        conn._client = None
        conn._handshaken = False

    async def _ensure_connected():
        calls["ensure_connected"] += 1
        conn._client = _FakeClient(connected=True)
        conn._handshaken = True

    async def _write_and_drain(plaintext, drain_ms):
        calls["write_and_drain"] += 1
        r = results.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    conn.disconnect = _disconnect
    conn.ensure_connected = _ensure_connected
    conn._write_and_drain = _write_and_drain
    return calls


def test_pooled_write_not_connected_recovers_on_fresh_session():
    # Pooled path: the in-place write raises BleakError("Not connected"); the
    # fallback must disconnect, reconnect, and retry — returning the fresh reply.
    conn = _make_conn()
    calls = _patch_tail(conn, results=[BleakError("Not connected"), [b"\x99"]])

    out = asyncio.run(conn.send_actuation(b"\x0a\x00"))

    assert out == [b"\x99"]
    assert calls["disconnect"] == 1        # stale session dropped
    assert calls["ensure_connected"] == 1  # fresh open
    assert calls["write_and_drain"] == 2   # failed pooled write + fresh retry


def test_pooled_hook_not_connected_recovers_on_fresh_session():
    # Same recovery when it's the bind-refresh hook (not the write) that raises —
    # this is exactly the mesh STOP crash (bind step over a dead proxy link).
    conn = _make_conn()
    hook_calls = {"n": 0}

    async def _hook(_c):
        hook_calls["n"] += 1
        if hook_calls["n"] == 1:
            raise BleakError("Not connected")

    conn._post_handshake_hook = _hook
    calls = _patch_tail(conn, results=[[b"\x77"]])  # only the fresh retry writes

    out = asyncio.run(conn.send_actuation(b"\x0a\x00"))

    assert out == [b"\x77"]
    assert calls["disconnect"] == 1
    assert calls["ensure_connected"] == 1
    assert calls["write_and_drain"] == 1   # pooled path failed before its write


def test_pooled_write_ok_no_reconnect():
    # Healthy pooled session: no fallback, no disconnect/reconnect churn.
    conn = _make_conn()
    calls = _patch_tail(conn, results=[[b"\x01"]])

    out = asyncio.run(conn.send_actuation(b"\x0a\x00"))

    assert out == [b"\x01"]
    assert calls["disconnect"] == 0
    assert calls["ensure_connected"] == 0
    assert calls["write_and_drain"] == 1


def test_cold_session_opens_and_sends():
    # Not pooled to begin with: straight to ensure_connected + write, no fallback.
    conn = _make_conn()
    conn._client = None
    conn._handshaken = False
    calls = _patch_tail(conn, results=[[b"\x02"]])

    out = asyncio.run(conn.send_actuation(b"\x0a\x00"))

    assert out == [b"\x02"]
    assert calls["disconnect"] == 0
    assert calls["ensure_connected"] == 1
    assert calls["write_and_drain"] == 1
