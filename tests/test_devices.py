"""Device-class dispatch + structure tests.

Verifies resolve_device_class() routes each hardware/firmware/type to the right
class — in particular that Gen2 HT25G2 valves (which share the "HT25" prefix
with the older mesh hose timers) land on the protobuf class, not the mesh one —
and that the consolidated protobuf family keeps its expected shape. No hardware
or Home Assistant required.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from orbit_bhyve.devices import (
    BHyveHT25Device,
    BHyveHT25Fw0085Device,
    BHyveHT25G2Device,
    BHyveHT34ADevice,
    BHyveHubDevice,
    UnsupportedModel,
    resolve_device_class,
)
from orbit_bhyve.connection import BHyveBleConnection
from orbit_bhyve.devices import protobuf as pb
from orbit_bhyve.devices import status as rx
from orbit_bhyve.devices.base import DeviceState, _mv_to_pct
from orbit_bhyve.devices.protobuf import BHyveProtobufDevice


@pytest.mark.parametrize(
    "hardware,firmware,type_,expected",
    [
        ("", "", "bridge", BHyveHubDevice),               # hub wins on type
        ("HT34A-0001", "0107", "", BHyveHT34ADevice),     # XD 4-port
        ("HT25G2-0001", "0111", "", BHyveHT25G2Device),   # Gen2 by suffix
        ("HT25-0001", "0111", "", BHyveHT25G2Device),       # Gen2 by fw0111
        ("HT25-0001", "0085", "", BHyveHT25Fw0085Device),   # mesh fw0085 (upstream subclass)
        ("HT25-0001", "0041", "", BHyveHT25Device),         # mesh base (fw0041)
    ],
)
def test_resolve_routes(hardware, firmware, type_, expected):
    assert resolve_device_class(hardware=hardware, firmware=firmware, type_=type_) is expected


def test_resolve_unknown_raises():
    with pytest.raises(UnsupportedModel):
        resolve_device_class(hardware="ZZ99", firmware="0001", type_="")


def test_protobuf_family_subclassing():
    assert issubclass(BHyveHT34ADevice, BHyveProtobufDevice)
    assert issubclass(BHyveHT25G2Device, BHyveProtobufDevice)


@pytest.mark.parametrize(
    "cls,label",
    [(BHyveHT34ADevice, "HT34A"), (BHyveHT25G2Device, "HT25G2")],
)
def test_protobuf_family_attrs(cls, label):
    assert cls.log_label == label
    assert cls.frame_magic == 0x11
    assert cls.trailer_const == 0x11


@pytest.mark.parametrize(
    "mv,pct",
    [
        (2400, 0),     # curve floor
        (3000, 100),   # curve ceiling
        (2700, 50),    # midpoint
        (2000, 0),     # below floor clamps
        (3500, 100),   # above ceiling clamps
    ],
)
def test_mv_to_pct(mv, pct):
    assert _mv_to_pct(mv) == pct


# --- actuation confirm-via-#15 (regression for stuck-open valve) ----------

def _status_frame(run_state: int) -> bytes:
    """A CRC-valid #16 status notification carrying only the run-state."""
    inner = pb._pb_field_bytes(rx.RX_F_STATUS, pb._pb_field_varint(rx.RX_F_STATUS_MODE, run_state))
    return pb._build_message(inner)


_STATUS_REQ_FRAME = None  # set lazily to the #15{} frame the device emits


class _FakeConn:
    """Stand-in for BHyveBleConnection: records sent frames and feeds a canned
    plaintext back through the device's own observer, exactly as _on_notify
    would after decrypting an RX notification."""

    def __init__(self, device, *, on_status=None, on_command=None):
        self.device = device
        self.on_status = on_status      # fed when the #15{} status request is sent
        self.on_command = on_command    # fed on any other frame (start/stop/rain)
        self.sent: list[bytes] = []
        self.disconnects = 0

    async def send(self, frame: bytes, drain_ms: int = 1500):
        self.sent.append(frame)
        pt = self.on_status if frame == pb._build_message(pb._REQUEST_STATUS_PB) else self.on_command
        if pt is not None:
            self.device._observe_plaintext(pt)
        return [b"\x01"]  # one notification (the bare #30 ack for a stop)

    async def disconnect(self):
        self.disconnects += 1

    @property
    def is_connected(self):
        return True


def _make_device(**state_kwargs):
    dev = object.__new__(BHyveHT25G2Device)  # bypass HA-heavy __init__
    dev.mac = "AA:BB:CC:DD:EE:FF"
    dev.state = DeviceState(**state_kwargs)
    return dev


def test_stop_confirms_via_status_poll_when_reply_lacks_status():
    # The device answers a stop with a bare #30 ack (no #16), so the stop send
    # alone can't confirm; the #15{} poll returns idle and closes the valve.
    dev = _make_device(is_watering=True, active_zone=1, seconds_remaining=600)
    dev.state.expected_off_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    dev.connection = _FakeConn(dev, on_status=_status_frame(1), on_command=None)

    ok = asyncio.run(dev.stop_watering())

    assert ok is True
    assert dev.state.is_watering is False
    assert dev.state.expected_off_at is None       # wall-clock auto-close disarmed
    assert pb._build_message(pb._REQUEST_STATUS_PB) in dev.connection.sent


def test_stop_not_confirmed_when_device_still_watering():
    # If the #15{} poll still shows run-state 4, the stop must NOT falsely
    # confirm — it retries with a fresh session and reports failure.
    dev = _make_device(is_watering=True, active_zone=1, seconds_remaining=600)
    dev.connection = _FakeConn(dev, on_status=_status_frame(4), on_command=None)

    ok = asyncio.run(dev.stop_watering())

    assert ok is False
    assert dev.state.is_watering is True
    assert dev.connection.disconnects == 2         # both attempts retried


def test_refresh_state_polls_status_and_sees_out_of_band_run():
    # The coordinator poll must actually read the device (#15{}) so a run HA
    # didn't start (a scheduled program) becomes visible.
    dev = _make_device(is_watering=False)
    dev.connection = _FakeConn(dev, on_status=_status_frame(4), on_command=_status_frame(4))

    state = asyncio.run(dev.refresh_state())

    assert state.is_watering is True
    assert pb._build_message(pb._REQUEST_STATUS_PB) in dev.connection.sent


def test_start_arms_wall_clock_autoclose():
    # A confirmed start must arm expected_off_at so the coordinator can close
    # the valve on the wall clock even if a later BLE read/stop fails.
    dev = _make_device(is_watering=False)
    dev.connection = _FakeConn(dev, on_status=_status_frame(4), on_command=_status_frame(4))

    ok = asyncio.run(dev.start_watering(1, 600))

    assert ok is True
    assert dev.state.is_watering is True
    assert dev.state.active_zone == 1
    assert dev.state.expected_off_at is not None


def test_stop_confirms_when_rain_delay_active():
    # After a stop with a rain delay active the device reports run-state 3
    # (rain-delay), which is "not watering" — the stop should confirm.
    dev = _make_device(is_watering=True, active_zone=1)
    dev.connection = _FakeConn(dev, on_status=_status_frame(3), on_command=None)

    ok = asyncio.run(dev.stop_watering())

    assert ok is True
    assert dev.state.is_watering is False


# --- event-driven drain (connection.py) -----------------------------------

def _make_conn() -> BHyveBleConnection:
    return BHyveBleConnection(None, "AA:BB:CC:DD:EE:FF", "00" * 16)


def test_on_notify_drops_duplicate_redelivery():
    # A re-delivered (byte-identical) frame must not be decrypted again — doing
    # so would advance the RX counter and desync the CTR stream. It's buffered
    # once; the duplicate is dropped.
    conn = _make_conn()
    frame = b"\x11\x02\x00\x00"
    conn._on_notify(None, frame)
    conn._on_notify(None, frame)
    assert conn._notif_buf == [frame]


def test_drain_returns_at_cap_when_silent():
    # No reply -> _drain waits out the (short) drain_ms cap and returns.
    conn = _make_conn()

    async def run():
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        await conn._drain(120)  # 120ms hard cap, no frames delivered
        return loop.time() - t0

    elapsed = asyncio.run(run())
    assert 0.10 <= elapsed < 0.30


def test_drain_returns_early_after_reply_goes_quiet():
    # A frame at 20ms should let _drain return ~one quiet window later, far
    # short of the 2s cap — this is the latency win over a fixed sleep.
    conn = _make_conn()

    async def run():
        loop = asyncio.get_running_loop()

        async def feed():
            await asyncio.sleep(0.02)
            conn._notif_buf.append(b"\x11\x02\x00\x00")
            conn._notif_event.set()

        t0 = loop.time()
        task = asyncio.create_task(feed())
        await conn._drain(2000)
        elapsed = loop.time() - t0
        await task
        return elapsed

    elapsed = asyncio.run(run())
    assert elapsed < 1.0            # returned well before the 2s cap
    assert conn._notif_buf         # the frame is retained for the caller
