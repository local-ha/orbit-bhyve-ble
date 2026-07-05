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


def _flow_frame(active: int, total: int) -> bytes:
    """A CRC-valid #59 watering/flow notification { #1=flow-active, #3=cumulative }."""
    inner = pb._pb_field_bytes(
        rx.RX_F_WATERING,
        pb._pb_field_varint(rx.RX_F_WATERING_ACTIVE, active)
        + pb._pb_field_varint(rx.RX_F_FLOW_TOTAL, total),
    )
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
    dev.flow_counts_per_gallon = 433  # set by base __init__ from options normally
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


def test_stop_confirms_immediately_via_stop_ack():
    # If the stop command response contains the #30 stop command acknowledgment,
    # it must confirm the stop immediately and bypass/skip needing status poll confirmations.
    dev = _make_device(is_watering=True, active_zone=1, seconds_remaining=600)
    dev.state.expected_off_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    
    stop_ack = pb._pb_field_bytes(30, b"\x08\x01")
    stop_ack_frame = pb._build_message(stop_ack)
    
    dev.connection = _FakeConn(dev, on_status=None, on_command=stop_ack_frame)
    
    ok = asyncio.run(dev.stop_watering())
    
    assert ok is True
    assert dev.state.is_watering is False
    assert dev.state.expected_off_at is None


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


def _status_clock_and_rain_delay(clock: int, minutes: int) -> bytes:
    """A #16 status carrying #7 device clock (top-level) + an active #16.#13
    rain-delay block, as the device would answer a #15{} poll."""
    rd = pb._pb_field_varint(rx.RX_F_RD_MINUTES, minutes)
    rd += pb._pb_field_varint(rx.RX_F_RD_ENABLED, 1)
    sub = pb._pb_field_varint(rx.RX_F_STATUS_MODE, 3)
    sub += pb._pb_field_bytes(rx.RX_F_STATUS_RAINDELAY, rd)
    top = pb._pb_field_varint(rx.RX_F_CLOCK, clock)
    top += pb._pb_field_bytes(rx.RX_F_STATUS, sub)
    return pb._build_message(top)


def test_set_rain_delay_anchors_expiry_to_device_clock():
    # The device honors the absolute #3 expiry literally, so set_rain_delay must
    # read the device clock (#7) via a #15{} poll first and compute
    # #3 = deviceClock + minutes*60 — NOT host time. A host/device skew would
    # otherwise end the delay early/late.
    clock = 1_700_000_000
    minutes = 360
    dev = _make_device(is_watering=False)
    dev.connection = _FakeConn(
        dev, on_status=_status_clock_and_rain_delay(clock, minutes), on_command=None
    )

    ok = asyncio.run(dev.set_rain_delay(minutes))

    assert ok is True
    status_req = pb._build_message(pb._REQUEST_STATUS_PB)
    unsub_req = pb._build_message(pb._FLOW_UNSUBSCRIBE_PB)
    rd_frames = [f for f in dev.connection.sent if f != status_req and f != unsub_req]
    assert len(rd_frames) == 1
    rd_pb = rx.pb_parse(rx._pb_field(rx.pb_parse(rx.decode_inner(rd_frames[0])), 17))
    assert rx._pb_field(rd_pb, rx.RX_F_RD_MINUTES) == minutes
    assert rx._pb_field(rd_pb, rx.RX_F_RD_EXPIRY) == clock + minutes * 60


# --- flow (#57/#59, Gen2-only) --------------------------------------------

def test_has_flow_only_on_gen2():
    # Gen2 (HT25G2) has an inline flow sensor; the XD (HT34A) does not.
    assert BHyveHT25G2Device.has_flow is True
    assert BHyveHT34ADevice.has_flow is False


def test_flow_subscribe_pb_round_trips_and_matches_capture():
    frame = pb._build_message(pb._FLOW_SUBSCRIBE_PB)
    assert rx.decode_inner(frame) == pb._FLOW_SUBSCRIBE_PB
    sub = rx.pb_parse(rx._pb_field(rx.pb_parse(pb._FLOW_SUBSCRIBE_PB), 57))
    assert rx._pb_field(sub, 1) == 1000   # intervalMs (app capture)
    assert rx._pb_field(sub, 2) == 2      # type (app capture)


def test_read_flow_noop_on_flowless_device():
    # The XD must never be poked with #57 — it has no flow path.
    xd = object.__new__(BHyveHT34ADevice)
    xd.mac = "AA:BB:CC:DD:EE:FF"
    xd.state = DeviceState()
    xd.connection = _FakeConn(xd)
    asyncio.run(xd.read_flow())
    assert xd.connection.sent == []


def test_gpm_from_samples_computes_rate():
    # 144 counts over 4.45 s = 32.4 counts/s → ~4.49 gpm at 433 counts/gal
    # (matches the measured BTValve01 calibration run).
    gpm = pb._gpm_from_samples([(0.0, 0), (4.45, 144)], 433)
    assert 4.4 <= gpm <= 4.6


def test_gpm_from_samples_scales_with_calibration():
    # Halving counts-per-gallon doubles the reported gpm (the option is honoured).
    base = pb._gpm_from_samples([(0.0, 0), (4.0, 200)], 400)
    half = pb._gpm_from_samples([(0.0, 0), (4.0, 200)], 200)
    assert round(half, 2) == round(base * 2, 2)


def test_gpm_from_samples_zero_when_no_advance():
    assert pb._gpm_from_samples([(0.0, 100), (4.0, 100)], 433) == 0.0  # counter flat
    assert pb._gpm_from_samples([(0.0, 100)], 433) == 0.0              # one sample
    assert pb._gpm_from_samples([], 433) == 0.0                         # no samples


class _DesyncThenFreshConn:
    """First flow subscribe decodes to nothing (simulates a desynced RX counter);
    after a disconnect (fresh handshake) the #59 decodes cleanly."""

    def __init__(self, device):
        self.device = device
        self.sent: list[bytes] = []
        self.disconnects = 0
        self._fresh = False

    async def send(self, frame: bytes, drain_ms: int = 1500):
        self.sent.append(frame)
        if self._fresh:
            self.device._observe_plaintext(_flow_frame(active=1, total=500))
        return [b"\x01"]

    async def disconnect(self):
        self.disconnects += 1
        self._fresh = True

    @property
    def is_connected(self):
        return True


def test_read_flow_resyncs_after_desynced_session():
    # No decodable #59 on the pooled session → read_flow drops the connection and
    # retries once on a fresh handshake, which decodes (regression for "Check flow
    # only updated at the next poll").
    dev = _make_device(is_watering=True)
    dev.connection = _DesyncThenFreshConn(dev)
    asyncio.run(dev.read_flow())
    assert dev.connection.disconnects == 1
    assert dev.state.flow_gpm == 0.0  # a decodable #59 (flow 0 here) was committed
    n_sub = dev.connection.sent.count(pb._build_message(pb._FLOW_SUBSCRIBE_PB))
    assert n_sub == 2  # both attempts subscribed exactly once


def test_read_flow_no_reconnect_when_healthy():
    # A healthy session decodes #59 on the first pass → no wasteful reconnect.
    dev = _make_device(is_watering=True)
    dev.connection = _FakeConn(dev, on_status=None, on_command=_flow_frame(active=1, total=500))
    asyncio.run(dev.read_flow())
    assert dev.connection.disconnects == 0
    assert dev.state.flow_gpm == 0.0


def test_read_flow_always_unsubscribes():
    # read_flow must cancel the stream (#57{#1=0}) as its last act, so it never
    # leaves a persistent #59 subscription that starves the next poll's #16 read.
    dev = _make_device(is_watering=True)
    dev.connection = _FakeConn(dev, on_status=None, on_command=_flow_frame(active=1, total=500))
    asyncio.run(dev.read_flow())
    assert dev.connection.sent[-1] == pb._build_message(pb._FLOW_UNSUBSCRIBE_PB)


def test_refresh_state_subscribes_flow_while_watering():
    # A Gen2 poll that finds a run in progress should also spot-check flow so the
    # gauge tracks live: the #57 subscribe is issued and flow_gpm is computed.
    dev = _make_device(is_watering=False)
    dev.connection = _FakeConn(
        dev, on_status=_status_frame(4), on_command=_flow_frame(active=1, total=489)
    )
    state = asyncio.run(dev.refresh_state())
    assert state.is_watering is True
    assert pb._build_message(pb._FLOW_SUBSCRIBE_PB) in dev.connection.sent
    assert state.flow_gpm is not None  # a numeric gauge value was set


def test_refresh_state_skips_flow_when_idle():
    # No run -> no flow subscribe (don't wake the radio for nothing).
    dev = _make_device(is_watering=False)
    dev.connection = _FakeConn(dev, on_status=_status_frame(1), on_command=None)
    asyncio.run(dev.refresh_state())
    assert pb._build_message(pb._FLOW_SUBSCRIBE_PB) not in dev.connection.sent


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


def test_device_state_health_metrics():
    state = DeviceState()
    assert state.last_successful_poll is None
    assert state.consecutive_timeouts == 0
    now = datetime.now(timezone.utc)
    state.last_successful_poll = now
    state.consecutive_timeouts += 1
    assert state.last_successful_poll == now
    assert state.consecutive_timeouts == 1


def test_configurable_gatt_settle_ms():
    assert BHyveHT25G2Device.GATT_SETTLE_MS == 300
    assert BHyveHT34ADevice.GATT_SETTLE_MS == 300


# --- Connected = poll reachability (A1) ------------------------------------

class _RaisingConn:
    """A connection whose status send always fails, to exercise the poll-failure
    path in refresh_state."""

    def __init__(self):
        self.disconnects = 0

    async def send(self, frame: bytes, drain_ms: int = 1500):
        raise RuntimeError("boom")

    async def disconnect(self):
        self.disconnects += 1

    @property
    def is_connected(self):
        return False


def test_connected_true_on_successful_poll():
    # A poll that reads a clean #16 marks the device reachable and resets timeouts.
    dev = _make_device(is_watering=False, consecutive_timeouts=3)
    dev.connection = _FakeConn(dev, on_status=_status_frame(1), on_command=None)
    state = asyncio.run(dev.refresh_state())
    assert state.is_connected is True
    assert state.consecutive_timeouts == 0
    assert dev.connection.disconnects >= 1  # ephemeral teardown


def test_connected_false_on_failed_poll():
    # A poll whose status read raises marks the device unreachable (not a stale
    # "connected"), increments the timeout counter, and still disconnects cleanly.
    dev = _make_device(is_watering=False, is_connected=True)
    dev.connection = _RaisingConn()
    state = asyncio.run(dev.refresh_state())
    assert state.is_connected is False
    assert state.consecutive_timeouts == 1
    assert dev.connection.disconnects == 1


# --- multi-frame-safe CTR self-heal (A2) -----------------------------------

class _FakeHass:
    def __init__(self):
        self.jobs: list = []

    def add_job(self, target, *args):
        self.jobs.append(target)


def _handshaken_conn() -> tuple[BHyveBleConnection, _FakeHass]:
    conn = _make_conn()
    conn._handshaken = True
    conn._iv = b"\x00" * 12
    conn._rx_ctr = 0
    hass = _FakeHass()
    conn.hass = hass
    return conn, hass


def _frame_decrypting_to(conn: BHyveBleConnection, pt: bytes, ctr: int) -> bytes:
    """Build an RX frame that conn.decrypt() (at rx_ctr==ctr) recovers to `pt`."""
    ks, _ = conn._aes_keystream(ctr, (len(pt) + 15) // 16)
    ct = bytes(b ^ k for b, k in zip(pt, ks[: len(pt)]))
    return bytes([conn._frame_magic, len(ct)]) + ct + b"\x00\x00"


def test_ctr_selfheal_on_bad_first_frame():
    # A garbage first frame (bad inner header) is a real CTR desync → self-heal.
    conn, hass = _handshaken_conn()
    frame = _frame_decrypting_to(conn, b"\xd0\x18\x29\x07deadbeef", 0)
    conn._on_notify(None, frame)
    assert len(hass.jobs) == 1  # disconnect scheduled


def test_ctr_selfheal_ignores_bad_continuation_frame():
    # A valid header frame first, then a non-header CONTINUATION frame (as a long
    # CTR-streamed reply would produce). The continuation must NOT trip the
    # self-heal — only the reply's first frame is required to carry the header.
    conn, hass = _handshaken_conn()
    good = _frame_decrypting_to(conn, rx.MSG_HEADER + b"\x00" * 8, 0)
    conn._on_notify(None, good)             # first frame: header ok, buffered
    cont = _frame_decrypting_to(conn, b"\x11\x22\x33\x44moredata", conn._rx_ctr)
    conn._on_notify(None, cont)             # continuation: bad header, not first
    assert hass.jobs == []                  # no disconnect scheduled
