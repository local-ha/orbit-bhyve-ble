"""Protocol round-trip + RX decode tests for the protobuf device family.

Covers the TX frame builders in devices/protobuf.py and the RX status decode in
devices/status.py — the two ends of the wire protocol shared by the HT34A XD and
HT25G2 Gen2 valves. No hardware or Home Assistant required.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from orbit_bhyve.devices import protobuf as tx
from orbit_bhyve.devices import status as rx
from orbit_bhyve.devices.base import DeviceState, _mv_to_pct


# --- protobuf low-level helpers -------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (127, b"\x7f"),
        (128, b"\x80\x01"),
        (300, b"\xac\x02"),
        (16384, b"\x80\x80\x01"),
    ],
)
def test_pb_varint(value, expected):
    assert tx._pb_varint(value) == expected


def test_pb_field_varint_and_bytes():
    # field 1, varint 2 -> tag (1<<3|0)=0x08, value 0x02
    assert tx._pb_field_varint(1, 2) == b"\x08\x02"
    # field 14, length-delimited -> tag (14<<3|2)=0x72, len, data
    assert tx._pb_field_bytes(14, b"\xaa\xbb") == b"\x72\x02\xaa\xbb"


# --- TX frame round-trip --------------------------------------------------

def _status_pb(*, run_state=None, battery_mv=None, watering_active=None) -> bytes:
    """Build a device-status protobuf the way the device would emit it, using
    the same field numbers status.py decodes."""
    out = b""
    if run_state is not None or battery_mv is not None:
        sub = b""
        if run_state is not None:
            sub += tx._pb_field_varint(rx.RX_F_STATUS_MODE, run_state)
        if battery_mv is not None:
            sub += tx._pb_field_bytes(
                rx.RX_F_STATUS_BATT, tx._pb_field_varint(rx.RX_F_BATT_MV, battery_mv)
            )
        out += tx._pb_field_bytes(rx.RX_F_STATUS, sub)
    if watering_active is not None:
        out += tx._pb_field_bytes(
            rx.RX_F_WATERING, tx._pb_field_varint(rx.RX_F_WATERING_ACTIVE, watering_active)
        )
    return out


def test_build_message_is_crc_valid_and_self_decodes():
    frame = tx._build_message(tx._build_start_pb(station_id=0, duration_sec=60))
    # decode_inner enforces header + CRC; a valid frame round-trips to its pb.
    pb = rx.decode_inner(frame)
    assert pb is not None
    assert pb == tx._build_start_pb(0, 60)


def test_start_pb_carries_station_and_duration():
    pb = tx._build_start_pb(station_id=2, duration_sec=900)
    top = rx.pb_parse(pb)
    timer_mode = rx._pb_field(top, 14)            # outer timerMode field
    tm = rx.pb_parse(timer_mode)
    assert rx._pb_field(tm, 1) == 2               # mode = manual(2)
    manual = rx.pb_parse(rx._pb_field(tm, 2))
    station_info = rx.pb_parse(rx._pb_field(manual, 3))
    assert rx._pb_field(station_info, 1) == 2     # wire station id (0-indexed)
    assert rx._pb_field(station_info, 2) == 900   # duration seconds


def test_stop_frame_is_crc_valid():
    assert rx.decode_inner(tx._build_message(tx._STOP_PB)) == tx._STOP_PB


# --- RX status decode -----------------------------------------------------

def test_extract_status_idle_with_battery():
    pb = _status_pb(run_state=1, battery_mv=2712)
    st = rx.extract_status(pb)
    assert st.run_state == 1
    assert st.is_watering is False
    assert st.battery_mv == 2712


def test_extract_status_running():
    st = rx.extract_status(_status_pb(run_state=4, battery_mv=2644))
    assert st.run_state == 4
    assert st.is_watering is True
    assert st.battery_mv == 2644


def test_watering_field_59_takes_precedence_over_absent_runstate():
    st = rx.extract_status(_status_pb(watering_active=1))
    assert st.is_watering is True
    assert st.run_state is None


def test_standalone_battery_report_field_46():
    pb = tx._pb_field_bytes(
        rx.RX_F_BATTERY_REPORT, tx._pb_field_varint(rx.RX_F_BATT_MV, 2800)
    )
    st = rx.extract_status(pb)
    assert st.battery_mv == 2800
    assert st.run_state is None
    assert st.is_watering is None


def test_decode_inner_rejects_bad_crc():
    frame = bytearray(tx._build_message(tx._STOP_PB))
    frame[-1] ^= 0xFF  # corrupt CRC -> simulate an RX-counter-desynced frame
    assert rx.decode_inner(bytes(frame)) is None


def test_decode_inner_rejects_wrong_header():
    assert rx.decode_inner(b"\x00\x01\x02\x03\x04\x05") is None


def test_pb_parse_rejects_truncated_length_delim():
    # tag 0x72 (field 14, len-delim) claims len 5 but no bytes follow.
    assert rx.pb_parse(b"\x72\x05") is None


# --- apply_status_plaintext (state mutation) ------------------------------

def _fake_device():
    return SimpleNamespace(
        mac="AA:BB:CC:DD:EE:FF",
        battery_mv=None,
        battery_pct=None,
        state=DeviceState(is_watering=True, active_zone=1, seconds_remaining=300),
    )


def test_apply_updates_battery_and_clears_zone_on_idle():
    dev = _fake_device()
    rx.apply_status_plaintext(dev, tx._build_message(_status_pb(run_state=1, battery_mv=2700)))
    assert dev.battery_mv == 2700
    assert dev.battery_pct == _mv_to_pct(2700)
    assert dev.state.is_watering is False
    assert dev.state.active_zone is None
    assert dev.state.seconds_remaining is None


def test_apply_sets_watering_true_on_running():
    dev = _fake_device()
    dev.state.is_watering = False
    rx.apply_status_plaintext(dev, tx._build_message(_status_pb(run_state=4, battery_mv=2644)))
    assert dev.state.is_watering is True


def test_apply_rejects_out_of_band_battery():
    dev = _fake_device()
    rx.apply_status_plaintext(dev, tx._build_message(_status_pb(run_state=1, battery_mv=5000)))
    assert dev.battery_mv is None  # 5000 mV is out of the 1500..4000 sanity band


def test_apply_ignores_desynced_frame():
    dev = _fake_device()
    frame = bytearray(tx._build_message(_status_pb(run_state=1, battery_mv=2700)))
    frame[-1] ^= 0xFF  # CRC fails -> frame ignored, state untouched
    rx.apply_status_plaintext(dev, bytes(frame))
    assert dev.battery_mv is None
    assert dev.state.is_watering is True  # unchanged from the fake's initial state
