"""Watering-program protocol tests for the CLI reference (`scripts/bhyve.py`).

Covers the #19/#20/#14/#10 builders, the multi-frame RX reassembler, and the
#19 body decoder — the encode/decode contract the HA layer (W3) must match
byte-for-byte. No hardware required. Byte references are the ones verified live
on both device families in Workstream 0 (see probe_programs.py).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import bhyve as B  # noqa: E402


# --- builder byte references (W0 hardware-verified) ------------------------

@pytest.mark.parametrize(
    "pb,expected",
    [
        (B.build_set_timer_mode_protobuf(1), "720408011200"),   # autoMode
        (B.build_set_timer_mode_protobuf(0), "720408001200"),   # offMode
        (B.build_set_timer_mode_protobuf(2), "720408021200"),   # manualMode (== stop)
        (B.build_stop_protobuf(), "720408021200"),
        (B.build_set_active_programs_protobuf(0), "a201020800"),
        (B.build_set_active_programs_protobuf(8), "a201020808"),  # slot D bit
        (B.build_sync_request_protobuf(), "5200"),               # #10 empty
        (B.build_get_active_programs_protobuf(), "ea0400"),       # #77 empty
        (B.build_program_delete_protobuf(4), "9a010408041200"),   # #19{#1=4,#2 NotSet}
    ],
)
def test_program_builder_byte_refs(pb, expected):
    assert pb.hex() == expected


def test_timer_mode_requires_empty_manual_params_marker():
    # the #2 12 00 marker must be present even for auto/off (a #14 omitting it is ignored)
    assert B.build_set_timer_mode_protobuf(1).endswith(bytes.fromhex("1200"))


def test_active_programs_bitmask_is_one_shifted():
    for slot, bit in [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16)]:
        assert bit == 1 << (slot - 1)
        pb = B.build_set_active_programs_protobuf(bit)
        # #20 { #1 = bit }
        body = B.pb_parse(pb)[0][2]
        assert B._pb_field(B.pb_parse(body), 1) == bit


# --- #19 build -> parse round-trips ----------------------------------------

def _body(pb19):
    """Strip the outer #19 field wrapper, returning the WateringProgram body."""
    return B.pb_parse(pb19)[0][2]


def test_weekdays_multizone_multistart_round_trip():
    spec = B.ProgramSpec(
        slot=4, day_mode="weekdays", weekday_mask=0x7F,
        start_mins=(360, 1080), zones=((0, 300), (1, 420)), name="W0TestD",
    )
    sch = B.parse_program_body(_body(B.build_program_protobuf(spec)))
    assert sch.slot == 4 and not sch.empty
    assert sch.day_mode == "weekdays" and sch.weekday_mask == 0x7F
    assert sch.start_mins == (360, 1080)
    assert sch.zones == ((0, 300), (1, 420))
    assert sch.name == "W0TestD" and sch.budget == 100


def test_interval_round_trip_emits_anchor_iso():
    spec = B.ProgramSpec(
        slot=2, day_mode="interval", interval_days=3,
        interval_anchor="2026-06-28T00:00:00-04:00",
        start_mins=(360,), zones=((0, 600),), name="Drip",
    )
    sch = B.parse_program_body(_body(B.build_program_protobuf(spec)))
    assert sch.day_mode == "interval" and sch.interval_days == 3
    assert sch.interval_anchor.startswith("2026-06-28")
    assert sch.start_mins == (360,) and sch.zones == ((0, 600),)


@pytest.mark.parametrize("mode,field", [("odd", 5), ("even", 6)])
def test_odd_even_empty_markers(mode, field):
    spec = B.ProgramSpec(slot=1, day_mode=mode, start_mins=(360,), zones=((0, 60),), name="x")
    body = _body(B.build_program_protobuf(spec))
    # the day-mode marker is an empty length-delimited field
    assert B._pb_field(B.pb_parse(body), field) == b""
    assert B.parse_program_body(body).day_mode == mode


def test_delete_produces_notset_and_parses_empty():
    sch = B.parse_program_body(_body(B.build_program_delete_protobuf(1)))
    assert sch.slot == 1 and sch.empty


def test_parse_decodes_packed_repeated_start_times():
    # HW-confirmed (fw0111): a #10 read echoes #8 start-times as a PACKED repeated
    # varint (wire 2), not the individual varints we write. A single start 55 came
    # back as `#8` bytes `37`; multi-start packs several varints in one field.
    body = (
        B.pb_field_varint(1, 6)
        + B.pb_field_bytes(3, B.pb_field_varint(1, 0x7F))
        + B.pb_field_bytes(8, B.pb_varint(360) + B.pb_varint(1080))  # packed
        + B.pb_field_bytes(9, B.pb_field_varint(1, 0) + B.pb_field_varint(2, 120))
    )
    sch = B.parse_program_body(body)
    assert sch.start_mins == (360, 1080)


def test_parse_decodes_packed_single_start_hw_shape():
    # the exact bytes BTValve03 echoed for `--start 00:55` (start_min 55 = 0x37)
    body = bytes.fromhex("08061a02087f4201374a040800103c50648a0107434c4954455354")
    sch = B.parse_program_body(body)
    assert sch.slot == 6 and sch.name == "CLITEST"
    assert sch.start_mins == (55,)
    assert sch.zones == ((0, 60),)
    assert sch.weekday_mask == 0x7F


# --- multi-frame RX reassembly ---------------------------------------------

def _frame_stream(key, iv, base, inner_msgs, block_splits):
    """Encrypt concatenated inner messages as one CTR stream and chop the
    ciphertext into outer frames of the given block counts."""
    stream = b"".join(B.build_message(p) for p in inner_msgs)
    ct, _ = B.aes_encrypt(key, iv, base, stream)
    frames, off = [], 0
    for nblk in block_splits:
        chunk = ct[off:off + nblk * 16]
        if not chunk:
            break
        frames.append(B.build_ble_frame(chunk, B.compute_trailer(b"")))
        off += nblk * 16
    if off < len(ct):
        frames.append(B.build_ble_frame(ct[off:], B.compute_trailer(b"")))
    return frames


def test_reassembles_messages_split_across_frames():
    key, iv, base = bytes(range(16)), bytes(range(4, 16)), 1000
    inner = [
        B.build_sync_request_protobuf(),
        B.build_program_protobuf(B.ProgramSpec(
            4, "weekdays", weekday_mask=42, start_mins=(360,), zones=((0, 300),),
            name="A long enough name to force this message across a frame boundary!")),
        B.build_set_active_programs_protobuf(9),
    ]
    # deliberately split so the long #19 spans multiple frames
    frames = _frame_stream(key, iv, base, inner, block_splits=(1, 3, 2))
    got_base, _stream, msgs = B.reassemble_rx(key, iv, base, frames)
    assert got_base == base
    assert sum(1 for m in msgs if m["crc_ok"]) == 3


def test_reassemble_finds_base_when_prior_push_consumed_blocks():
    key, iv = bytes(range(16)), bytes(range(4, 16))
    real_base = 1234
    inner = [B.build_set_active_programs_protobuf(3)]
    frames = _frame_stream(key, iv, real_base, inner, block_splits=(1,))
    # caller's tracked base is a few blocks stale; the sweep must recover it
    got_base, _stream, msgs = B.reassemble_rx(key, iv, real_base - 5, frames)
    assert got_base == real_base
    assert msgs and msgs[0]["crc_ok"]


def test_dedup_consecutive_drops_repeat_frame():
    frames = [b"\x11\x02\xaa\xbb", b"\x11\x02\xaa\xbb", b"\x11\x02\xcc\xdd"]
    assert B._dedup_consecutive(frames) == [b"\x11\x02\xaa\xbb", b"\x11\x02\xcc\xdd"]


# --- clock sync (#18) -------------------------------------------------------

def test_set_clock_builds_iso_local_string():
    from datetime import datetime, timezone, timedelta

    when = datetime(2026, 7, 6, 21, 45, 30, tzinfo=timezone(timedelta(hours=-4)))
    pb = B.build_set_clock_protobuf(when)
    assert pb[:2].hex() == "9201"  # field 18, wire 2
    inner = B.pb_parse(B._pb_field(B.pb_parse(pb), 18))
    assert B._pb_field(inner, 1).decode() == "2026-07-06T21:45:30-04:00"


# --- sync-dump parsing ------------------------------------------------------

def test_parse_sync_dump_fills_enabled_from_bitmask():
    key, iv, base = bytes(range(16)), bytes(range(4, 16)), 500
    prog_a = B.build_program_protobuf(B.ProgramSpec(1, "odd", start_mins=(360,), zones=((0, 60),), name="A"))
    prog_c = B.build_program_protobuf(B.ProgramSpec(3, "even", start_mins=(420,), zones=((0, 60),), name="C"))
    active = B.build_set_active_programs_protobuf(0b001)  # only A enabled (bit 0)
    frames = _frame_stream(key, iv, base, [prog_a, prog_c, active], block_splits=(2, 2))
    _b, _s, msgs = B.reassemble_rx(key, iv, base, frames)
    programs, mask, _status = B.parse_sync_dump(msgs)
    assert mask == 0b001
    assert programs[1].enabled is True    # A (bit 0 set)
    assert programs[3].enabled is False   # C (bit 2 clear)
