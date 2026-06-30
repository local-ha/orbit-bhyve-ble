"""Protobuf-family RX status decode (HT34A / HT25G2).

Ported from our standalone CLI's proven decoder (`scripts/bhyve.py`,
`extract_status`) — hardware-validated against fw0107 (XD) and fw0111
(Gen2). The device→host notification is an inner message
`AA 77 5A 0F | payload_len | 00 | protobuf | CRC16-CCITT`; we parse the
protobuf for battery mV and run-state.

The CRC check is load-bearing here: a notification decrypted with a
desynced RX counter yields garbage that fails CRC, so consuming only
CRC-valid frames keeps a momentary counter desync from poisoning state.
"""
from __future__ import annotations

import logging
import struct
from datetime import datetime, timezone
from typing import NamedTuple

from .base import _mv_to_pct

_LOGGER = logging.getLogger(__name__)

MSG_HEADER = bytes([0xAA, 0x77, 0x5A, 0x0F])

# RX message field numbers (see docs/ble_protocol.md).
RX_F_STATUS = 16          # device status submessage
RX_F_STATUS_MODE = 1      #   #16.#1: 1=idle, 3=rain-delay, 4=manual running
RX_F_STATUS_RAINDELAY = 13  # #16.#13: rain-delay block { #1=min, #3=expiry, #4=on }
RX_F_RD_MINUTES = 1       #   #16.#13.#1: rain-delay minutes
RX_F_RD_EXPIRY = 3        #   #16.#13.#3: rain-delay expiry, Unix epoch seconds
RX_F_RD_ENABLED = 4       #   #16.#13.#4: rain-delay enabled flag (0/1)
RX_F_STATUS_BATT = 14     #   #16.#14: battery block { #3 = mV }
RX_F_BATT_MV = 3          #   battery millivolts (#16.#14.#3 or #46.#3)
RX_F_BATTERY_REPORT = 46  # standalone battery report { #3 = mV }
RX_F_WATERING = 59        # watering status { #1 active flag (0=not watering) }
RX_F_WATERING_ACTIVE = 1


def _crc16_ccitt(data: bytes, init: int = 0) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def _read_varint(data: bytes, i: int):
    shift = 0
    result = 0
    while i < len(data):
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
    return None, i


def pb_parse(data: bytes):
    """Parse protobuf to a list of (field, wire, value), or None if malformed."""
    fields = []
    i = 0
    while i < len(data):
        tag, i = _read_varint(data, i)
        if tag is None:
            return None
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            val, i = _read_varint(data, i)
            if val is None:
                return None
            fields.append((field, wire, val))
        elif wire == 2:
            ln, i = _read_varint(data, i)
            if ln is None or i + ln > len(data):
                return None
            fields.append((field, wire, data[i:i + ln]))
            i += ln
        elif wire == 5:
            if i + 4 > len(data):
                return None
            fields.append((field, wire, data[i:i + 4]))
            i += 4
        elif wire == 1:
            if i + 8 > len(data):
                return None
            fields.append((field, wire, data[i:i + 8]))
            i += 8
        else:
            return None  # groups / unknown wire types
    return fields


def decode_inner(pt: bytes):
    """Validate the inner message CRC and return its protobuf, or None."""
    if len(pt) < 6 or pt[:4] != MSG_HEADER:
        return None
    payload_len = pt[4]
    pb_end = 4 + payload_len
    if payload_len < 2 or pb_end + 2 > len(pt):
        return None
    protobuf = pt[6:pb_end]
    crc_rx = struct.unpack("<H", pt[pb_end:pb_end + 2])[0]
    if crc_rx != _crc16_ccitt(pt[:pb_end], 0):
        return None
    return protobuf


def _pb_field(fields, num):
    for field, _wire, val in fields or ():
        if field == num:
            return val
    return None


def _pb_subfield(fields, outer, inner):
    blob = _pb_field(fields, outer)
    if not isinstance(blob, (bytes, bytearray)):
        return None
    return _pb_field(pb_parse(blob), inner)


class DeviceStatus(NamedTuple):
    run_state: int | None        # #16.#1: 1=idle, 3=rain-delay, 4=running
    is_watering: bool | None     # derived from #16.#1 / #59.#1
    battery_mv: int | None       # #16.#14.#3 or standalone #46.#3
    rain_delay_minutes: int | None = None  # #16.#13.#1
    rain_delay_expiry: int | None = None   # #16.#13.#3, Unix epoch seconds
    rain_delay_active: bool | None = None  # #16.#13.#4


def extract_status(protobuf: bytes) -> DeviceStatus:
    top = pb_parse(protobuf)
    if top is None:
        return DeviceStatus(None, None, None)

    run_state = battery_mv = is_watering = None
    rd_minutes = rd_expiry = rd_active = None

    status = _pb_field(top, RX_F_STATUS)          # #16 submessage
    if isinstance(status, (bytes, bytearray)):
        sfields = pb_parse(status)
        run_state = _pb_field(sfields, RX_F_STATUS_MODE)
        battery_mv = _pb_subfield(sfields, RX_F_STATUS_BATT, RX_F_BATT_MV)
        rd = _pb_field(sfields, RX_F_STATUS_RAINDELAY)   # #16.#13
        if isinstance(rd, (bytes, bytearray)):
            rdf = pb_parse(rd)
            rd_minutes = _pb_field(rdf, RX_F_RD_MINUTES)
            rd_expiry = _pb_field(rdf, RX_F_RD_EXPIRY)
            enabled = _pb_field(rdf, RX_F_RD_ENABLED)
            # A cleared delay echoes a bare #13{#1=0} (no #4), so don't leave
            # active=None there or the clear is dropped — derive it from minutes
            # when #4 is absent.
            if enabled is not None:
                rd_active = bool(enabled)
            elif rd_minutes is not None:
                rd_active = rd_minutes > 0
            else:
                rd_active = None

    if battery_mv is None:                         # standalone #46.#3
        battery_mv = _pb_subfield(top, RX_F_BATTERY_REPORT, RX_F_BATT_MV)

    active = _pb_subfield(top, RX_F_WATERING, RX_F_WATERING_ACTIVE)  # #59.#1
    if active is not None:
        is_watering = bool(active)
    elif run_state is not None:
        is_watering = run_state == 4

    return DeviceStatus(
        run_state=run_state,
        is_watering=is_watering,
        battery_mv=battery_mv,
        rain_delay_minutes=rd_minutes,
        rain_delay_expiry=rd_expiry,
        rain_delay_active=rd_active,
    )


def apply_status_plaintext(device, pt: bytes) -> None:
    """Plaintext observer for protobuf-family devices: decode a CRC-valid
    status notification and update the device's live battery + watering state.
    Non-status / desynced frames fail CRC and are ignored."""
    protobuf = decode_inner(pt)
    if protobuf is None:
        return
    st = extract_status(protobuf)

    if st.battery_mv is not None and 1500 <= st.battery_mv <= 4000:
        device.battery_mv = st.battery_mv
        device.battery_pct = _mv_to_pct(st.battery_mv)

    if st.is_watering is not None:
        device.state.is_watering = st.is_watering
        if not st.is_watering:
            device.state.active_zone = None
            device.state.seconds_remaining = None

    if st.rain_delay_active is not None:
        if st.rain_delay_active and st.rain_delay_minutes:
            device.state.rain_delay_minutes = st.rain_delay_minutes
            device.state.rain_delay_ends = (
                datetime.fromtimestamp(st.rain_delay_expiry, tz=timezone.utc)
                if st.rain_delay_expiry
                else None
            )
        else:
            device.state.rain_delay_minutes = 0
            device.state.rain_delay_ends = None

    if (
        st.battery_mv is not None
        or st.is_watering is not None
        or st.rain_delay_active is not None
    ):
        _LOGGER.debug(
            "%s: live status battery=%smv watering=%s run_state=%s rain_delay=%s",
            device.mac, st.battery_mv, st.is_watering, st.run_state,
            st.rain_delay_minutes,
        )
