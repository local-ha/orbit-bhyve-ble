#!/usr/bin/env python3
"""
Orbit B-Hyve XD Bluetooth Valve Controller

Direct BLE control of the B-Hyve XD hose timer — no cloud, no app, no Wi-Fi hub.

Setup (first time):
    python3 bhyve.py setup                          # Interactive setup wizard
    python3 bhyve.py setup --email you@email.com     # Auto-extract via Orbit API

Control:
    python3 bhyve.py on 1 300        # Zone 1 on for 5 minutes
    python3 bhyve.py on 2 600        # Zone 2 on for 10 minutes
    python3 bhyve.py off              # Stop all watering

Requirements:
    pip install bleak cryptography requests

⚠️  WARNING: Do NOT update your B-Hyve device firmware!
    This controller was reverse-engineered against firmware version 0107.
    A firmware update could change the encryption protocol and break
    compatibility. If the B-Hyve app prompts you to update, decline it.

Protocol reverse-engineered against firmware 0107.
See the project README for the full reverse-engineering documentation.
"""

import asyncio
import argparse
import struct
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ─── Configuration ───────────────────────────────────────────────────────

# Config location: $BHYVE_CONFIG overrides; otherwise the legacy in-repo path.
# Keeping secrets out of the repo tree is the documented setup (point
# $BHYVE_CONFIG at a file outside the checkout); the in-repo path stays as a
# backwards-compatible fallback for existing users.
CONFIG_FILE = Path(os.environ.get("BHYVE_CONFIG") or (Path(__file__).parent / ".bhyve_config.json"))

ORBIT_API_BASE = "https://api.orbitbhyve.com/v1"
ORBIT_APP_ID = "Bhyve-App"

# GATT characteristic UUIDs
AES_CHAR   = "00006c71-fe32-4f58-8b78-98e42b2c047f"
WRITE_CHAR = "00006c72-fe32-4f58-8b78-98e42b2c047f"
READ_CHAR  = "00006c73-fe32-4f58-8b78-98e42b2c047f"

# Inner message constants
MSG_HEADER = bytes([0xAA, 0x77, 0x5A, 0x0F])

FIRMWARE_WARNING = """
╔══════════════════════════════════════════════════════════════════╗
║  ⚠️  WARNING: Do NOT update your B-Hyve device firmware!        ║
║                                                                  ║
║  This controller was reverse-engineered against firmware v0107.  ║
║  A firmware update may change the encryption protocol and break  ║
║  this tool. If the B-Hyve app asks you to update, DECLINE.       ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ─── Config Management ──────────────────────────────────────────────────

def load_config():
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def save_config(config):
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    print(f"Config saved to {CONFIG_FILE}")


# ─── Orbit Cloud API ────────────────────────────────────────────────────

def orbit_login(email, password):
    import requests
    resp = requests.post(
        f"{ORBIT_API_BASE}/session",
        json={"session": {"email": email, "password": password}},
        headers={"orbit-app-id": ORBIT_APP_ID, "Content-Type": "application/json"},
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("orbit_api_key"), data.get("user_id")


def orbit_get_devices(token):
    import requests
    resp = requests.get(
        f"{ORBIT_API_BASE}/devices",
        headers={"orbit-api-key": token, "orbit-app-id": ORBIT_APP_ID},
    )
    resp.raise_for_status()
    return resp.json()


def orbit_get_network_key(token, topology_id):
    # Orbit renamed the endpoint and the response field on accounts migrated
    # to the newer schema. Try legacy paths first so behavior is unchanged
    # for accounts still on the old schema; fall through to current names.
    import requests
    headers = {"orbit-api-key": token, "orbit-app-id": ORBIT_APP_ID}
    candidate_paths = [
        f"/network_topologies/{topology_id}",
        f"/meshes/{topology_id}",
        f"/networks/{topology_id}",
    ]
    last_error = None
    for path in candidate_paths:
        url = f"{ORBIT_API_BASE}{path}"
        try:
            resp = requests.get(url, headers=headers)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            body = resp.json()
            key = body.get("network_key") or body.get("ble_network_key")
            if key:
                return key
        except Exception as e:
            last_error = e
    if last_error:
        raise last_error
    raise RuntimeError("No candidate endpoint returned a network_key")


# ─── Crypto ──────────────────────────────────────────────────────────────

def crc16_ccitt(data, init=0):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def aes_encrypt(key, iv, counter, plaintext):
    result = bytearray()
    for offset in range(0, len(plaintext), 16):
        chunk = plaintext[offset:offset + 16]
        block = iv + struct.pack("<I", counter)
        keystream = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)
        result.extend(b ^ k for b, k in zip(chunk, keystream[:len(chunk)]))
        counter = (counter + 1) % 0x100000000  # 2^32, per-block counter wrap
    return bytes(result), counter


def compute_trailer(plaintext):
    """2-byte outer-frame trailer: uint16_LE(sum(plaintext) + 0x11 + len).

    Matches custom_components/orbit_bhyve_ble/bhyve_device.py and docs/encryption.md.
    The 0x11 is the BLE frame magic header byte; `len` is the frame length byte.
    """
    total = sum(plaintext) + 0x11 + len(plaintext)
    return struct.pack("<H", total & 0xFFFF)


# ─── Message Building ────────────────────────────────────────────────────

def build_message(protobuf):
    payload_len = len(protobuf) + 2
    msg = MSG_HEADER + bytes([payload_len, 0x00]) + protobuf
    crc = struct.pack("<H", crc16_ccitt(msg, 0))
    return msg + crc


def build_ble_frame(ciphertext, trailer):
    return bytes([0x11, len(ciphertext)]) + ciphertext + trailer


def pb_varint(val):
    r = bytearray()
    while val > 0x7F:
        r.append((val & 0x7F) | 0x80)
        val >>= 7
    r.append(val & 0x7F)
    return bytes(r)


def pb_field_varint(f, v):
    return pb_varint((f << 3) | 0) + pb_varint(v)


def pb_field_bytes(f, d):
    return pb_varint((f << 3) | 2) + pb_varint(len(d)) + d


def build_start_protobuf(station_id, duration_sec):
    station_info = pb_field_varint(1, station_id) + pb_field_varint(2, duration_sec)
    manual_params = pb_field_bytes(3, station_info)
    timer_mode = pb_field_varint(1, 2) + pb_field_bytes(2, manual_params)
    return pb_field_bytes(14, timer_mode)


def build_stop_protobuf():
    return bytes.fromhex("720408021200")


def build_rain_delay_protobuf(minutes, expiry=None):
    """Rain delay: #17 { #1=minutes; #3=expiryUnixUTC; #4=1 }.

    `minutes=0` clears the delay (sent as a bare #17{#1=0}). For a set, the app
    sends an absolute expiry (deviceClock + minutes*60) and the enable flag; the
    device echoes its own authoritative expiry back in #16.#13.
    """
    body = pb_field_varint(1, minutes)
    if minutes > 0 and expiry is not None:
        body += pb_field_varint(3, expiry) + pb_field_varint(4, 1)
    return pb_field_bytes(17, body)


def build_request_status_protobuf():
    """Status request: #15 {} (empty). Elicits a full #16 status burst — works
    even when the device is "active" (watering or rain-delay), unlike the
    unsolicited connect-time push which the device suppresses in those states.
    """
    return pb_field_bytes(15, b"")


def build_flow_subscribe_protobuf(interval_ms=1000):
    """Flow subscribe: #57 { #1=intervalMs; #2=2 }. The device then streams periodic
    #59 FlowSensorData frames. On fw0111 these carry only three varints:
    #1=currentFlowRateFrequency_Hz (~0 when dry), #2=currentCycleRunTimeSec (+1/s),
    #3=currentCycleVolumeTicks (cumulative per run; #1 ~= d#3/dt). The float fields
    #4=currentFlowRateGpm / #5=currentCycleVolumeGal do NOT populate on fw0111, so gpm
    is derived from the #3 tick slope. (Vendor names per knobunc's OrbitPbApi schema.)

    Byte-for-byte the app's flow-screen subscribe (Gen2 capture: #1=1000, #2=2).
    Only Gen2 (HT25G2) answered it in the app capture; the XD was never asked —
    the `flow` command sends it to BOTH to confirm the XD truly has no flow path
    (vs. the app just not offering the screen for that model).
    """
    return pb_field_bytes(57, pb_field_varint(1, interval_ms) + pb_field_varint(2, 2))


# ─── Session derivation ────────────────────────────────────────────────────

def derive_session(init_tx, rx_resp):
    """From the 20-byte 6c71 write + read response, return (iv, tx_ctr, rx_ctr).

    IV = rx_resp[:4] || init_tx[4:12] (same for both directions). The 20-byte init
    write carries two counter seeds: TX at [12:16], RX at [16:20]. See
    docs/encryption.md.
    """
    if len(init_tx) < 20 or len(rx_resp) < 4:
        raise ValueError("need >=20-byte init_tx and >=4-byte rx_resp")
    iv = rx_resp[:4] + init_tx[4:12]
    tx_counter = struct.unpack("<I", init_tx[12:16])[0]
    rx_counter = struct.unpack("<I", init_tx[16:20])[0]
    return iv, tx_counter, rx_counter


# ─── RX decode (frame / inner-message / protobuf) ──────────────────────────

def parse_ble_frame(raw):
    """Split `0x11 | len | ciphertext | trailer(2)`; None if not a 0x11 frame."""
    if len(raw) < 4 or raw[0] != 0x11:
        return None
    length = raw[1]
    ct = raw[2:2 + length]
    trailer = raw[2 + length:2 + length + 2]
    if len(ct) != length:
        return None
    return length, ct, trailer


def decode_inner(pt):
    """Parse a decrypted inner message and validate its CRC; None if no header."""
    if len(pt) < 6 or pt[:4] != MSG_HEADER:
        return None
    payload_len = pt[4]
    pb_end = 4 + payload_len            # protobuf occupies pt[6:pb_end]
    if payload_len < 2 or pb_end + 2 > len(pt):
        return None
    protobuf = pt[6:pb_end]
    crc_rx = struct.unpack("<H", pt[pb_end:pb_end + 2])[0]
    crc_calc = crc16_ccitt(pt[:pb_end], 0)
    return {
        "protobuf": protobuf,
        "crc_ok": crc_rx == crc_calc,
        "crc_rx": crc_rx,
        "crc_calc": crc_calc,
    }


def decrypt_frame(key, iv, ct, base_counter, lo=-8, hi=1024):
    """Decrypt, sweeping the counter to find one yielding a valid inner frame.

    Pass the correct base (tx_counter or rx_counter); the small window absorbs
    per-frame counter advance across a notification burst. Returns
    (counter, plaintext, inner) for the first CRC-valid decode, else the first
    header-only match, else Nones.
    """
    fallback = None
    for d in range(lo, hi):
        c = (base_counter + d) % 0x100000000
        pt, _ = aes_encrypt(key, iv, c, ct)
        if pt[:4] != MSG_HEADER:
            continue
        inner = decode_inner(pt)
        if inner and inner["crc_ok"]:
            return c, pt, inner
        if fallback is None:
            fallback = (c, pt, inner)
    return fallback if fallback else (None, None, None)


# ─── Minimal protobuf reader ──────────────────────────────────────────────

def _read_varint(data, i):
    result = shift = 0
    while i < len(data):
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7
        if shift > 63:
            break
    return None, i


def pb_parse(data):
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


def pb_format(data, indent=1):
    fields = pb_parse(data)
    pad = "    " * indent
    if fields is None:
        return f"{pad}<not protobuf> {data.hex()}"
    lines = []
    for field, wire, val in fields:
        if wire == 0:
            lines.append(f"{pad}#{field} varint = {val}")
        elif wire == 2:
            if val and pb_parse(val) is not None:
                lines.append(f"{pad}#{field} ({len(val)}B) {{")
                lines.append(pb_format(val, indent + 1))
                lines.append(f"{pad}}}")
            else:
                lines.append(f"{pad}#{field} bytes({len(val)}) = {val.hex()}")
        elif wire == 5:
            lines.append(f"{pad}#{field} i32 = {val.hex()}")
        elif wire == 1:
            lines.append(f"{pad}#{field} i64 = {val.hex()}")
    return "\n".join(lines)


# ─── RX status extraction ──────────────────────────────────────────────────

# RX message field numbers (see docs/ble_protocol.md "Device→Host (RX) Notifications").
RX_F_CLOCK = 7             # wrapper: device clock, Unix epoch seconds
RX_F_STATUS = 16          # device status / state submessage
RX_F_STATUS_MODE = 1      #   #16.#1: 1=idle, 3=rain-delay, 4=manual running
RX_F_STATUS_RUNECHO = 2   #   #16.#2: active-run echo { #1=2, #2 { #3 { #1 stationId } } }
RX_F_RUNECHO_PARAMS = 2   #     #16.#2.#2 manualParams
RX_F_RUNECHO_STATION = 3  #     #16.#2.#2.#3 stationInfo
RX_F_STATION_ID = 1       #     #16.#2.#2.#3.#1: stationId (0-indexed; zone = id + 1)
RX_F_STATUS_PROGRESS = 6  #   #16.#6: run progress (present only while watering)
# HW-verified 2026-07-05 (Gen2 fw0111 + XD fw0107): #16.#6.#5 counts DOWN (remaining),
# #16.#6.#7 is the constant total. Matches knobunc's currentTimeRemainingSec / totalRunTimeSec.
RX_F_PROGRESS_REMAINING = 5  # #16.#6.#5: seconds remaining (counts down)
RX_F_PROGRESS_TOTAL = 7      # #16.#6.#7: total run-time seconds (constant)
RX_F_PROGRESS_STATION = 4    # #16.#6.#4: currentStationId (running station; HW-verified)
RX_F_STATUS_RAINDELAY = 13  # #16.#13: rain-delay block { #1=min, #3=expiry, #4=on }
RX_F_RD_MINUTES = 1       #   #16.#13.#1: rain-delay minutes
RX_F_RD_EXPIRY = 3        #   #16.#13.#3: rain-delay expiry, Unix epoch seconds
RX_F_RD_ENABLED = 4       #   #16.#13.#4: rain-delay enabled flag (0/1)
RX_F_STATUS_BATT = 14     #   #16.#14: battery block { #3 = mV }
RX_F_BATT_MV = 3          #   battery millivolts (in #16.#14 and #46)
RX_F_BATTERY_REPORT = 46  # standalone battery report { #3 = mV }
RX_F_WATERING = 59        # watering/flow status { #1 flow-active, #2 seq, #3 cumulative }
RX_F_WATERING_ACTIVE = 1  #   #59.#1: water CURRENTLY flowing (not "valve open")
RX_F_FLOW_TOTAL = 3       #   #59.#3: CUMULATIVE volume counter for this run (Gen2)
RX_F_RUNECHO_MODE = 1     #   #16.#2.#1: timerMode.mode (0=off, 1=auto, 2=manual)
RX_F_STATUS_NEXTSTART_FLAGS = 9   # #16.#9: nextStartProgramFlags (slot bitmask, A=bit0)
RX_F_STATUS_NEXTSTART = 10        # #16.#10: nextStartTimeSecEpochUTC

# #59.#3 is a cumulative per-run volume counter in raw device units, not gpm.
# Divide by this to get gallons. MEASURED 2026-07-03 (BTValve01): a 44.5 s window
# logged +1443 counts while a bucket caught 3.33 gal → 1443/3.33 ≈ 433 counts/gal.
FLOW_COUNTS_PER_GALLON = 433


class DeviceStatus(NamedTuple):
    """Decoded device telemetry from an RX notification (absent fields => None)."""
    run_state: int | None        # #16.#1: 1=idle, 3=rain-delay, 4=running
    is_watering: bool | None     # derived from #16.#1 / #59.#1
    battery_mv: int | None       # #16.#14.#3 or standalone #46.#3
    device_clock: int | None = None        # #7 Unix epoch seconds
    active_station: int | None = None      # #16.#6.#4 (fallback #16.#2.#2.#3.#1), 0-indexed (zone = +1)
    seconds_remaining: int | None = None   # #16.#6.#5 (counts down), present only while watering
    flow_total: int | None = None          # #59.#3 cumulative volume counter (Gen2)
    rain_delay_minutes: int | None = None  # #16.#13.#1
    rain_delay_expiry: int | None = None   # #16.#13.#3, Unix epoch seconds
    rain_delay_active: bool | None = None  # #16.#13.#4
    controller_mode: int | None = None     # #16.#2.#1 timerMode.mode: 0=off, 1=auto, 2=manual
    next_start_flags: int | None = None    # #16.#9 nextStartProgramFlags (slot bitmask, A=bit0)
    next_start_epoch: int | None = None    # #16.#10 nextStartTimeSecEpochUTC


def _pb_field(fields, num):
    """Return the value of the first field `num` in a parsed field list, or None."""
    for field, _wire, val in fields or ():
        if field == num:
            return val
    return None


def _pb_subfield(fields, outer, inner):
    """Return field `inner` inside the length-delimited field `outer`, or None."""
    return _pb_path(fields, outer, inner)


def _pb_path(fields, *nums):
    """Walk nested length-delimited submessages by field number, returning the
    final field's value (or None if any hop is missing / not a submessage)."""
    cur = fields
    for n in nums[:-1]:
        blob = _pb_field(cur, n)
        if not isinstance(blob, (bytes, bytearray)):
            return None
        cur = pb_parse(blob)
    return _pb_field(cur, nums[-1])


def extract_status(protobuf):
    """Extract HA-relevant telemetry from a decoded RX protobuf -> DeviceStatus."""
    top = pb_parse(protobuf)
    if top is None:
        return DeviceStatus(None, None, None)

    clock = _pb_field(top, RX_F_CLOCK)
    run_state = battery_mv = is_watering = None
    active_station = seconds_remaining = None
    rd_minutes = rd_expiry = rd_active = None
    controller_mode = next_start_flags = next_start_epoch = None

    status = _pb_field(top, RX_F_STATUS)          # #16 submessage
    if isinstance(status, (bytes, bytearray)):
        sfields = pb_parse(status)
        run_state = _pb_field(sfields, RX_F_STATUS_MODE)
        battery_mv = _pb_subfield(sfields, RX_F_STATUS_BATT, RX_F_BATT_MV)  # #16.#14.#3
        controller_mode = _pb_path(sfields, RX_F_STATUS_RUNECHO, RX_F_RUNECHO_MODE)  # #16.#2.#1
        next_start_flags = _pb_field(sfields, RX_F_STATUS_NEXTSTART_FLAGS)  # #16.#9
        next_start_epoch = _pb_field(sfields, RX_F_STATUS_NEXTSTART)        # #16.#10
        # Which zone is running: prefer the shallow #16.#6.#4, fall back to the
        # deep timerMode path #16.#2.#2.#3.#1.
        active_station = _pb_subfield(sfields, RX_F_STATUS_PROGRESS, RX_F_PROGRESS_STATION)
        if not isinstance(active_station, int):
            active_station = _pb_path(
                sfields, RX_F_STATUS_RUNECHO, RX_F_RUNECHO_PARAMS,
                RX_F_RUNECHO_STATION, RX_F_STATION_ID,
            )
        seconds_remaining = _pb_subfield(  # #16.#6.#5 (remaining; counts down)
            sfields, RX_F_STATUS_PROGRESS, RX_F_PROGRESS_REMAINING
        )
        rd = _pb_field(sfields, RX_F_STATUS_RAINDELAY)                      # #16.#13
        if isinstance(rd, (bytes, bytearray)):
            rdf = pb_parse(rd)
            rd_minutes = _pb_field(rdf, RX_F_RD_MINUTES)
            rd_expiry = _pb_field(rdf, RX_F_RD_EXPIRY)
            enabled = _pb_field(rdf, RX_F_RD_ENABLED)
            # A cleared delay echoes a bare #13{#1=0} (no #4); derive active from
            # minutes when #4 is absent so the cleared state isn't ambiguous.
            if enabled is not None:
                rd_active = bool(enabled)
            elif rd_minutes is not None:
                rd_active = rd_minutes > 0
            else:
                rd_active = None
            # Run-state is authoritative: #16.#13 is NOT cleared on expiry (it lingers
            # stale as {#1:mins,#3:<past>,#4:1}; HW-verified 2026-07-05), so a run-state
            # other than 3 (rain-delay) means no delay is active regardless of the block.
            if run_state is not None and run_state != 3:
                rd_active = False

    if battery_mv is None:                         # standalone #46.#3
        battery_mv = _pb_subfield(top, RX_F_BATTERY_REPORT, RX_F_BATT_MV)

    # run_state (#16.#1) is authoritative for "valve open"; #59.#1 is "water
    # currently flowing" — a valve can be open with no flow (#59.#1=0), so #59.#1
    # may only assert watering, never negate it (see status.py for the rationale).
    if run_state is not None:
        is_watering = run_state == 4
    elif _pb_subfield(top, RX_F_WATERING, RX_F_WATERING_ACTIVE):     # #59.#1 truthy
        is_watering = True
    flow_total = _pb_subfield(top, RX_F_WATERING, RX_F_FLOW_TOTAL)   # #59.#3 cumulative

    return DeviceStatus(
        run_state=run_state,
        is_watering=is_watering,
        battery_mv=battery_mv,
        device_clock=clock,
        active_station=active_station,
        seconds_remaining=seconds_remaining,
        flow_total=flow_total,
        rain_delay_minutes=rd_minutes,
        rain_delay_expiry=rd_expiry,
        rain_delay_active=rd_active,
        controller_mode=controller_mode,
        next_start_flags=next_start_flags,
        next_start_epoch=next_start_epoch,
    )


# ─── Watering programs (#19 / #20 / #14 / #10) ─────────────────────────────
#
# See docs/ble_protocol.md and protobuf/orbit_ble.proto. Reads use #10 syncRequest
# (a one-shot full dump — every #19 slot + #16 status + the #20 enable bitmask),
# reassembled from a multi-frame RX burst. Writes/runs use the 3-write handshake:
# store #19 -> enable #20 -> autoMode #14{1} -> re-send store+enable, confirmed via
# #16.#9/#10 next-start. This module is the reference the HA layer mirrors.

PROGRAM_SLOTS = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
SLOT_LETTERS = {v: k for k, v in PROGRAM_SLOTS.items()}

# day-mode field numbers inside a #19 body (exactly one is present)
_DM_WEEKDAYS = 3   # { #1 dayFlags }  bit0=Sun .. bit6=Sat
_DM_INTERVAL = 4   # { #1 intervalDays, #2 anchorIso }
_DM_ODD = 5        # {} empty marker
_DM_EVEN = 6       # {} empty marker
_DM_RUNONCE = 7    # { #1 programFlags }  (unverified on our hardware)

WEEKDAY_BITS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
WEEKDAY_NAMES = {v: k for k, v in WEEKDAY_BITS.items()}


class ProgramSpec(NamedTuple):
    """A program to write (CLI zones are 1-indexed; `zones` here are 0-indexed
    station ids for the wire)."""
    slot: int                            # 1=A .. 6=F
    day_mode: str                        # "weekdays" | "interval" | "odd" | "even" | "once"
    weekday_mask: int | None = None      # weekdays: bit0=Sun .. bit6=Sat
    interval_days: int | None = None     # interval: N
    interval_anchor: str | None = None   # interval: ISO-8601 anchor
    start_mins: tuple = ()               # minutes-from-midnight (device-local)
    zones: tuple = ()                    # (station_id_0idx, run_sec)
    name: str = ""
    budget: int = 100
    enabled: bool = False                # drive the enable handshake after storing


class ProgramSchedule(NamedTuple):
    """A #19 program body decoded from a device read."""
    slot: int | None
    empty: bool                          # #2 programTypeNotSet present -> empty slot
    day_mode: str | None = None
    weekday_mask: int | None = None
    interval_days: int | None = None
    interval_anchor: str | None = None
    start_mins: tuple = ()
    zones: tuple = ()                    # (station_id_0idx, run_sec)
    name: str | None = None
    budget: int | None = None
    enabled: bool | None = None          # filled from the #20 bitmask, not the #19 body


# ── builders ────────────────────────────────────────────────────────────────

def build_sync_request_protobuf():
    """#10 syncRequest {} — empty; device replies with a full state dump."""
    return pb_field_bytes(10, b"")


def build_get_active_programs_protobuf():
    """#77 getActivePrograms {} — empty; device replies with just the #20 bitmask."""
    return pb_field_bytes(77, b"")


def build_set_active_programs_protobuf(flags):
    """#20 setActivePrograms { #1 activeProgramFlags } — the enable BITMASK
    (A=bit0: 1<<(slot-1)). The device fills #2/#3 lastChange* itself."""
    return pb_field_bytes(20, pb_field_varint(1, flags))


def build_set_timer_mode_protobuf(mode):
    """#14 timerMode { #1 mode, #2 {} EMPTY } — DEVICE-GLOBAL controller mode.

    mode 0=offMode ("controller off / automatic watering disabled"), 1=autoMode
    ("Enable Watering", the normal resting state — scheduled programs run),
    2=manualMode (empty #2 => stop the current run). The empty #2 marker (`12 00`)
    is REQUIRED — a #14 that omits it is silently ignored.
    """
    return pb_field_bytes(14, pb_field_varint(1, mode) + pb_field_bytes(2, b""))


def build_program_protobuf(spec):
    """#19 setProgramSchedule from a ProgramSpec (a full, runnable program)."""
    body = pb_field_varint(1, spec.slot)
    if spec.day_mode == "weekdays":
        body += pb_field_bytes(_DM_WEEKDAYS, pb_field_varint(1, spec.weekday_mask or 0))
    elif spec.day_mode == "interval":
        iv = pb_field_varint(1, spec.interval_days or 1)
        if spec.interval_anchor:
            iv += pb_field_bytes(2, spec.interval_anchor.encode())
        body += pb_field_bytes(_DM_INTERVAL, iv)
    elif spec.day_mode == "odd":
        body += pb_field_bytes(_DM_ODD, b"")
    elif spec.day_mode == "even":
        body += pb_field_bytes(_DM_EVEN, b"")
    elif spec.day_mode == "once":
        body += pb_field_bytes(_DM_RUNONCE, pb_field_varint(1, 1 << (spec.slot - 1)))
    for m in spec.start_mins:
        body += pb_field_varint(8, m)
    for sid, sec in spec.zones:
        body += pb_field_bytes(9, pb_field_varint(1, sid) + pb_field_varint(2, sec))
    body += pb_field_varint(10, spec.budget)
    if spec.name:
        body += pb_field_bytes(17, spec.name.encode())
    return pb_field_bytes(19, body)


def build_program_delete_protobuf(slot):
    """Clear a slot to empty: #19 { #1 slot, #2 {} } (programTypeNotSet, no #8/#9)."""
    return pb_field_bytes(19, pb_field_varint(1, slot) + pb_field_bytes(2, b""))


# ── multi-frame RX reassembly (mirrored in HA connection.py) ─────────────────

def _count_rx_blocks(raw_frames):
    """Number of 16-byte CTR blocks a burst of frames consumes (the amount the RX
    counter advances across them)."""
    n = 0
    for raw in raw_frames:
        parsed = parse_ble_frame(raw)
        if parsed is not None:
            n += (parsed[0] + 15) // 16 or 1
    return n


def _dedup_consecutive(frames):
    """Drop a byte-identical re-delivery of the previous frame (a proxy dup that
    would otherwise advance rx_ctr and desync the stream)."""
    out = []
    for f in frames:
        if not out or f != out[-1]:
            out.append(f)
    return out


def _split_inner_messages(stream):
    """Scan a decrypted byte stream for every `aa775a0f`-headed inner message.

    The device packs back-to-back messages contiguously (NOT block-padded), so
    one outer frame is not necessarily one message and a message may span frames.
    Returns [{offset, total, crc_ok, protobuf}].
    """
    msgs = []
    i = 0
    while i + 6 <= len(stream):
        hdr = stream.find(MSG_HEADER, i)
        if hdr < 0 or hdr + 6 > len(stream):
            break
        payload_len = stream[hdr + 4]
        total = payload_len + 6
        if payload_len < 2 or hdr + total > len(stream):
            break  # incomplete trailing message
        inner = decode_inner(stream[hdr:hdr + total])
        msgs.append({
            "offset": hdr,
            "total": total,
            "crc_ok": bool(inner and inner["crc_ok"]),
            "protobuf": inner["protobuf"] if inner else None,
        })
        i = hdr + total
    return msgs


def reassemble_rx(key, iv, base_counter, raw_frames, sweep=32):
    """Rebuild the per-direction plaintext stream from a burst of 0x11 frames and
    split it into inner messages.

    A long inner message streams as consecutive 16-byte CTR blocks, each in its
    own outer frame, the RX counter advancing per block across all frames. We
    decrypt frame-by-frame at a block-aligned running counter, concatenate, then
    scan for headers. The base counter is swept (a prior push may have consumed
    some) and the base yielding the most CRC-valid messages wins. Returns
    (best_base, stream, messages).
    """
    cts = []
    for raw in raw_frames:
        parsed = parse_ble_frame(raw)
        if parsed is not None:
            cts.append(parsed[1])
    if not cts:
        return base_counter, b"", []

    def decode_at(base):
        parts, blocks = [], 0
        for ct in cts:
            pt, _ = aes_encrypt(key, iv, (base + blocks) % 0x100000000, ct)
            parts.append(pt)
            blocks += (len(ct) + 15) // 16 or 1
        stream = b"".join(parts)
        msgs = _split_inner_messages(stream)
        return stream, msgs, sum(1 for m in msgs if m["crc_ok"])

    best = None
    for d in range(sweep):
        for base in ((base_counter + d) % 0x100000000,
                     (base_counter - d) % 0x100000000):
            stream, msgs, score = decode_at(base)
            if best is None or score > best[0]:
                best = (score, base, stream, msgs)
            if d == 0:
                break
    _score, base, stream, msgs = best
    return base, stream, msgs


# ── decode ──────────────────────────────────────────────────────────────────

def parse_program_body(pb):
    """Decode a #19 WateringProgram body -> ProgramSchedule (or None if malformed)."""
    f = pb_parse(pb)
    if f is None:
        return None
    slot = _pb_field(f, 1)
    notset = _pb_field(f, 2)
    empty = isinstance(notset, (bytes, bytearray))  # #2 programTypeNotSet present

    day_mode = weekday_mask = interval_days = interval_anchor = None
    wk = _pb_field(f, _DM_WEEKDAYS)
    if isinstance(wk, (bytes, bytearray)):
        day_mode, weekday_mask = "weekdays", _pb_field(pb_parse(wk), 1)
    iv = _pb_field(f, _DM_INTERVAL)
    if isinstance(iv, (bytes, bytearray)):
        ivf = pb_parse(iv)
        day_mode, interval_days = "interval", _pb_field(ivf, 1)
        anchor = _pb_field(ivf, 2)
        if isinstance(anchor, (bytes, bytearray)):
            interval_anchor = anchor.decode(errors="replace")
    if _pb_field(f, _DM_ODD) is not None:
        day_mode = "odd"
    if _pb_field(f, _DM_EVEN) is not None:
        day_mode = "even"
    if _pb_field(f, _DM_RUNONCE) is not None:
        day_mode = "once"

    # #8 start times: bare varint on our firmware, but tolerate the echo quirk
    # where a read re-emits them nested as #8 { #45 = value }.
    start_mins = []
    for num, wire, v in f:
        if num != 8:
            continue
        if wire == 0:
            start_mins.append(v)
        elif isinstance(v, (bytes, bytearray)):
            m = _pb_field(pb_parse(v), 45)
            if m is not None:
                start_mins.append(m)

    zones = []
    for num, _wire, v in f:
        if num == 9 and isinstance(v, (bytes, bytearray)):
            zf = pb_parse(v)
            zones.append((_pb_field(zf, 1), _pb_field(zf, 2)))

    name = _pb_field(f, 17)
    if isinstance(name, (bytes, bytearray)):
        name = name.decode(errors="replace")
    return ProgramSchedule(
        slot=slot, empty=empty, day_mode=day_mode, weekday_mask=weekday_mask,
        interval_days=interval_days, interval_anchor=interval_anchor,
        start_mins=tuple(start_mins), zones=tuple(zones), name=name,
        budget=_pb_field(f, 10),
    )


def parse_sync_dump(msgs):
    """From a reassembled #10 dump, return (programs {slot:ProgramSchedule},
    active_mask int|None, status DeviceStatus|None). `enabled` is filled on each
    program from the #20 bitmask."""
    programs, active_mask, status = {}, None, None
    for m in msgs:
        pb = m.get("protobuf")
        if not pb:
            continue
        top = pb_parse(pb)
        if top is None:
            continue
        p19 = _pb_field(top, 19)
        if isinstance(p19, (bytes, bytearray)):
            sch = parse_program_body(p19)
            if sch and sch.slot is not None:
                programs[sch.slot] = sch
        p20 = _pb_field(top, 20)
        if isinstance(p20, (bytes, bytearray)):
            active_mask = _pb_field(pb_parse(p20), 1)
        if isinstance(_pb_field(top, 16), (bytes, bytearray)):
            status = extract_status(pb)
    if active_mask is not None:
        for sid, sch in list(programs.items()):
            programs[sid] = sch._replace(enabled=bool(active_mask & (1 << (sid - 1))))
    return programs, active_mask, status


def _first_status(msgs):
    """Return the first DeviceStatus from a reassembled burst that carries #16
    (run-state or controller-mode), else None."""
    for m in msgs:
        pb = m.get("protobuf")
        if not pb:
            continue
        st = extract_status(pb)
        if st.run_state is not None or st.controller_mode is not None:
            return st
    return None


# ── formatting ───────────────────────────────────────────────────────────────

def _flags_to_slots(flags):
    """Bitmask -> 'A', 'A+C', etc. (A=bit0)."""
    if not flags:
        return "-"
    return "+".join(SLOT_LETTERS.get(b + 1, f"?{b}") for b in range(6) if flags & (1 << b))


def _fmt_weekdays(mask):
    if mask == 0x7F:
        return "every day"
    return ",".join(WEEKDAY_NAMES[b] for b in range(7) if mask & (1 << b)) or "(none)"


def _fmt_schedule(sch):
    """One-line human summary of a decoded ProgramSchedule."""
    if sch.empty:
        return "empty"
    if sch.day_mode == "weekdays":
        days = _fmt_weekdays(sch.weekday_mask or 0)
    elif sch.day_mode == "interval":
        days = f"every {sch.interval_days}d"
        if sch.interval_anchor:
            days += f" from {sch.interval_anchor[:10]}"
    elif sch.day_mode in ("odd", "even", "once"):
        days = sch.day_mode
    else:
        days = "?"
    starts = ",".join(f"{m // 60:02d}:{m % 60:02d}" for m in sch.start_mins) or "-"
    zones = ",".join(f"z{sid + 1}:{sec}s" for sid, sec in sch.zones) or "-"
    en = "" if sch.enabled is None else (" [enabled]" if sch.enabled else " [disabled]")
    name = f'"{sch.name}" ' if sch.name else ""
    return f"{name}{days} @ {starts} zones {zones}{en}"


# ─── Setup Wizard ────────────────────────────────────────────────────────

def cmd_setup(args):
    print(FIRMWARE_WARNING)
    print("B-Hyve Controller Setup")
    print("=" * 40)
    print()

    email = args.email
    password = args.password

    if not email:
        print("This wizard extracts your device's encryption key from the")
        print("Orbit B-Hyve cloud. You need the email and password from the")
        print("B-Hyve app (created when you first paired your sprinkler).")
        print()
        email = input("Orbit B-Hyve email: ").strip()

    if not password:
        import getpass
        password = getpass.getpass("Orbit B-Hyve password: ")

    # Login
    print(f"\nLogging in as {email}...")
    try:
        token, user_id = orbit_login(email, password)
        print(f"  Authenticated! (user_id: {user_id})")
    except Exception as e:
        print(f"  Login failed: {e}")
        print("  Check your email/password. You can reset it at:")
        print("  https://techsupport.orbitbhyve.com")
        sys.exit(1)

    # Get devices
    print("\nFetching devices...")
    try:
        devices = orbit_get_devices(token)
    except Exception as e:
        print(f"  Failed to fetch devices: {e}")
        sys.exit(1)

    if not devices:
        print("  No devices found on this account.")
        sys.exit(1)

    print(f"  Found {len(devices)} device(s):\n")

    config = {"devices": []}

    for i, dev in enumerate(devices):
        mac = dev.get("mac_address", "unknown")
        name = dev.get("name", "Unknown")
        fw = dev.get("firmware_version", "?")
        hw = dev.get("hardware_version", "?")
        stations = dev.get("num_stations", "?")
        topology_id = dev.get("network_topology_id") or dev.get("mesh_id", "")
        device_id = dev.get("id", "")

        print(f"  [{i+1}] {name}")
        print(f"      MAC: {mac}")
        print(f"      Firmware: {fw}  Hardware: {hw}")
        print(f"      Stations: {stations}")

        # Get network key
        if topology_id:
            try:
                network_key_b64 = orbit_get_network_key(token, topology_id)
                import base64
                network_key_hex = base64.b64decode(network_key_b64).hex()
                print(f"      Network Key: {network_key_b64}")
                print(f"      Key (hex): {network_key_hex}")

                # Format MAC with colons
                mac_formatted = ":".join(mac[j:j+2].upper() for j in range(0, len(mac), 2))

                config["devices"].append({
                    "name": name,
                    "mac": mac_formatted,
                    "network_key": network_key_hex,
                    "network_key_b64": network_key_b64,
                    "stations": stations,
                    "firmware": fw,
                    "device_id": device_id,
                })
                print(f"      Status: Ready!")
            except Exception as e:
                print(f"      Failed to get network key: {e}")
        else:
            print(f"      No network topology — device may need pairing first")
        print()

    if config["devices"]:
        save_config(config)
        print("\nSetup complete! You can now control your sprinkler:")
        dev = config["devices"][0]
        print(f"\n  python3 bhyve.py on 1 300    # Zone 1 for 5 minutes")
        print(f"  python3 bhyve.py off          # Stop watering")
        if len(config["devices"]) > 1:
            print(f"\n  Use --device N to select a specific device (1-{len(config['devices'])})")

    print(FIRMWARE_WARNING)


# ─── BLE Control ─────────────────────────────────────────────────────────

class _RxCollector:
    """Collects RX notifications on 6c73 and decodes them with the RX counter.

    Notifications can arrive before the session is derived, so raw frames are kept
    and decoded once `arm()` supplies the key/IV/RX-counter. `event` fires on the
    first CRC-valid decode so callers can use a bounded `wait_for` instead of a
    fixed sleep.
    """

    def __init__(self):
        self.key = self.iv = self.rx_counter = None
        self.raw = []        # every raw notification (bytes)
        self.decoded = []    # CRC-valid inner messages (decode_inner dicts)
        self.event = asyncio.Event()

    def arm(self, key, iv, rx_counter):
        self.key, self.iv, self.rx_counter = key, iv, rx_counter
        for raw in self.raw:          # decode anything buffered pre-arm
            self._decode(raw)

    def handle(self, _sender, data):
        raw = bytes(data)
        self.raw.append(raw)
        if self.rx_counter is not None:
            self._decode(raw)

    def _decode(self, raw):
        parsed = parse_ble_frame(raw)
        if parsed is None:
            return
        _, ct, _ = parsed
        _c, _pt, inner = decrypt_frame(self.key, self.iv, ct, self.rx_counter)
        if inner and inner["crc_ok"]:
            self.decoded.append(inner)
            self.event.set()

    def merged_status(self):
        """Combine telemetry across decoded frames (types carry different fields)."""
        run_state = is_watering = battery_mv = device_clock = None
        active_station = seconds_remaining = flow_total = None
        rd_minutes = rd_expiry = rd_active = None
        controller_mode = next_start_flags = next_start_epoch = None
        for inner in self.decoded:
            st = extract_status(inner["protobuf"])
            run_state = st.run_state if st.run_state is not None else run_state
            is_watering = st.is_watering if st.is_watering is not None else is_watering
            battery_mv = st.battery_mv if st.battery_mv is not None else battery_mv
            device_clock = st.device_clock if st.device_clock is not None else device_clock
            active_station = st.active_station if st.active_station is not None else active_station
            seconds_remaining = (
                st.seconds_remaining if st.seconds_remaining is not None else seconds_remaining
            )
            flow_total = st.flow_total if st.flow_total is not None else flow_total
            rd_minutes = st.rain_delay_minutes if st.rain_delay_minutes is not None else rd_minutes
            rd_expiry = st.rain_delay_expiry if st.rain_delay_expiry is not None else rd_expiry
            rd_active = st.rain_delay_active if st.rain_delay_active is not None else rd_active
            controller_mode = st.controller_mode if st.controller_mode is not None else controller_mode
            next_start_flags = st.next_start_flags if st.next_start_flags is not None else next_start_flags
            next_start_epoch = st.next_start_epoch if st.next_start_epoch is not None else next_start_epoch
        return DeviceStatus(
            run_state, is_watering, battery_mv, device_clock,
            active_station, seconds_remaining, flow_total,
            rd_minutes, rd_expiry, rd_active,
            controller_mode, next_start_flags, next_start_epoch,
        )


_MODE_NAMES = {0: "off", 1: "auto", 2: "manual"}


def _format_status(st):
    parts = []
    if st.is_watering is not None:
        parts.append("watering" if st.is_watering else "idle")
    if st.active_station is not None:          # #16.#2.#2.#3.#1 (0-indexed)
        parts.append(f"zone {st.active_station + 1}")
    if st.seconds_remaining is not None:       # #16.#6.#5
        parts.append(f"{st.seconds_remaining}s left")
    if st.run_state is not None:
        parts.append(f"run_state={st.run_state}")
    if st.controller_mode is not None:         # #16.#2.#1 (0=off, 1=auto, 2=manual)
        parts.append(f"mode={_MODE_NAMES.get(st.controller_mode, st.controller_mode)}")
    if st.next_start_flags:                    # #16.#9/#10: next scheduled program run
        when = ""
        if st.next_start_epoch:
            ns = datetime.fromtimestamp(st.next_start_epoch, tz=timezone.utc).astimezone()
            when = f" @ {ns:%Y-%m-%d %H:%M}"
        parts.append(f"next {_flags_to_slots(st.next_start_flags)}{when}")
    if st.battery_mv is not None:
        parts.append(f"battery {st.battery_mv} mV")
    if st.device_clock is not None:
        parts.append(f"clock {st.device_clock}")
    return ", ".join(parts) if parts else "no decodable telemetry"


def _format_rain_delay(st):
    """Human-readable rain-delay summary from a DeviceStatus (#16.#13)."""
    if st.rain_delay_active is None and st.rain_delay_minutes is None:
        if st.run_state == 3:        # run-state says rain-delay, block not decoded
            return "active (duration unknown)"
        return "unknown (no status decoded)"
    if not st.rain_delay_active or not st.rain_delay_minutes:
        return "off"
    parts = [f"{st.rain_delay_minutes} min ({st.rain_delay_minutes / 60:g} h)"]
    if st.rain_delay_expiry:
        ends = datetime.fromtimestamp(st.rain_delay_expiry, tz=timezone.utc).astimezone()
        parts.append(f"ends {ends:%Y-%m-%d %H:%M}")
    return ", ".join(parts)


async def _await_rx(collector, first_timeout, drain=1.5):
    """Wait (bounded) for the first decoded RX frame, then drain the burst briefly.

    The first frame after a command is a small ack (clock only); the richer #16
    state push (run-state + battery) follows a beat later, and battery can arrive
    as a separate #46 frame — so drain a moment after the first to merge them.
    """
    try:
        await asyncio.wait_for(collector.event.wait(), timeout=first_timeout)
    except asyncio.TimeoutError:
        return
    await asyncio.sleep(drain)


async def _connect(client):
    """Shared connect step: BlueZ-only MTU acquire (guarded), print MTU."""
    # _acquire_mtu() exists only on the BlueZ (Linux) backend; Windows
    # negotiates MTU automatically, so call it only if present.
    acquire_mtu = getattr(client._backend, "_acquire_mtu", None)
    if acquire_mtu is not None:
        await acquire_mtu()
    print(f"Connected (MTU={client.mtu_size})")


async def _init_session(client, key, collector):
    """Subscribe to RX, run the AES session init, arm the collector, return iv/counter."""
    await client.start_notify(READ_CHAR, collector.handle)
    init_tx = bytearray(os.urandom(20))
    init_tx[11] = 0x00
    init_tx = bytes(init_tx)
    await client.write_gatt_char(AES_CHAR, init_tx)
    rx = await client.read_gatt_char(AES_CHAR)
    iv, counter, rx_counter = derive_session(init_tx, rx)
    collector.arm(key, iv, rx_counter)
    print("Session established")
    return iv, counter


async def ble_command(mac, network_key, command, zones=None, duration=600):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(network_key)
    print(f"Scanning for {mac}...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        print(f"{mac} not found — check it's powered and in BLE range "
              "(the scan can miss it transiently; just retry).")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        collector = _RxCollector()
        iv, counter = await _init_session(client, key, collector)

        async def send_pb(protobuf):
            nonlocal counter
            msg = build_message(protobuf)
            ct, counter = aes_encrypt(key, iv, counter, msg)
            await client.write_gatt_char(
                WRITE_CHAR, build_ble_frame(ct, compute_trailer(msg)), response=False
            )

        if command == "on":
            for zone in zones:
                await send_pb(build_start_protobuf(zone - 1, duration))
                mins, secs = duration // 60, duration % 60
                time_str = f"{mins}m{secs}s" if secs else f"{mins}m"
                print(f"Zone {zone} ON for {time_str} — sent!")

        elif command == "off":
            await send_pb(build_stop_protobuf())
            print("All zones STOPPED — sent!")

        # Wait (bounded) for the device's confirmation, then decode it — fast
        # devices return immediately, a silent one exits on the timeout.
        await _await_rx(collector, first_timeout=4.0)

        # A stop is answered with only a bare #30 ack (no #16 status), so the
        # first burst can't confirm the real run-state; solicit a full #16 with
        # #15{}. For a start the #16 usually rides the reply, so only poll if it
        # didn't. This mirrors the HA confirm path (protobuf.py).
        need_poll = command == "off" or collector.merged_status().is_watering is None
        if need_poll:
            collector.event.clear()
            await send_pb(build_request_status_protobuf())
            await _await_rx(collector, first_timeout=4.0)

        if collector.decoded:
            print(f"Confirmed: {_format_status(collector.merged_status())}")
        elif collector.raw:
            print(f"Device responded ({len(collector.raw)} notification(s)) but none decoded.")
        else:
            print("No confirmation notification received.")
        await client.stop_notify(READ_CHAR)
        print("Done.")


async def ble_status(mac, network_key):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(network_key)
    print(f"Scanning for {mac}...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        print(f"{mac} not found — check it's powered and in BLE range "
              "(the scan can miss it transiently; just retry).")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        collector = _RxCollector()
        iv, counter = await _init_session(client, key, collector)

        # Solicit the status rather than waiting on the unsolicited connect-time
        # push: the device suppresses that push while "active" (watering or a
        # rain delay active), so a passive read comes up empty exactly when state
        # matters most. #15{} elicits a full #16 burst reliably in every state.
        msg = build_message(build_request_status_protobuf())
        ct, _ = aes_encrypt(key, iv, counter, msg)
        await client.write_gatt_char(
            WRITE_CHAR, build_ble_frame(ct, compute_trailer(msg)), response=False
        )
        await _await_rx(collector, first_timeout=6.0)
        await client.stop_notify(READ_CHAR)

        if collector.decoded:
            print(f"Status: {_format_status(collector.merged_status())}")
        elif collector.raw:
            print(f"Received {len(collector.raw)} notification(s) but none decoded.")
        else:
            # We connected fine (MTU printed above) and solicited a status, so
            # this isn't range/sleep — the device simply didn't answer this time.
            print("Connected and requested status, but no decodable reply "
                  "(retry; the link can drop a burst transiently).")


async def ble_rain_delay(mac, network_key, action, hours=None):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(network_key)
    print(f"Scanning for {mac}...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        print(f"{mac} not found — check it's powered and in BLE range "
              "(the scan can miss it transiently; just retry).")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        collector = _RxCollector()
        iv, counter = await _init_session(client, key, collector)

        async def send_pb(protobuf):
            nonlocal counter
            msg = build_message(protobuf)
            ct, counter = aes_encrypt(key, iv, counter, msg)
            await client.write_gatt_char(
                WRITE_CHAR, build_ble_frame(ct, compute_trailer(msg)), response=False
            )

        # Don't depend on the unsolicited connect-time push: the device
        # suppresses it while "active" (watering or rain-delay active). Solicit
        # a #16 status burst with #15{} — reliable in every state. It carries the
        # device clock (for a set's expiry) and the current rain-delay block.
        await send_pb(build_request_status_protobuf())
        await _await_rx(collector, first_timeout=6.0)
        st = collector.merged_status()

        if action == "get":
            print(f"Rain delay: {_format_rain_delay(st)}")
            await client.stop_notify(READ_CHAR)
            return

        if action == "set":
            minutes = int(round(hours * 60))
            clock = st.device_clock or int(time.time())
            protobuf = build_rain_delay_protobuf(minutes, clock + minutes * 60)
            label = f"set {hours:g}h ({minutes} min)"
        else:  # clear
            protobuf = build_rain_delay_protobuf(0)
            label = "clear"

        # Reset so merged_status reflects only the post-command echo, not the
        # status burst we already consumed above.
        collector.decoded.clear()
        collector.event.clear()
        await send_pb(protobuf)
        print(f"Rain delay {label} — sent!")

        await _await_rx(collector, first_timeout=4.0)
        if collector.decoded:
            st2 = collector.merged_status()
            extra = f" [run_state={st2.run_state}]" if st2.run_state is not None else ""
            print(f"Confirmed: {_format_rain_delay(st2)}{extra}")
        elif collector.raw:
            print(f"Device responded ({len(collector.raw)} notification(s)) but none decoded.")
        else:
            print("No confirmation notification received.")
        await client.stop_notify(READ_CHAR)
        print("Done.")


# ─── Watering-program transport (multi-frame RX; running RX counter) ─────────

class _BurstCollector:
    """Keeps every raw RX frame and fires an event on each. Unlike _RxCollector
    (which decodes each frame independently), program reads need the raw frames so
    reassemble_rx can rebuild a multi-frame stream."""

    def __init__(self):
        self.raw = []
        self.event = asyncio.Event()

    def handle(self, _sender, data):
        self.raw.append(bytes(data))
        self.event.set()


async def _drain_burst(collector, window, quiet=1.6):
    """Collect frames for up to `window` s, returning `quiet` s after the last one."""
    deadline = time.time() + window
    last = time.time()
    while time.time() < deadline:
        collector.event.clear()
        try:
            await asyncio.wait_for(collector.event.wait(), timeout=quiet)
            last = time.time()
        except asyncio.TimeoutError:
            if time.time() - last >= quiet:
                break


class _ProgramSession:
    """A connected BLE session with running RX-counter tracking, so multiple
    request/replies on ONE connection each reassemble correctly (the RX counter
    advances by block-count across every reply). Mirrors the reference in
    scripts/exploration/probe_programs.py; HA's connection.py mirrors this."""

    def __init__(self, client, collector, key, iv, tx_ctr, rx_ctr):
        self.client, self.collector = client, collector
        self.key, self.iv = key, iv
        self.tx_ctr, self.rx_ctr = tx_ctr, rx_ctr

    async def send(self, protobuf):
        msg = build_message(protobuf)
        ct, self.tx_ctr = aes_encrypt(self.key, self.iv, self.tx_ctr, msg)
        await self.client.write_gatt_char(
            WRITE_CHAR, build_ble_frame(ct, compute_trailer(msg)), response=False
        )

    async def request(self, protobuf, window=4.0):
        """Send a request, drain the reply burst, reassemble, advance rx_ctr."""
        n0 = len(self.collector.raw)
        self.collector.event.clear()
        await self.send(protobuf)
        await _drain_burst(self.collector, window)
        new = _dedup_consecutive(self.collector.raw[n0:])
        if not new:
            return []
        base, _stream, msgs = reassemble_rx(self.key, self.iv, self.rx_ctr, new)
        self.rx_ctr = (base + _count_rx_blocks(new)) % 0x100000000
        return msgs


async def _open_program_session(client, key):
    """Handshake and return a _ProgramSession armed with a raw-frame burst collector."""
    collector = _BurstCollector()
    await client.start_notify(READ_CHAR, collector.handle)
    init_tx = bytearray(os.urandom(20))
    init_tx[11] = 0x00
    init_tx = bytes(init_tx)
    await client.write_gatt_char(AES_CHAR, init_tx)
    rx = await client.read_gatt_char(AES_CHAR)
    iv, tx_ctr, rx_ctr = derive_session(init_tx, rx)
    print("Session established")
    return _ProgramSession(client, collector, key, iv, tx_ctr, rx_ctr)


async def _program_set(sess, spec):
    """Store a program and, if enabled, drive the 3-write run handshake."""
    letter = SLOT_LETTERS.get(spec.slot, str(spec.slot))
    programs, mask, _ = parse_sync_dump(await sess.request(build_sync_request_protobuf(), window=6.0))
    mask = mask or 0

    pb = build_program_protobuf(spec)
    print(f"  STORE program {letter}: {pb.hex()}")
    await sess.request(pb, window=4.0)

    programs, _, _ = parse_sync_dump(await sess.request(build_sync_request_protobuf(), window=6.0))
    if spec.slot in programs and not programs[spec.slot].empty:
        print(f"  readback: {_fmt_schedule(programs[spec.slot])}")
    else:
        print(f"  ⚠ slot {letter} not found in read-back — the store may not have taken")

    bit = 1 << (spec.slot - 1)
    if not spec.enabled:
        # Store only; clear this slot's enable bit but leave the controller in
        # autoMode (never drop it to offMode). Other slots keep their state.
        await sess.request(build_set_active_programs_protobuf(mask & ~bit))
        await sess.request(build_set_timer_mode_protobuf(1))  # autoMode
        print(f"  stored {letter} (disabled). Enable it with `program set ... --enable`.")
        return

    newmask = mask | bit
    # The device computes a next-start only when store+enable arrive while already
    # in autoMode, so: enable -> autoMode -> re-send store+enable, then confirm.
    await sess.request(build_set_active_programs_protobuf(newmask))
    await sess.request(build_set_timer_mode_protobuf(1))  # autoMode / "Enable Watering"
    await sess.request(pb, window=4.0)
    await sess.request(build_set_active_programs_protobuf(newmask))

    conf = _first_status(await sess.request(build_request_status_protobuf(), window=5.0))
    if conf and conf.next_start_flags:
        when = ""
        if conf.next_start_epoch:
            ns = datetime.fromtimestamp(conf.next_start_epoch, tz=timezone.utc).astimezone()
            out = (conf.next_start_epoch - conf.device_clock) if conf.device_clock else None
            when = f" at {ns:%Y-%m-%d %H:%M}" + (f" (~{out}s out)" if out else "")
        print(f"  ✅ enabled {letter}; next start = {_flags_to_slots(conf.next_start_flags)}{when}")
    else:
        print(f"  ⚠ enabled {letter} but the device did not report a next-start "
              "(check the schedule/day-mode)")


async def ble_program(mac, network_key, action, spec=None, slot=None):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(network_key)
    print(f"Scanning for {mac}...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        print(f"{mac} not found — check it's powered and in BLE range "
              "(the scan can miss it transiently; just retry).")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        sess = await _open_program_session(client, key)
        try:
            if action in ("list", "get"):
                msgs = await sess.request(build_sync_request_protobuf(), window=6.0)
                programs, mask, status = parse_sync_dump(msgs)
                if not programs:
                    print("No programs decoded (retry; the sync burst can drop).")
                slots = [slot] if slot else sorted(programs)
                for sid in slots:
                    sch = programs.get(sid)
                    letter = SLOT_LETTERS.get(sid, str(sid))
                    if sch is None:
                        print(f"  {letter}: (not returned)")
                    else:
                        print(f"  {letter}: {_fmt_schedule(sch)}")
                if status and status.next_start_flags:
                    print(f"  next run: {_flags_to_slots(status.next_start_flags)}")

            elif action == "delete":
                letter = SLOT_LETTERS.get(slot, str(slot))
                print(f"  deleting slot {letter} ...")
                # drop its enable bit first so an enabled slot isn't left dangling
                _, mask, _ = parse_sync_dump(await sess.request(build_sync_request_protobuf(), window=6.0))
                await sess.request(build_set_active_programs_protobuf((mask or 0) & ~(1 << (slot - 1))))
                await sess.request(build_program_delete_protobuf(slot))
                await sess.request(build_set_timer_mode_protobuf(1))  # keep controller in autoMode
                programs, _, _ = parse_sync_dump(await sess.request(build_sync_request_protobuf(), window=6.0))
                sch = programs.get(slot)
                if sch is None or sch.empty:
                    print(f"  ✅ slot {letter} cleared")
                else:
                    print(f"  ⚠ slot {letter} still present: {_fmt_schedule(sch)}")

            elif action == "set":
                await _program_set(sess, spec)
        finally:
            await client.stop_notify(READ_CHAR)
        print("Done.")


async def ble_set_controller_mode(mac, network_key, mode):
    """Set the device-global controller mode: 1=auto ("Enable Watering"), 0=off."""
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(network_key)
    name = _MODE_NAMES.get(mode, str(mode))
    print(f"Scanning for {mac}...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        print(f"{mac} not found — check it's powered and in BLE range "
              "(the scan can miss it transiently; just retry).")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        sess = await _open_program_session(client, key)
        try:
            before = _first_status(await sess.request(build_request_status_protobuf(), window=5.0))
            await sess.request(build_set_timer_mode_protobuf(mode))
            after = _first_status(await sess.request(build_request_status_protobuf(), window=5.0))
            b = _MODE_NAMES.get(before.controller_mode) if before else "?"
            a = _MODE_NAMES.get(after.controller_mode) if after else "?"
            print(f"Controller mode: {b} -> {a} (requested {name})")
        finally:
            await client.stop_notify(READ_CHAR)
        print("Done.")


async def ble_flow(mac, network_key, seconds=8):
    from bleak import BleakClient, BleakScanner

    key = bytes.fromhex(network_key)
    print(f"Scanning for {mac}...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        print(f"{mac} not found — check it's powered and in BLE range "
              "(the scan can miss it transiently; just retry).")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        collector = _RxCollector()
        iv, counter = await _init_session(client, key, collector)

        async def send_pb(protobuf):
            nonlocal counter
            msg = build_message(protobuf)
            ct, counter = aes_encrypt(key, iv, counter, msg)
            await client.write_gatt_char(
                WRITE_CHAR, build_ble_frame(ct, compute_trailer(msg)), response=False
            )

        # Subscribe (#57), then collect the streamed #59 frames for `seconds`.
        # A single subscribe yields only a short burst, so re-send each loop to
        # keep frames coming across the window. This is the XD-vs-Gen2 probe: the
        # Gen2 answers with #59; if the XD sends none, it has no flow path (vs.
        # the app merely not offering a flow screen for that model).
        print(f"Subscribing to flow (#57) and listening for {seconds}s...")
        print("(#59.#3 is a CUMULATIVE per-run counter, not a rate — the rate is its slope.)")
        seen = 0
        samples = []  # (monotonic_time, cumulative_counter)
        deadline = asyncio.get_event_loop().time() + seconds
        while asyncio.get_event_loop().time() < deadline:
            collector.event.clear()
            await send_pb(build_flow_subscribe_protobuf(1000))
            await _await_rx(collector, first_timeout=2.0, drain=0.3)
            for inner in collector.decoded[seen:]:
                st = extract_status(inner["protobuf"])
                if st.flow_total is not None:
                    now = asyncio.get_event_loop().time()
                    delta = st.flow_total - samples[-1][1] if samples else 0
                    samples.append((now, st.flow_total))
                    print(f"  #59  total={st.flow_total:<6} (+{delta})")
            seen = len(collector.decoded)
        await client.stop_notify(READ_CHAR)

        if len(samples) >= 2:
            dt = samples[-1][0] - samples[0][0]
            dtotal = samples[-1][1] - samples[0][1]
            rate = dtotal / dt if dt > 0 else 0
            gpm = rate * 60 / FLOW_COUNTS_PER_GALLON
            gal = dtotal / FLOW_COUNTS_PER_GALLON
            print(f"Flow window: +{dtotal} counts over {dt:.1f}s = {rate:.1f} counts/s")
            print(f"  ÷{FLOW_COUNTS_PER_GALLON} counts/gal (measured): "
                  f"~{gpm:.2f} gpm, ~{gal:.3f} gal this window")
            print("  → to re-calibrate: divide a window's counts by the gallons you "
                  "measured over it, and update FLOW_COUNTS_PER_GALLON.")
        elif samples:
            print(f"Flow: 1 #59 frame (total={samples[0][1]}); need ≥2 frames for a rate.")
        else:
            print("No #59 flow frames received — this device has no flow-sensor "
                  "path (expected for the XD; the flow screen is Gen2-only).")
        print("Done.")


def cmd_control(args):
    config = load_config()

    # Get device config
    if not config.get("devices"):
        print("No devices configured. Run setup first:")
        print("  python3 bhyve.py setup")
        sys.exit(1)

    dev_idx = (args.device or 1) - 1
    if dev_idx >= len(config["devices"]):
        print(f"Device {dev_idx+1} not found. You have {len(config['devices'])} device(s).")
        sys.exit(1)

    dev = config["devices"][dev_idx]
    mac = args.mac or dev["mac"]
    network_key = dev["network_key"]

    print(f"B-Hyve Controller — {dev['name']}")

    if args.command == "on":
        if not args.zones:
            print("Error: 'on' requires a zone number (1-4)")
            sys.exit(1)
        zones = [int(z.strip()) for z in args.zones.split(",")]
        max_stations = dev.get("stations", 4)
        for z in zones:
            if z < 1 or z > max_stations:
                print(f"Error: Zone {z} out of range (1-{max_stations})")
                sys.exit(1)
        asyncio.run(ble_command(mac, network_key, "on", zones, args.duration))

    elif args.command == "off":
        asyncio.run(ble_command(mac, network_key, "off"))


def cmd_status(args):
    config = load_config()

    if not config.get("devices"):
        print("No devices configured. Run setup first:")
        print("  python3 bhyve.py setup")
        sys.exit(1)

    dev_idx = (args.device or 1) - 1
    if dev_idx < 0 or dev_idx >= len(config["devices"]):
        print(f"Device {dev_idx+1} not found. You have {len(config['devices'])} device(s).")
        sys.exit(1)

    dev = config["devices"][dev_idx]
    mac = args.mac or dev["mac"]
    network_key = dev["network_key"]

    print(f"B-Hyve Controller — {dev['name']}")
    asyncio.run(ble_status(mac, network_key))


def cmd_flow(args):
    config = load_config()

    if not config.get("devices"):
        print("No devices configured. Run setup first:")
        print("  python3 bhyve.py setup")
        sys.exit(1)

    dev_idx = (args.device or 1) - 1
    if dev_idx < 0 or dev_idx >= len(config["devices"]):
        print(f"Device {dev_idx+1} not found. You have {len(config['devices'])} device(s).")
        sys.exit(1)

    dev = config["devices"][dev_idx]
    mac = args.mac or dev["mac"]
    network_key = dev["network_key"]

    print(f"B-Hyve Controller — {dev['name']}")
    asyncio.run(ble_flow(mac, network_key, args.seconds))


def cmd_rain_delay(args):
    config = load_config()

    if not config.get("devices"):
        print("No devices configured. Run setup first:")
        print("  python3 bhyve.py setup")
        sys.exit(1)

    dev_idx = (args.device or 1) - 1
    if dev_idx < 0 or dev_idx >= len(config["devices"]):
        print(f"Device {dev_idx+1} not found. You have {len(config['devices'])} device(s).")
        sys.exit(1)

    if args.rd_action == "set" and args.hours is None:
        print("Error: 'rain-delay set' requires an hours value, e.g. `rain-delay set 24`")
        sys.exit(1)
    if args.rd_action == "set" and args.hours < 0:
        print("Error: hours must be >= 0 (use `rain-delay clear` to turn it off)")
        sys.exit(1)

    dev = config["devices"][dev_idx]
    mac = args.mac or dev["mac"]
    network_key = dev["network_key"]

    print(f"B-Hyve Controller — {dev['name']}")
    asyncio.run(ble_rain_delay(mac, network_key, args.rd_action, args.hours))


def _resolve_device(args):
    """Shared (mac, network_key, name) lookup from $BHYVE_CONFIG + --device/--mac."""
    config = load_config()
    if not config.get("devices"):
        print("No devices configured. Run setup first:\n  python3 bhyve.py setup")
        sys.exit(1)
    dev_idx = (getattr(args, "device", None) or 1) - 1
    if dev_idx < 0 or dev_idx >= len(config["devices"]):
        print(f"Device {dev_idx+1} not found. You have {len(config['devices'])} device(s).")
        sys.exit(1)
    dev = config["devices"][dev_idx]
    return (args.mac or dev["mac"]), dev["network_key"], dev["name"]


def _parse_slot(s):
    s = str(s).strip().upper()
    if s in PROGRAM_SLOTS:
        return PROGRAM_SLOTS[s]
    if s.isdigit() and 1 <= int(s) <= 6:
        return int(s)
    raise SystemExit(f"invalid slot {s!r} — use A-F (or 1-6)")


def _parse_weekdays(s):
    s = s.strip().lower()
    if s in ("all", "daily", "every", "everyday"):
        return 0x7F
    mask = 0
    for tok in s.split(","):
        key = tok.strip()[:3]
        if key not in WEEKDAY_BITS:
            raise SystemExit(f"invalid weekday {tok!r} — use sun,mon,tue,wed,thu,fri,sat or 'all'")
        mask |= 1 << WEEKDAY_BITS[key]
    return mask


def _parse_start_times(s):
    out = []
    for tok in s.split(","):
        tok = tok.strip()
        h, _, m = tok.partition(":")
        try:
            out.append((int(h) * 60 + int(m or 0)) % 1440)
        except ValueError:
            raise SystemExit(f"invalid start time {tok!r} — use HH:MM (e.g. 06:00)")
    return tuple(out)


def _parse_zones(s):
    """'1:300,2:420' -> ((0,300),(1,420)); CLI zones are 1-indexed, wire is 0-indexed."""
    out = []
    for tok in s.split(","):
        tok = tok.strip()
        z, _, sec = tok.partition(":")
        try:
            out.append((int(z) - 1, int(sec)))
        except ValueError:
            raise SystemExit(f"invalid zone spec {tok!r} — use ZONE:SECONDS (e.g. 1:300)")
    return tuple(out)


def _spec_from_args(args):
    modes = [m for m, on in (("weekdays", args.days), ("interval", args.every),
                             ("odd", args.odd), ("even", args.even), ("once", args.once)) if on]
    if len(modes) != 1:
        raise SystemExit("choose exactly one day-mode: --days / --every / --odd / --even / --once")
    day_mode = modes[0]
    weekday_mask = _parse_weekdays(args.days) if day_mode == "weekdays" else None
    interval_anchor = None
    if day_mode == "interval":
        interval_anchor = args.anchor or (
            datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        )
    return ProgramSpec(
        slot=_parse_slot(args.slot),
        day_mode=day_mode,
        weekday_mask=weekday_mask,
        interval_days=args.every,
        interval_anchor=interval_anchor,
        start_mins=_parse_start_times(args.start),
        zones=_parse_zones(args.zones),
        name=args.name or "",
        budget=args.budget,
        enabled=args.enable,
    )


def cmd_program(args):
    mac, network_key, name = _resolve_device(args)
    print(f"B-Hyve Controller — {name}")
    if args.prog_action in (None, "list"):
        asyncio.run(ble_program(mac, network_key, "list"))
    elif args.prog_action == "get":
        asyncio.run(ble_program(mac, network_key, "get", slot=_parse_slot(args.slot)))
    elif args.prog_action == "delete":
        asyncio.run(ble_program(mac, network_key, "delete", slot=_parse_slot(args.slot)))
    elif args.prog_action == "set":
        asyncio.run(ble_program(mac, network_key, "set", spec=_spec_from_args(args)))


def cmd_mode(args):
    mac, network_key, name = _resolve_device(args)
    print(f"B-Hyve Controller — {name}")
    mode = 1 if args.mode_action == "enable" else 0
    asyncio.run(ble_set_controller_mode(mac, network_key, mode))


# ─── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Orbit B-Hyve XD Bluetooth Valve Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup (first time):
  %(prog)s setup                         Interactive setup wizard
  %(prog)s setup --email you@email.com   Non-interactive with email

Control:
  %(prog)s on 1 300          Zone 1 on for 5 minutes
  %(prog)s on 1 600          Zone 1 on for 10 minutes (default)
  %(prog)s on 2 60           Zone 2 on for 1 minute
  %(prog)s off               Stop all watering
  %(prog)s status            Read device telemetry (battery, state)
  %(prog)s flow              Read the flow sensor (Gen2; probes the XD too)
  %(prog)s rain-delay get    Read the current rain delay
  %(prog)s rain-delay set 24 Delay watering for 24 hours
  %(prog)s rain-delay clear  Clear the rain delay

Programs (slots A-D):
  %(prog)s program list      List all program slots
  %(prog)s program get A     Show slot A
  %(prog)s program set A --days mon,wed,fri --start 06:00,18:00 --zones 1:300,2:420 --name Front --enable
  %(prog)s program set B --every 3 --start 06:00 --zones 1:600 --name Drip
  %(prog)s program delete A  Clear slot A
  %(prog)s mode enable       Enable automatic watering (autoMode)
  %(prog)s mode disable      Turn the controller off (offMode)

⚠️  Do NOT update your B-Hyve firmware — it may break this tool!
        """,
    )

    sub = parser.add_subparsers(dest="action")

    # Setup
    setup_p = sub.add_parser("setup", help="First-time setup wizard")
    setup_p.add_argument("--email", "-e", help="Orbit B-Hyve account email")
    setup_p.add_argument("--password", "-p", help="Orbit B-Hyve account password")

    # On
    on_p = sub.add_parser("on", help="Turn on a zone")
    on_p.add_argument("zones", help="Zone number (1-4)")
    on_p.add_argument("duration", nargs="?", type=int, default=600,
                       help="Duration in seconds (default: 600)")
    on_p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
    on_p.add_argument("--mac", help="Override MAC address")

    # Off
    off_p = sub.add_parser("off", help="Stop all watering")
    off_p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
    off_p.add_argument("--mac", help="Override MAC address")

    # Status
    status_p = sub.add_parser("status", help="Read device telemetry (battery, state)")
    status_p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
    status_p.add_argument("--mac", help="Override MAC address")

    # Flow (Gen2 flow sensor; also probes whether the XD reports flow)
    flow_p = sub.add_parser("flow", help="Read the flow sensor (#57/#59; Gen2)")
    flow_p.add_argument("seconds", nargs="?", type=int, default=8,
                        help="Seconds to listen for #59 flow frames (default: 8)")
    flow_p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
    flow_p.add_argument("--mac", help="Override MAC address")

    # Rain delay
    rd_p = sub.add_parser("rain-delay", help="Get/set/clear the rain delay")
    rd_p.add_argument("rd_action", choices=["get", "set", "clear"],
                      help="get current delay, set <hours>, or clear it")
    rd_p.add_argument("hours", nargs="?", type=float,
                      help="Hours of delay (for 'set'), e.g. 24")
    rd_p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
    rd_p.add_argument("--mac", help="Override MAC address")

    # Programs (slots A-D)
    def _dev_args(p):
        p.add_argument("--device", "-d", type=int, help="Device number (if multiple)")
        p.add_argument("--mac", help="Override MAC address")

    prog_p = sub.add_parser("program", help="Get/set/delete watering programs (slots A-D)")
    prog_sub = prog_p.add_subparsers(dest="prog_action")
    _dev_args(prog_p)
    pl = prog_sub.add_parser("list", help="List all program slots")
    _dev_args(pl)
    pg = prog_sub.add_parser("get", help="Show one slot")
    pg.add_argument("slot", help="Slot letter A-F")
    _dev_args(pg)
    pdel = prog_sub.add_parser("delete", help="Clear a slot")
    pdel.add_argument("slot", help="Slot letter A-F")
    _dev_args(pdel)
    pset = prog_sub.add_parser("set", help="Create/replace a program in a slot")
    pset.add_argument("slot", help="Slot letter A-F")
    pset.add_argument("--days", help="weekday list, e.g. mon,wed,fri or 'all'")
    pset.add_argument("--every", type=int, help="every N days")
    pset.add_argument("--anchor", help="interval anchor date ISO (default: today)")
    pset.add_argument("--odd", action="store_true", help="odd calendar days")
    pset.add_argument("--even", action="store_true", help="even calendar days")
    pset.add_argument("--once", action="store_true", help="one-time run (unverified on hardware)")
    pset.add_argument("--start", required=True, help="start times HH:MM[,HH:MM]")
    pset.add_argument("--zones", required=True, help="zone:seconds list, e.g. 1:300,2:420")
    pset.add_argument("--name", default="", help="program name")
    pset.add_argument("--budget", type=int, default=100, help="seasonal budget %% (default 100)")
    pset.add_argument("--enable", action="store_true",
                      help="enable + arm the schedule (runs the 3-write handshake)")
    _dev_args(pset)

    # Controller mode
    mode_p = sub.add_parser("mode", help="Enable (auto) or disable (off) automatic watering")
    mode_p.add_argument("mode_action", choices=["enable", "disable"],
                        help="enable = autoMode ('Enable Watering'); disable = offMode")
    _dev_args(mode_p)

    args = parser.parse_args()

    if args.action == "setup":
        cmd_setup(args)
    elif args.action in ("on", "off"):
        args.command = args.action
        cmd_control(args)
    elif args.action == "status":
        cmd_status(args)
    elif args.action == "flow":
        cmd_flow(args)
    elif args.action == "rain-delay":
        cmd_rain_delay(args)
    elif args.action == "program":
        cmd_program(args)
    elif args.action == "mode":
        cmd_mode(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
