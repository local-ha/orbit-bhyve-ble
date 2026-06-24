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
RX_F_STATUS_MODE = 1      #   #16.#1: 1=idle, 4=manual running
RX_F_STATUS_BATT = 14     #   #16.#14: battery block { #3 = mV }
RX_F_BATT_MV = 3          #   battery millivolts (in #16.#14 and #46)
RX_F_BATTERY_REPORT = 46  # standalone battery report { #3 = mV }
RX_F_WATERING = 59        # watering status { #1 active flag (0=not watering) }
RX_F_WATERING_ACTIVE = 1


class DeviceStatus(NamedTuple):
    """Decoded device telemetry from an RX notification (absent fields => None)."""
    run_state: int | None        # #16.#1: 1=idle, 4=running
    is_watering: bool | None     # derived from #16.#1 / #59.#1
    battery_mv: int | None       # #16.#14.#3 or standalone #46.#3
    device_clock: int | None = None  # #7 Unix epoch seconds


def _pb_field(fields, num):
    """Return the value of the first field `num` in a parsed field list, or None."""
    for field, _wire, val in fields or ():
        if field == num:
            return val
    return None


def _pb_subfield(fields, outer, inner):
    """Return field `inner` inside the length-delimited field `outer`, or None."""
    blob = _pb_field(fields, outer)
    if not isinstance(blob, (bytes, bytearray)):
        return None
    return _pb_field(pb_parse(blob), inner)


def extract_status(protobuf):
    """Extract HA-relevant telemetry from a decoded RX protobuf -> DeviceStatus."""
    top = pb_parse(protobuf)
    if top is None:
        return DeviceStatus(None, None, None)

    clock = _pb_field(top, RX_F_CLOCK)
    run_state = battery_mv = is_watering = None

    status = _pb_field(top, RX_F_STATUS)          # #16 submessage
    if isinstance(status, (bytes, bytearray)):
        sfields = pb_parse(status)
        run_state = _pb_field(sfields, RX_F_STATUS_MODE)
        battery_mv = _pb_subfield(sfields, RX_F_STATUS_BATT, RX_F_BATT_MV)  # #16.#14.#3

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
        device_clock=clock,
    )


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
        for inner in self.decoded:
            st = extract_status(inner["protobuf"])
            run_state = st.run_state if st.run_state is not None else run_state
            is_watering = st.is_watering if st.is_watering is not None else is_watering
            battery_mv = st.battery_mv if st.battery_mv is not None else battery_mv
            device_clock = st.device_clock if st.device_clock is not None else device_clock
        return DeviceStatus(run_state, is_watering, battery_mv, device_clock)


def _format_status(st):
    parts = []
    if st.is_watering is not None:
        parts.append("watering" if st.is_watering else "idle")
    if st.run_state is not None:
        parts.append(f"run_state={st.run_state}")
    if st.battery_mv is not None:
        parts.append(f"battery {st.battery_mv} mV")
    if st.device_clock is not None:
        parts.append(f"clock {st.device_clock}")
    return ", ".join(parts) if parts else "no decodable telemetry"


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
        print(f"{mac} not found — is it awake (press the button) and in range?")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        collector = _RxCollector()
        iv, counter = await _init_session(client, key, collector)

        if command == "on":
            for zone in zones:
                protobuf = build_start_protobuf(zone - 1, duration)
                message = build_message(protobuf)
                ct, counter = aes_encrypt(key, iv, counter, message)
                frame = build_ble_frame(ct, compute_trailer(message))
                await client.write_gatt_char(WRITE_CHAR, frame, response=False)
                mins, secs = duration // 60, duration % 60
                time_str = f"{mins}m{secs}s" if secs else f"{mins}m"
                print(f"Zone {zone} ON for {time_str} — sent!")

        elif command == "off":
            protobuf = build_stop_protobuf()
            message = build_message(protobuf)
            ct, counter = aes_encrypt(key, iv, counter, message)
            frame = build_ble_frame(ct, compute_trailer(message))
            await client.write_gatt_char(WRITE_CHAR, frame, response=False)
            print("All zones STOPPED — sent!")

        # Wait (bounded) for the device's confirmation, then decode it — fast
        # devices return immediately, a silent one exits on the timeout.
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
        print(f"{mac} not found — is it awake (press the button) and in range?")
        return
    print("Found. Connecting...")

    async with BleakClient(device, timeout=15.0) as client:
        await _connect(client)
        collector = _RxCollector()
        await _init_session(client, key, collector)
        print("Waiting for status push...")

        # The device pushes a status (#16) on connect; wait (bounded) for it.
        await _await_rx(collector, first_timeout=6.0)
        await client.stop_notify(READ_CHAR)

        if collector.decoded:
            print(f"Status: {_format_status(collector.merged_status())}")
        elif collector.raw:
            print(f"Received {len(collector.raw)} notification(s) but none decoded.")
        else:
            # We connected fine (MTU printed above), so this isn't range/sleep —
            # the device just didn't volunteer a status push. It reliably answers a
            # command, so on/off confirmations read back state even when this won't.
            print("Connected, but the device sent no status push "
                  "(it may not volunteer state while active).")


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

    args = parser.parse_args()

    if args.action == "setup":
        cmd_setup(args)
    elif args.action in ("on", "off"):
        args.command = args.action
        cmd_control(args)
    elif args.action == "status":
        cmd_status(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
