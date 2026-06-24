#!/usr/bin/env python3
"""
Shared research helpers for the B-Hyve BLE reverse-engineering tools.

This module now holds only what is genuinely research-only: device resolution and
the live BLE session helper (LiveSession). Both the *encode* primitives (AES-CTR,
CRC-16, trailer, frame/message builders, protobuf writers) and the *decode* path
(session derivation, frame/inner parsing, the protobuf reader, RX status
extraction) are reused from the shipping CLI `scripts/bhyve.py` rather than
duplicated — the CLI gained the decode side so it can surface device telemetry.

Dependency direction: research tools import the shipping CLI; the CLI must never
import this module. (See the brief's "Upstream PR Priorities".)

Protocol reference: ../../docs/encryption.md and ../../docs/ble_protocol.md.
    outer:  0x11 | len | ciphertext(len) | trailer(2, LE)
    inner:  AA 77 5A 0F | payload_len | 00 | protobuf | CRC16-CCITT(2, LE)
    cipher: AES-128-ECB used as CTR; keystream = AES-ECB(key, IV || ctr_LE)
    IV          = rx_response[:4] || init_tx[4:12]   (same for both directions)
    counter_TX  = uint32_LE(init_tx[12:16])
    counter_RX  = uint32_LE(init_tx[16:20])
"""
import sys
from pathlib import Path

# Frame dumps print Unicode (→, ✓, ✗); Windows consoles default to cp1252 and
# raise UnicodeEncodeError mid-report. Force UTF-8 so a live run never dies after
# the command was already sent. Idempotent/best-effort; importing this module
# (every tool does) installs the guard once for all of them.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# Import the shipping CLI for the canonical ENCODE primitives, config loader, and
# GATT constants. bhyve.py imports bleak/requests lazily, so this stays offline.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bhyve as bh  # noqa: E402

MSG_HEADER = bh.MSG_HEADER
AES_CHAR, WRITE_CHAR, READ_CHAR = bh.AES_CHAR, bh.WRITE_CHAR, bh.READ_CHAR

# Re-export the shipping primitives so tools have one import surface. The encode
# path, the decode path, and session derivation all live in the CLI now (single
# source of truth); this module only adds research-only helpers below.
crc16_ccitt = bh.crc16_ccitt
compute_trailer = bh.compute_trailer
build_message = bh.build_message
build_ble_frame = bh.build_ble_frame
load_config = bh.load_config

derive_session = bh.derive_session
parse_ble_frame = bh.parse_ble_frame
decode_inner = bh.decode_inner
decrypt_frame = bh.decrypt_frame
pb_parse = bh.pb_parse
pb_format = bh.pb_format
extract_status = bh.extract_status
DeviceStatus = bh.DeviceStatus


def aes_ctr(key, iv, counter, data):
    """AES-128 ECB-as-CTR. Returns (out, next_counter). Symmetric (enc == dec)."""
    return bh.aes_encrypt(key, iv, counter, data)


def build_command_frame(key, iv, counter, protobuf):
    """Encode a protobuf into a full on-wire frame. Returns (frame, next_counter)."""
    message = build_message(protobuf)
    ct, next_counter = aes_ctr(key, iv, counter, message)
    return build_ble_frame(ct, compute_trailer(message)), next_counter


# ─── Device resolution (from saved config or --mac/--key) ─────────────────

def resolve_device(args):
    """Return (name, mac, key_hex) from --mac/--key overrides or saved config."""
    if getattr(args, "mac", None) and getattr(args, "key", None):
        return ("<cli-override>", args.mac, args.key)
    config = load_config()
    devices = config.get("devices") or []
    if not devices:
        sys.exit("No devices configured (run `bhyve.py setup`) and no --mac/--key given.")
    idx = (getattr(args, "device", None) or 1) - 1
    if idx < 0 or idx >= len(devices):
        sys.exit(f"--device {args.device} out of range (have {len(devices)}).")
    dev = devices[idx]
    mac = getattr(args, "mac", None) or dev["mac"]
    key = getattr(args, "key", None) or dev["network_key"]
    return (dev.get("name", f"device{idx + 1}"), mac, key)


# ─── Live BLE session helper ──────────────────────────────────────────────

class LiveSession:
    """Async context manager: scan → connect → MTU → AES init → notify.

    Exposes iv / tx_counter / rx_counter (derived for both directions), a
    timestamped `rx_frames` buffer, `send(protobuf)` (advances the TX counter),
    and `decode_rx(raw)` (decodes with the RX counter). Mirrors the session-init
    quirks of the shipping CLI exactly (init_tx[11] = 0x00, write-without-response).
    """

    def __init__(self, mac, key_hex, scan_timeout=25.0, connect_timeout=15.0):
        self.mac = mac
        self.key = bytes.fromhex(key_hex)
        self.scan_timeout = scan_timeout
        self.connect_timeout = connect_timeout
        self.rx_frames = []   # list of (t_relative, raw_bytes)

    async def __aenter__(self):
        import os
        import time
        from bleak import BleakClient, BleakScanner

        device = await BleakScanner.find_device_by_address(self.mac, timeout=self.scan_timeout)
        if device is None:
            sys.exit(f"{self.mac} not found — is it awake and in range?")
        self.client = BleakClient(device, timeout=self.connect_timeout)
        await self.client.__aenter__()

        # _acquire_mtu() is BlueZ-only; Windows/WinRT negotiates automatically.
        acquire_mtu = getattr(self.client._backend, "_acquire_mtu", None)
        if acquire_mtu is not None:
            await acquire_mtu()
        self.mtu = self.client.mtu_size

        self._t0 = time.monotonic()
        await self.client.start_notify(
            READ_CHAR,
            lambda _s, d: self.rx_frames.append((time.monotonic() - self._t0, bytes(d))),
        )

        # AES session init — identical to bhyve.py (init_tx[11] forced to 0x00).
        init_tx = bytearray(os.urandom(20))
        init_tx[11] = 0x00
        self.init_tx = bytes(init_tx)
        await self.client.write_gatt_char(AES_CHAR, self.init_tx)
        self.init_rx = bytes(await self.client.read_gatt_char(AES_CHAR))
        self.iv, self.tx_counter, self.rx_counter = derive_session(self.init_tx, self.init_rx)
        return self

    async def __aexit__(self, *exc):
        try:
            await self.client.stop_notify(READ_CHAR)
        except Exception:
            pass
        await self.client.__aexit__(*exc)

    async def send(self, protobuf):
        """Build + write a command frame on 6c72, advancing the TX counter."""
        frame, self.tx_counter = build_command_frame(self.key, self.iv, self.tx_counter, protobuf)
        await self.client.write_gatt_char(WRITE_CHAR, frame, response=False)
        return frame

    def decode_rx(self, raw):
        """Decode an RX notification with the RX counter. Returns (ctr, pt, inner)."""
        parsed = parse_ble_frame(raw)
        if parsed is None:
            return None, None, None
        _, ct, _ = parsed
        return decrypt_frame(self.key, self.iv, ct, self.rx_counter)
