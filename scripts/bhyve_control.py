#!/usr/bin/env python3
"""
Orbit B-Hyve XD Bluetooth Valve Controller

Direct BLE control of the B-Hyve XD 4-valve hose timer.
No cloud, no app, no Wi-Fi hub required.

Usage:
    python3 bhyve_control.py on 1 300       # Zone 1 for 5 minutes
    python3 bhyve_control.py on 1 600       # Zone 1 for 10 minutes
    python3 bhyve_control.py off             # Stop all watering

Requirements: pip install bleak cryptography
Run on any Linux machine with Bluetooth (tested on Fedora with bluez).

Protocol reverse-engineered from the Orbit B-Hyve Android app.
Encryption: Custom AES-ECB-based CTR mode with per-session IV.
"""

import asyncio
import argparse
import struct
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ─── Device Configuration ───────────────────────────────────────────────

MAC_ADDRESS = "XX:XX:XX:XX:XX:XX"
NETWORK_KEY = bytes.fromhex("<YOUR_NETWORK_KEY_HEX>")

# GATT characteristic UUIDs
AES_CHAR    = "00006c71-fe32-4f58-8b78-98e42b2c047f"  # AES session init (20B r/w)
WRITE_CHAR  = "00006c72-fe32-4f58-8b78-98e42b2c047f"  # Encrypted commands TX
READ_CHAR   = "00006c73-fe32-4f58-8b78-98e42b2c047f"  # Encrypted responses RX (notify)

# Inner message header (constant)
MSG_HEADER = bytes([0xAA, 0x77, 0x5A, 0x0F])


# ─── Crypto ──────────────────────────────────────────────────────────────

def crc16_ccitt(data: bytes, init: int = 0) -> int:
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def aes_encrypt(key: bytes, iv: bytes, counter: int, plaintext: bytes) -> tuple[bytes, int]:
    """Encrypt using the B-Hyve custom AES-ECB CTR mode.

    Block = IV(12B) || LE_uint32(counter)
    Keystream = AES_ECB(key, block)
    Ciphertext = plaintext XOR keystream
    Counter increments per 16-byte block.

    Returns (ciphertext, new_counter).
    """
    result = bytearray()
    for offset in range(0, len(plaintext), 16):
        chunk = plaintext[offset:offset + 16]
        block = iv + struct.pack("<I", counter)
        keystream = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)
        result.extend(b ^ k for b, k in zip(chunk, keystream[: len(chunk)]))
        counter = (counter + 1) % 0xFFFFFFFF
    return bytes(result), counter


# ─── Message Building ────────────────────────────────────────────────────

def build_message(protobuf: bytes) -> bytes:
    """Wrap protobuf in inner message format with header and CRC16.

    Format: [AA775A0F] [payload_len] [0x00] [protobuf] [CRC16-LE]
    CRC16 = CRC16-CCITT(init=0) over everything before the CRC, stored LE.
    """
    payload_len = len(protobuf) + 2  # includes the 2-byte CRC
    msg = MSG_HEADER + bytes([payload_len, 0x00]) + protobuf
    crc = struct.pack("<H", crc16_ccitt(msg, 0))
    return msg + crc


def build_ble_frame(ciphertext: bytes, trailer: bytes) -> bytes:
    """Build BLE frame: [0x11] [length] [ciphertext] [2B trailer]"""
    return bytes([0x11, len(ciphertext)]) + ciphertext + trailer


def build_start_protobuf(station_id: int, duration_sec: int) -> bytes:
    """Build timerMode protobuf for starting a zone.

    timerMode {
        mode = manualMode (2)
        manualModeParams {
            stationInfo {
                stationId = <0-indexed>
                runTimeSec = <duration>
            }
        }
    }
    """

    def varint(val):
        r = bytearray()
        while val > 0x7F:
            r.append((val & 0x7F) | 0x80)
            val >>= 7
        r.append(val & 0x7F)
        return bytes(r)

    def field_varint(f, v):
        return varint((f << 3) | 0) + varint(v)

    def field_bytes(f, d):
        return varint((f << 3) | 2) + varint(len(d)) + d

    station_info = field_varint(1, station_id) + field_varint(2, duration_sec)
    manual_params = field_bytes(3, station_info)
    timer_mode = field_varint(1, 2) + field_bytes(2, manual_params)
    return field_bytes(14, timer_mode)


def build_stop_protobuf() -> bytes:
    """Build timerMode protobuf for stopping all watering.

    timerMode { mode = manualMode (2), manualModeParams = {} }
    """
    return bytes.fromhex("720408021200")


# ─── BLE Communication ──────────────────────────────────────────────────

async def run_command(command: str, zones: list[int] = None, duration: int = 600):
    from bleak import BleakClient

    print(f"Connecting to {MAC_ADDRESS}...")

    async with BleakClient(MAC_ADDRESS, timeout=15.0) as client:
        # Negotiate MTU (required for frames > 20 bytes)
        await client._backend._acquire_mtu()
        print(f"Connected (MTU={client.mtu_size})")

        # Enable notifications
        notifications = []

        def on_notify(sender, data):
            notifications.append(data)

        await client.start_notify(READ_CHAR, on_notify)

        # AES session init: write 20 random bytes with byte[11]=0x00
        init_tx = bytearray(os.urandom(20))
        init_tx[11] = 0x00
        init_tx = bytes(init_tx)

        await client.write_gatt_char(AES_CHAR, init_tx)
        rx = await client.read_gatt_char(AES_CHAR)

        # Derive session parameters
        iv = rx[:4] + init_tx[4:12]
        counter = struct.unpack("<I", init_tx[12:16])[0]
        print(f"Session established")

        # Build and send command
        if command == "on":
            for zone in zones:
                station_id = zone - 1  # 0-indexed in protocol
                protobuf = build_start_protobuf(station_id, duration)
                message = build_message(protobuf)
                ciphertext, counter = aes_encrypt(NETWORK_KEY, iv, counter, message)
                frame = build_ble_frame(ciphertext, b"\x80\x04")

                await client.write_gatt_char(WRITE_CHAR, frame, response=True)
                print(f"Zone {zone} ON for {duration}s — accepted!")

        elif command == "off":
            protobuf = build_stop_protobuf()
            message = build_message(protobuf)
            ciphertext, counter = aes_encrypt(NETWORK_KEY, iv, counter, message)
            frame = build_ble_frame(ciphertext, b"\x80\x03")

            await client.write_gatt_char(WRITE_CHAR, frame, response=True)
            print("All zones STOPPED — accepted!")

        # Wait for device response
        await asyncio.sleep(3)
        if notifications:
            print(f"Device responded ({len(notifications)} notification(s))")

        await client.stop_notify(READ_CHAR)
        print("Done.")


# ─── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Orbit B-Hyve XD Bluetooth Valve Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s on 1 300          Zone 1 on for 5 minutes
  %(prog)s on 1 600          Zone 1 on for 10 minutes (default)
  %(prog)s on 2 60           Zone 2 on for 1 minute
  %(prog)s off               Stop all watering
        """,
    )
    parser.add_argument("command", choices=["on", "off"], help="on or off")
    parser.add_argument("zones", nargs="?", help="Zone number (1-4)")
    parser.add_argument("duration", nargs="?", type=int, default=600,
                        help="Duration in seconds (default: 600)")
    parser.add_argument("--mac", default=MAC_ADDRESS,
                        help=f"Device MAC (default: {MAC_ADDRESS})")

    args = parser.parse_args()
    global MAC_ADDRESS
    MAC_ADDRESS = args.mac

    if args.command == "on":
        if not args.zones:
            parser.error("'on' requires a zone number (1-4)")
        zones = [int(z.strip()) for z in args.zones.split(",")]
        for z in zones:
            if z < 1 or z > 4:
                parser.error(f"Zone {z} out of range (1-4)")
        asyncio.run(run_command("on", zones, args.duration))
    else:
        asyncio.run(run_command("off"))


if __name__ == "__main__":
    main()
