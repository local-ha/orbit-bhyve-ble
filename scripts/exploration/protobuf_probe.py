#!/usr/bin/env python3
"""
B-Hyve Protobuf BleInitMsg Probe

Attempts to authenticate with the B-Hyve device using Protocol Buffer
BleInitMsg messages with various networkKey candidates.

The device requires:
  - Properly encoded protobuf BleInitMsg (field 1: bdAddress, field 2: networkKey)
  - CRC32 appended to message
  - Written to characteristic 00006c72-fe32-4f58-8b78-98e42b2c047f

GATT Error 0x80 = rejected (wrong key or format)
No error = accepted

Run on <your_linux_host>:
  python3 protobuf_probe.py
"""
import asyncio
import struct
import zlib
from bleak import BleakClient

MAC = "XX:XX:XX:XX:XX:XX"
MAC_BYTES = bytes.fromhex(MAC.replace(":", ""))

WRITE_CHAR  = "00006c72-fe32-4f58-8b78-98e42b2c047f"
NOTIFY_CHAR = "00006c73-fe32-4f58-8b78-98e42b2c047f"

notifications = []


def on_notify(sender, data):
    print(f"  NOTIFY: {data.hex()}")
    notifications.append(data)


def encode_varint(n):
    """Encode a non-negative integer as protobuf varint."""
    result = b""
    while True:
        bits = n & 0x7F
        n >>= 7
        if n:
            result += bytes([bits | 0x80])
        else:
            result += bytes([bits])
            break
    return result


def pb_bytes_field(field_num, data):
    """Encode a protobuf length-delimited (bytes) field."""
    tag = (field_num << 3) | 2
    return encode_varint(tag) + encode_varint(len(data)) + data


def pb_uint32_field(field_num, value):
    """Encode a protobuf varint field."""
    tag = (field_num << 3) | 0
    return encode_varint(tag) + encode_varint(value)


def build_ble_init_msg(network_key=b"", advert_type=0, device_sn=0):
    """
    Build OrbitPbApi_BleInitMsg:
      field 1: bdAddress (bytes)
      field 2: networkKey (bytes)
      field 3: advertType (uint32)
      field 4: deviceSn (uint32)
    """
    msg = pb_bytes_field(1, MAC_BYTES)
    if network_key:
        msg += pb_bytes_field(2, network_key)
    if advert_type:
        msg += pb_uint32_field(3, advert_type)
    if device_sn:
        msg += pb_uint32_field(4, device_sn)
    return msg


def append_crc32(data):
    """Append CRC32 (little-endian) to message."""
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return data + struct.pack("<I", crc)


async def try_write(client, payload, label):
    """Attempt a write, return True if accepted (no GATT error)."""
    try:
        await client.write_gatt_char(WRITE_CHAR, payload)
        print(f"  ✓ ACCEPTED: {label}")
        print(f"    Payload: {payload.hex()}")
        return True
    except Exception as e:
        err = str(e)
        if "128" in err or "0x80" in err:
            print(f"  ✗ 0x80: {label}")
        else:
            print(f"  ✗ {err}: {label}")
        return False


async def main():
    print(f"B-Hyve Protobuf Probe — {MAC}\n")

    # networkKey candidates to try
    key_candidates = [
        # Empty / no key
        (b"",                                   "empty (no field 2)"),
        # Zero-length vs zero-value
        (b"\x00",                               "single zero byte"),
        (b"\x00" * 6,                           "6 zero bytes (MAC length)"),
        (b"\x00" * 16,                          "16 zero bytes"),
        # MAC-derived
        (MAC_BYTES,                             "MAC bytes as key"),
        (MAC_BYTES[::-1],                       "MAC bytes reversed"),
        # Common defaults
        (b"\xFF" * 6,                           "6 xFF bytes"),
        (b"\xFF" * 16,                          "16 xFF bytes"),
        # ASCII strings
        (b"orbit",                              "b'orbit'"),
        (b"bhyve",                              "b'bhyve'"),
        (b"BHYV",                               "b'BHYV' magic"),
        (b"OrbitBLE",                           "b'OrbitBLE'"),
        (b"\x00" * 4,                           "4 zero bytes"),
        # XOR of MAC bytes
        (bytes([b ^ 0xFF for b in MAC_BYTES]),  "MAC XOR 0xFF"),
    ]

    async with BleakClient(MAC, timeout=15.0) as client:
        print("✓ Connected\n")

        await client.start_notify(NOTIFY_CHAR, on_notify)
        print("✓ Notifications enabled\n")

        print("=== Testing BleInitMsg with CRC32 ===\n")
        for key, label in key_candidates:
            msg = build_ble_init_msg(network_key=key)
            payload = append_crc32(msg)
            accepted = await try_write(client, payload, label)
            if accepted:
                print(f"\n  *** FOUND WORKING KEY: {key.hex() if key else '(empty)'} ***\n")
                await asyncio.sleep(2)
                print(f"  Notifications received: {len(notifications)}")
                for n in notifications:
                    print(f"    {n.hex()}")
                return
            await asyncio.sleep(0.3)

        print("\n=== Testing WITHOUT CRC32 ===\n")
        for key, label in key_candidates[:4]:
            msg = build_ble_init_msg(network_key=key)
            accepted = await try_write(client, msg, f"(no CRC) {label}")
            if accepted:
                print(f"\n  *** ACCEPTED WITHOUT CRC: {label} ***\n")
                return
            await asyncio.sleep(0.3)

        print("\n=== Testing raw protobuf to read_write char ===\n")
        READ_WRITE_CHAR = "00006c71-fe32-4f58-8b78-98e42b2c047f"
        msg = build_ble_init_msg(network_key=b"")
        payload = append_crc32(msg)
        try:
            await client.write_gatt_char(READ_WRITE_CHAR, payload)
            print(f"  ✓ ACCEPTED on read_write char!")
        except Exception as e:
            print(f"  ✗ {e}")

        print(f"\nDone. Total notifications: {len(notifications)}")
        await client.stop_notify(NOTIFY_CHAR)


if __name__ == "__main__":
    asyncio.run(main())
