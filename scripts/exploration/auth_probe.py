#!/usr/bin/env python3
"""
B-Hyve BLE Authentication Probe — with REAL networkKey

Sends BleInitMsg with the extracted networkKey to authenticate,
then listens for notifications and attempts valve control.

Run on <your_linux_host>:
  python3 auth_probe.py
"""
import asyncio
import struct
import zlib
import time
from bleak import BleakClient

MAC = "XX:XX:XX:XX:XX:XX"
MAC_BYTES = bytes.fromhex("446755D46834")
NETWORK_KEY = bytes.fromhex("<YOUR_NETWORK_KEY_HEX>")

# Characteristics
WRITE_CHAR     = "00006c72-fe32-4f58-8b78-98e42b2c047f"  # write-without-response, write
READ_WRITE     = "00006c71-fe32-4f58-8b78-98e42b2c047f"  # read, write
NOTIFY_CHAR    = "00006c73-fe32-4f58-8b78-98e42b2c047f"  # notify
WRITE_ONLY     = "00006c76-fe32-4f58-8b78-98e42b2c047f"  # write

notifications = []


def on_notify(sender, data):
    print(f"  NOTIFY [{len(data)} bytes]: {data.hex()}")
    notifications.append(data)


def encode_varint(n):
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
    tag = (field_num << 3) | 2
    return encode_varint(tag) + encode_varint(len(data)) + data


def pb_uint32_field(field_num, value):
    tag = (field_num << 3) | 0
    return encode_varint(tag) + encode_varint(value)


def build_ble_init_msg(network_key, advert_type=0, device_sn=0):
    """
    OrbitPbApi_BleInitMsg:
      field 1: bdAddress (bytes) — device MAC
      field 2: networkKey (bytes) — 16-byte auth key
      field 3: advertType (uint32)
      field 4: deviceSn (uint32)
    """
    msg = pb_bytes_field(1, MAC_BYTES)
    msg += pb_bytes_field(2, network_key)
    if advert_type:
        msg += pb_uint32_field(3, advert_type)
    if device_sn:
        msg += pb_uint32_field(4, device_sn)
    return msg


def append_crc32(data):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return data + struct.pack("<I", crc)


def build_watering_command(station, duration_sec):
    """
    Build IpcMsg > bleBridgedMsgs > BleDevSpec_IrrigationTimer > wateringStatus
    This is speculative — may need adjustment based on actual protocol.
    """
    # WateringStatus (field 2 of IrrigationTimer)
    # We'll try a minimal approach: currentTimeSecEpochLocal + wateringStatus
    epoch_local = int(time.time())

    # IrrigationTimer inner message
    irrigation = pb_uint32_field(1, epoch_local)  # currentTimeSecEpochLocal

    # For wateringStatus, we need to figure out the wire format
    # Try station + duration as simple fields
    watering = pb_uint32_field(1, station)  # station number
    watering += pb_uint32_field(2, duration_sec)  # duration

    irrigation += pb_bytes_field(2, watering)  # wateringStatus as submessage

    # BleBridgedMsg wrapper
    bridged = pb_bytes_field(10, irrigation)  # devSpecific.irrigationTimer = field 10

    # IpcMsg wrapper
    ipc = pb_bytes_field(87, bridged)  # bleBridgedMsgs = field 87 (repeated)

    return ipc


async def try_write(client, char_uuid, payload, label, response=True):
    try:
        await client.write_gatt_char(char_uuid, payload, response=response)
        print(f"  OK: {label}")
        return True
    except Exception as e:
        err = str(e)
        if "128" in err or "0x80" in err:
            print(f"  GATT 0x80: {label}")
        else:
            print(f"  ERROR ({err}): {label}")
        return False


async def main():
    print(f"B-Hyve Auth Probe — {MAC}")
    print(f"networkKey: {NETWORK_KEY.hex()}\n")

    async with BleakClient(MAC, timeout=15.0) as client:
        print("Connected\n")

        # Enable notifications first
        await client.start_notify(NOTIFY_CHAR, on_notify)
        print("Notifications enabled\n")

        # === Phase 1: BleInitMsg authentication ===
        print("=== Phase 1: BleInitMsg Authentication ===\n")

        init_msg = build_ble_init_msg(NETWORK_KEY)
        print(f"  Raw protobuf: {init_msg.hex()}")

        # Try with CRC32 on primary write char
        payload_crc = append_crc32(init_msg)
        print(f"  With CRC32:   {payload_crc.hex()}")

        accepted = await try_write(client, WRITE_CHAR, payload_crc,
                                   "BleInitMsg + CRC32 on 6c72")
        await asyncio.sleep(1)

        if not accepted:
            # Try without CRC
            accepted = await try_write(client, WRITE_CHAR, init_msg,
                                       "BleInitMsg (no CRC) on 6c72")
            await asyncio.sleep(1)

        if not accepted:
            # Try on read/write characteristic
            accepted = await try_write(client, READ_WRITE, payload_crc,
                                       "BleInitMsg + CRC32 on 6c71")
            await asyncio.sleep(1)

        if not accepted:
            accepted = await try_write(client, READ_WRITE, init_msg,
                                       "BleInitMsg (no CRC) on 6c71")
            await asyncio.sleep(1)

        if not accepted:
            # Try on write-only characteristic
            accepted = await try_write(client, WRITE_ONLY, payload_crc,
                                       "BleInitMsg + CRC32 on 6c76")
            await asyncio.sleep(1)

        if not accepted:
            accepted = await try_write(client, WRITE_ONLY, init_msg,
                                       "BleInitMsg (no CRC) on 6c76")
            await asyncio.sleep(1)

        if not accepted:
            # Try write-without-response mode
            accepted = await try_write(client, WRITE_CHAR, payload_crc,
                                       "BleInitMsg + CRC32 (no response) on 6c72",
                                       response=False)
            await asyncio.sleep(1)

        if not accepted:
            # Try wrapping BleInitMsg inside IpcMsg (field 1)
            ipc_init = pb_bytes_field(1, init_msg)
            ipc_crc = append_crc32(ipc_init)
            accepted = await try_write(client, WRITE_CHAR, ipc_crc,
                                       "IpcMsg(BleInitMsg) + CRC32 on 6c72")
            await asyncio.sleep(1)

        if not accepted:
            ipc_init = pb_bytes_field(1, init_msg)
            accepted = await try_write(client, WRITE_CHAR, ipc_init,
                                       "IpcMsg(BleInitMsg) no CRC on 6c72")
            await asyncio.sleep(1)

        # Print any notifications received during auth
        print(f"\nNotifications after auth phase: {len(notifications)}")
        for n in notifications:
            print(f"  {n.hex()}")

        if not accepted:
            print("\nAll auth attempts failed with GATT 0x80.")
            print("The message framing may need a length prefix or different CRC position.")
            print("\nTrying additional framings...\n")

            # Try length-prefixed: [2-byte LE length][protobuf][CRC32]
            length_prefix = struct.pack("<H", len(init_msg))
            framed = length_prefix + init_msg
            framed_crc = append_crc32(framed)
            accepted = await try_write(client, WRITE_CHAR, framed_crc,
                                       "len16LE + BleInitMsg + CRC32")
            await asyncio.sleep(0.5)

            if not accepted:
                # [1-byte length][protobuf][CRC32]
                framed = bytes([len(init_msg)]) + init_msg
                framed_crc = append_crc32(framed)
                accepted = await try_write(client, WRITE_CHAR, framed_crc,
                                           "len8 + BleInitMsg + CRC32")
                await asyncio.sleep(0.5)

            if not accepted:
                # CRC32 prepended instead of appended
                crc = zlib.crc32(init_msg) & 0xFFFFFFFF
                prepended = struct.pack("<I", crc) + init_msg
                accepted = await try_write(client, WRITE_CHAR, prepended,
                                           "CRC32 + BleInitMsg (CRC first)")
                await asyncio.sleep(0.5)

            if not accepted:
                # Try CRC16-CCITT instead of CRC32
                # Simple CRC16 implementation
                def crc16_ccitt(data):
                    crc = 0xFFFF
                    for byte in data:
                        crc ^= byte << 8
                        for _ in range(8):
                            if crc & 0x8000:
                                crc = (crc << 1) ^ 0x1021
                            else:
                                crc <<= 1
                            crc &= 0xFFFF
                    return crc

                crc16 = crc16_ccitt(init_msg)
                with_crc16 = init_msg + struct.pack("<H", crc16)
                accepted = await try_write(client, WRITE_CHAR, with_crc16,
                                           "BleInitMsg + CRC16-CCITT")
                await asyncio.sleep(0.5)

            if not accepted:
                # XOR checksum (single byte)
                xor_sum = 0
                for b in init_msg:
                    xor_sum ^= b
                with_xor = init_msg + bytes([xor_sum])
                accepted = await try_write(client, WRITE_CHAR, with_xor,
                                           "BleInitMsg + XOR checksum")
                await asyncio.sleep(0.5)

        # === Phase 2: If auth succeeded, try reading and valve control ===
        if accepted:
            print("\n=== Phase 2: Post-Auth Operations ===\n")

            # Wait for any unsolicited notifications
            await asyncio.sleep(3)
            print(f"Total notifications: {len(notifications)}")
            for n in notifications:
                print(f"  {n.hex()}")

            # Try reading status
            try:
                val = await client.read_gatt_char(READ_WRITE)
                print(f"\nRead 6c71: {val.hex()}")
            except Exception as e:
                print(f"\nRead 6c71 failed: {e}")

            # Try valve control (station 1, 60 seconds)
            print("\n=== Valve Control: Station 1, 60s ===")
            valve_cmd = build_watering_command(1, 60)
            valve_crc = append_crc32(valve_cmd)
            await try_write(client, WRITE_CHAR, valve_crc,
                           "Valve 1 ON 60s (IpcMsg + CRC32)")
            await asyncio.sleep(3)

            print(f"\nFinal notifications: {len(notifications)}")
            for n in notifications:
                print(f"  {n.hex()}")

        await client.stop_notify(NOTIFY_CHAR)
        print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
