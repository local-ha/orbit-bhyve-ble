#!/usr/bin/env python3
"""
B-Hyve BLE Initialization Probe

The device has a 20-byte read/write characteristic (6c71) that likely handles
the AES session initialization. This script attempts various 20-byte payloads
to establish the encrypted session.

Key facts:
- 6c71 is exactly 20 bytes (rejects other lengths)
- 6c71 currently reads: a1abb80e + 16 zero bytes
- The protocol uses AES encryption (networkKey = 16 bytes = AES-128)
- There's a "seq init" step before AES communication works
- There's a "ctr" (counter) field used with AES (likely AES-CTR mode)

Hypothesis: 6c71 format = [4-byte counter/header] + [16-byte AES block]

Run on <your_linux_host>:
  python3 init_probe.py
"""
import asyncio
import struct
import zlib
import os
from bleak import BleakClient

MAC = "XX:XX:XX:XX:XX:XX"
MAC_BYTES = bytes.fromhex("446755D46834")
NETWORK_KEY = bytes.fromhex("<YOUR_NETWORK_KEY_HEX>")

# Characteristics
READ_WRITE     = "00006c71-fe32-4f58-8b78-98e42b2c047f"  # 20 bytes, read/write
WRITE_CHAR     = "00006c72-fe32-4f58-8b78-98e42b2c047f"  # write-without-response, write
NOTIFY_CHAR    = "00006c73-fe32-4f58-8b78-98e42b2c047f"  # notify
WRITE_ONLY     = "00006c76-fe32-4f58-8b78-98e42b2c047f"  # write

notifications = []


def on_notify(sender, data):
    print(f"  NOTIFY [{len(data)}B]: {data.hex()}")
    notifications.append(data)


def aes_ecb_encrypt(key, plaintext):
    """AES-128 ECB encrypt a single 16-byte block."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        enc = cipher.encryptor()
        return enc.update(plaintext) + enc.finalize()
    except ImportError:
        # Fallback: try pycryptodome
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext)


def aes_ctr_encrypt(key, nonce_bytes, plaintext):
    """AES-128 CTR encrypt."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        # Pad nonce to 16 bytes
        nonce_padded = nonce_bytes.ljust(16, b'\x00')
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce_padded))
        enc = cipher.encryptor()
        return enc.update(plaintext) + enc.finalize()
    except ImportError:
        from Crypto.Cipher import AES
        nonce_padded = nonce_bytes.ljust(8, b'\x00')
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce_padded)
        return cipher.encrypt(plaintext)


async def main():
    print(f"B-Hyve Init Probe — {MAC}")
    print(f"networkKey: {NETWORK_KEY.hex()}\n")

    async with BleakClient(MAC, timeout=15.0) as client:
        print("Connected\n")

        # Enable notifications
        await client.start_notify(NOTIFY_CHAR, on_notify)
        print("Notifications enabled\n")

        # Read current state of 6c71
        val = await client.read_gatt_char(READ_WRITE)
        print(f"6c71 read [{len(val)}B]: {val.hex()}")
        header = val[:4]
        body = val[4:]
        print(f"  Header (4B): {header.hex()} (LE uint32: {struct.unpack('<I', header)[0]})")
        print(f"  Body  (16B): {body.hex()}")

        # Also read a second time to see if it changes
        val2 = await client.read_gatt_char(READ_WRITE)
        print(f"6c71 read2[{len(val2)}B]: {val2.hex()}")
        if val2 == val:
            print("  (same as first read)")
        else:
            print("  (CHANGED!)")

        # Check 6c76 expected length
        print(f"\nChecking 6c76 expected write length...")
        for size in [1, 2, 4, 8, 16, 20]:
            try:
                await client.write_gatt_char(WRITE_ONLY, b'\x00' * size)
                print(f"  6c76 accepts {size} bytes!")
                break
            except Exception as e:
                err = str(e)
                if "13" in err or "Length" in err:
                    pass  # Wrong length, try next
                elif "128" in err or "0x80" in err:
                    print(f"  6c76 accepts {size} bytes (GATT 0x80 — wrong content)")
                    break
                else:
                    pass

        print(f"\n=== Phase 1: 20-byte writes to 6c71 ===\n")

        # Extract counter from header
        ctr = struct.unpack('<I', header)[0]

        # Try various 20-byte payloads
        payloads = []

        # 1. networkKey with zero header
        payloads.append((b'\x00' * 4 + NETWORK_KEY, "zeros + networkKey"))

        # 2. Same header as device + networkKey
        payloads.append((header + NETWORK_KEY, "device_header + networkKey"))

        # 3. Counter+1 + networkKey
        payloads.append((struct.pack('<I', ctr + 1) + NETWORK_KEY, "ctr+1 + networkKey"))

        # 4. Counter+1 + MAC padded to 16 bytes
        mac_padded = MAC_BYTES + b'\x00' * 10
        payloads.append((struct.pack('<I', ctr + 1) + mac_padded, "ctr+1 + MAC_padded"))

        # 5. Counter+1 + AES_ECB(networkKey, MAC_padded)
        try:
            encrypted_mac = aes_ecb_encrypt(NETWORK_KEY, mac_padded)
            payloads.append((struct.pack('<I', ctr + 1) + encrypted_mac, "ctr+1 + AES(MAC)"))
        except Exception as e:
            print(f"  AES encrypt failed: {e}")

        # 6. Counter+1 + AES_ECB(networkKey, all_zeros)
        try:
            encrypted_zeros = aes_ecb_encrypt(NETWORK_KEY, b'\x00' * 16)
            payloads.append((struct.pack('<I', ctr + 1) + encrypted_zeros, "ctr+1 + AES(zeros)"))
        except Exception as e:
            pass

        # 7. Counter+1 + AES_ECB(networkKey, counter_as_block)
        try:
            ctr_block = struct.pack('<I', ctr + 1) + b'\x00' * 12
            encrypted_ctr = aes_ecb_encrypt(NETWORK_KEY, ctr_block)
            payloads.append((struct.pack('<I', ctr + 1) + encrypted_ctr, "ctr+1 + AES(ctr_block)"))
        except Exception as e:
            pass

        # 8. All zeros (20 bytes)
        payloads.append((b'\x00' * 20, "20 zero bytes"))

        # 9. MAC (6B) + networkKey (16B) = 22... too long. Try MAC_4B + key
        payloads.append((MAC_BYTES[:4] + NETWORK_KEY, "MAC[:4] + networkKey"))

        # 10. networkKey + counter
        payloads.append((NETWORK_KEY + header, "networkKey + device_header"))

        for payload, label in payloads:
            assert len(payload) == 20, f"Payload {label} is {len(payload)} bytes, need 20"
            try:
                await client.write_gatt_char(READ_WRITE, payload)
                print(f"  OK: {label}")
                print(f"      Wrote: {payload.hex()}")
                # Read back
                readback = await client.read_gatt_char(READ_WRITE)
                print(f"      Read:  {readback.hex()}")
                await asyncio.sleep(1)
                if notifications:
                    print(f"      Notifications: {len(notifications)}")
                    for n in notifications:
                        print(f"        {n.hex()}")
            except Exception as e:
                err = str(e)
                if "128" in err or "0x80" in err:
                    print(f"  GATT 0x80: {label}")
                else:
                    print(f"  ERROR: {label} — {err}")
            await asyncio.sleep(0.3)

        # Phase 2: After 6c71 init, try writing protobuf BleInitMsg to 6c72
        print(f"\n=== Phase 2: Check if auth state changed ===\n")

        # Read 6c71 again to see current state
        val3 = await client.read_gatt_char(READ_WRITE)
        print(f"6c71 after writes: {val3.hex()}")

        # Try protobuf BleInitMsg on 6c72 again
        from auth_probe import build_ble_init_msg, append_crc32
        init_msg = build_ble_init_msg(NETWORK_KEY)
        payload_crc = append_crc32(init_msg)
        try:
            await client.write_gatt_char(WRITE_CHAR, payload_crc)
            print(f"  6c72 protobuf ACCEPTED!")
        except Exception as e:
            err = str(e)
            if "128" in err or "0x80" in err:
                print(f"  6c72 protobuf still GATT 0x80")
            else:
                print(f"  6c72 error: {err}")

        print(f"\nTotal notifications: {len(notifications)}")
        for n in notifications:
            print(f"  {n.hex()}")

        await client.stop_notify(NOTIFY_CHAR)
        print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
