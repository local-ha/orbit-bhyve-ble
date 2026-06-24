import asyncio
from bleak import BleakClient
import struct

MAC = "XX:XX:XX:XX:XX:XX"

CHARS = {
    "read_write": "00006c71-fe32-4f58-8b78-98e42b2c047f",
    "write_cmd": "00006c72-fe32-4f58-8b78-98e42b2c047f",
    "write_only": "00006c76-fe32-4f58-8b78-98e42b2c047f",
    "notify": "00006c73-fe32-4f58-8b78-98e42b2c047f",
}

notifications = []

def notification_handler(sender, data):
    print(f"NOTIFICATION: {sender[-8:]} -> {data.hex()}")
    notifications.append((sender, data.hex()))

async def explore_protocol():
    print(f"Exploring B-Hyve protocol on {MAC}")
    
    try:
        async with BleakClient(MAC, timeout=30.0) as client:
            print(f"✓ Connected")
            
            # Get service details
            services = list(client.services)
            print(f"\n=== Services ({len(services)} total) ===")
            for svc in services:
                print(f"\nService: {svc.uuid}")
                for char in svc.characteristics:
                    print(f"  Characteristic: {char.uuid}")
                    print(f"    Properties: {char.properties}")
            
            # Enable notifications
            print("\n=== Enabling notifications ===")
            await client.start_notify(CHARS["notify"], notification_handler)
            print("✓ Notifications enabled")
            await asyncio.sleep(1)
            
            # Test 1: Try reading initial state
            print("\n=== Test 1: Read characteristics ===")
            for name, uuid in CHARS.items():
                if name != "notify":
                    try:
                        value = await client.read_gatt_char(uuid)
                        print(f"  {name}: {value.hex() if value else None}")
                    except Exception as e:
                        print(f"  {name}: ERROR - {e}")
            
            # Test 2: Minimal command tests
            print("\n=== Test 2: Minimal commands ===")
            test_cmds = [
                ("empty", b""),
                ("single_0", b"\x00"),
                ("single_1", b"\x01"),
                ("single_FF", b"\xFF"),
                ("two_bytes", b"\x01\x00"),
                ("three_bytes", b"\x01\x00\x00"),
                ("four_bytes", b"\x01\x00\x00\x00"),
            ]
            
            for cmd_name, data in test_cmds:
                print(f"\n  Command: {cmd_name} = {data.hex()}")
                
                # Try write_cmd characteristic
                print(f"    write_cmd: ", end="")
                try:
                    await client.write_gatt_char(CHARS["write_cmd"], data)
                    print("✓")
                    await asyncio.sleep(0.2)
                except Exception as e:
                    print(f"✗ ({e})")
                
                # Try write_only characteristic
                print(f"    write_only: ", end="")
                try:
                    await client.write_gatt_char(CHARS["write_only"], data)
                    print("✓")
                    await asyncio.sleep(0.2)
                except Exception as e:
                    print(f"✗ ({e})")
            
            # Test 3: Try possible handshake/auth patterns
            print("\n=== Test 3: Handshake patterns ===")
            
            # Common BLE auth patterns
            handshake_patterns = [
                ("handshake_1", b"\xAA\x55"),
                ("handshake_2", b"\x55\xAA"),
                ("init_seq_1", b"\x01\x02\x03\x04"),
                ("magic_bytes", bytes([0x42, 0x48, 0x59, 0x56])),  # "BHYV"
                ("version_req", b"\x00\x00\x00\x01"),
            ]
            
            for name, data in handshake_patterns:
                print(f"\n  Handshake: {name}")
                
                print(f"    write_cmd: ", end="")
                try:
                    await client.write_gatt_char(CHARS["write_cmd"], data)
                    print("✓")
                    await asyncio.sleep(0.3)
                except Exception as e:
                    print(f"✗ ({e})")
                    
                print(f"    read_write: ", end="")
                try:
                    value = await client.read_gatt_char(CHARS["read_write"])
                    print(f"✓ -> {value.hex() if value else None}")
                except Exception as e:
                    print(f"✗ ({e})")
                    
            # Test 4: Try to write to read_write characteristic
            print("\n=== Test 4: Write to read_write characteristic ===")
            write_tests = [
                ("simple_write", b"\x01\x02\x03"),
                ("valve_request", b"\x01\x01"),
                ("status_request", b"\x02"),
            ]
            
            for name, data in write_tests:
                print(f"\n  Write to read_write: {name}")
                try:
                    await client.write_gatt_char(CHARS["read_write"], data)
                    print(f"    ✓ Write succeeded")
                    
                    # Try reading back
                    try:
                        value = await client.read_gatt_char(CHARS["read_write"])
                        print(f"    Read back: {value.hex() if value else None}")
                    except Exception as e:
                        print(f"    Read failed: {e}")
                    
                    await asyncio.sleep(0.3)
                except Exception as e:
                    print(f"    ✗ Write failed: {e}")
            
            # Final read
            print("\n=== Final state check ===")
            for name, uuid in CHARS.items():
                if name != "notify":
                    try:
                        value = await client.read_gatt_char(uuid)
                        print(f"  {name}: {value.hex() if value else None}")
                    except:
                        pass
            
            # Summary
            print(f"\n=== Test Summary ===")
            print(f"Total notifications: {len(notifications)}")
            for sender, data in notifications:
                print(f"  {sender[-8:]}: {data}")
            
            await client.stop_notify(CHARS["notify"])
            print("✓ Cleanup complete")
            
    except Exception as e:
        print(f"Critical error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(explore_protocol())
