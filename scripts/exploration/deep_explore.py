import asyncio
from bleak import BleakClient
import sys

MAC = "XX:XX:XX:XX:XX:XX"

async def main():
    print(f"Connecting to {MAC}...")
    try:
        async with BleakClient(MAC, timeout=30.0) as client:
            print(f"✓ Connected: {client.is_connected}")
            
            print("\n=== FULL SERVICE DISCOVERY ===")
            for service in client.services:
                print(f"\nService: {service.uuid}")
                if service.description:
                    print(f"  Description: {service.description}")
                
                for char in service.characteristics:
                    print(f"  Characteristic: {char.uuid}")
                    if char.description:
                        print(f"    Description: {char.description}")
                    print(f"    Properties: {char.properties}")
                    print(f"    Handle: {char.handle}")
                    
                    # Try to read if possible
                    if "read" in char.properties:
                        try:
                            data = await client.read_gatt_char(char.uuid)
                            if len(data) > 0:
                                print(f"    READ: {data.hex()}")
                                try:
                                    ascii_str = data.decode("utf-8", errors="ignore")
                                    if ascii_str.strip():
                                        print(f"      ASCII: {ascii_str}")
                                except:
                                    pass
                            else:
                                print(f"    READ: (empty)")
                        except Exception as e:
                            print(f"    READ ERROR: {e}")
                    
                    # Check descriptors
                    for desc in char.descriptors:
                        print(f"    Descriptor: {desc.uuid} (handle: {desc.handle})")
                        # Try to read descriptor
                        try:
                            desc_data = await client.read_gatt_descriptor(desc.handle)
                            print(f"      Value: {desc_data.hex()}")
                            if desc.uuid == "00002902-0000-1000-8000-00805f9b34fb":  # CCCD
                                cccd_val = int.from_bytes(desc_data, byteorder="little")
                                print(f"      CCCD bits: {cccd_val:016b} ({cccd_val})")
                                print(f"      Notifications: {bool(cccd_val & 0x0001)}")
                                print(f"      Indications: {bool(cccd_val & 0x0002)}")
                        except Exception as e:
                            print(f"      READ ERROR: {e}")
            
            print("\n=== TESTING CCCD ENABLE ===")
            # Find notify characteristic and enable CCCD
            for service in client.services:
                for char in service.characteristics:
                    if "notify" in char.properties:
                        print(f"\nFound notify characteristic: {char.uuid}")
                        # Look for CCCD descriptor
                        for desc in char.descriptors:
                            if desc.uuid == "00002902-0000-1000-8000-00805f9b34fb":
                                print(f"  CCCD descriptor handle: {desc.handle}")
                                try:
                                    # Enable notifications (0x0001)
                                    enable_bytes = bytes([0x01, 0x00])
                                    await client.write_gatt_descriptor(desc.handle, enable_bytes)
                                    print("  ✓ CCCD enabled for notifications")
                                except Exception as e:
                                    print(f"  ✗ Failed to enable CCCD: {e}")
            
            print("\n=== TESTING COMMAND STRUCTURE ===")
            # Based on common BLE protocols, try more structured commands
            test_commands = [
                bytes([0xAA, 0x55, 0x01, 0x00]),  # Common sync pattern
                bytes([0x55, 0xAA, 0x01, 0x00]),
                bytes([0xFE, 0xED, 0x01, 0x00]),  # Another common pattern
                bytes([0x00] * 4),  # All zeros
                bytes([0xFF] * 4),  # All ones
                bytes([0x7E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),  # Longer command
            ]
            
            # Try each characteristic
            for service in client.services:
                for char in service.characteristics:
                    if "write" in char.properties:
                        print(f"\nTrying writes to {char.uuid}:")
                        for i, cmd in enumerate(test_commands[:3]):  # Limit to 3 per char
                            try:
                                print(f"  Command {i+1}: {cmd.hex()} -> ", end="")
                                await client.write_gatt_char(char.uuid, cmd)
                                print("SUCCESS")
                                await asyncio.sleep(0.2)
                            except Exception as e:
                                print(f"FAILED: {e}")
            
            print("\n✓ Deep exploration complete")
            
    except Exception as e:
        print(f"✗ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
