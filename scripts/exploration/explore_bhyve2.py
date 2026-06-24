import asyncio
from bleak import BleakClient
import sys

MAC = "XX:XX:XX:XX:XX:XX"

# Key characteristics from discovery
CHAR_WRITE = "00006c76-fe32-4f58-8b78-98e42b2c047f"  # Write only
CHAR_NOTIFY = "00006c73-fe32-4f58-8b78-98e42b2c047f"  # Notify only
CHAR_RW = "00006c71-fe32-4f58-8b78-98e42b2c047f"      # Read/Write
CHAR_WRITE_FAST = "00006c72-fe32-4f58-8b78-98e42b2c047f"  # Write/Write without response
CHAR_DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"  # Standard device name

def notification_handler(sender, data):
    print(f"NOTIFICATION from {sender}: {data.hex()}")

async def main():
    print(f"Connecting to {MAC}...")
    try:
        async with BleakClient(MAC, timeout=30.0) as client:
            print(f"✓ Connected: {client.is_connected}")
            
            # 1. Read device name
            print("\n1. Reading device name...")
            try:
                name_bytes = await client.read_gatt_char(CHAR_DEVICE_NAME)
                name = name_bytes.decode("utf-8", errors="ignore")
                print(f"   Device Name: {name}")
            except Exception as e:
                print(f"   Failed to read name: {e}")
            
            # 2. Try reading from read/write characteristic
            print("\n2. Reading from RW characteristic...")
            try:
                data = await client.read_gatt_char(CHAR_RW)
                print(f"   {CHAR_RW}: {data.hex()} (length: {len(data)})")
                if len(data) > 0:
                    try:
                        ascii_str = data.decode("utf-8", errors="ignore")
                        print(f"   As ASCII: {ascii_str}")
                    except:
                        pass
            except Exception as e:
                print(f"   Failed to read: {e}")
            
            # 3. Enable notifications
            print("\n3. Enabling notifications...")
            try:
                await client.start_notify(CHAR_NOTIFY, notification_handler)
                print(f"   Notifications enabled for {CHAR_NOTIFY}")
                print("   Waiting 3 seconds for any notifications...")
                await asyncio.sleep(3)
                await client.stop_notify(CHAR_NOTIFY)
                print("   Notifications stopped")
            except Exception as e:
                print(f"   Failed to enable notifications: {e}")
            
            # 4. Test writes with simple patterns
            print("\n4. Testing writes...")
            test_payloads = [
                bytes([0x01]),  # Simple on
                bytes([0x00]),  # Simple off
                bytes([0x01, 0x00, 0x00, 0x00]),  # Maybe valve 1 on
                bytes([0x00, 0x01, 0x00, 0x00]),  # Maybe valve 2 on
                bytes([0xAA, 0x55]),  # Test pattern
            ]
            
            for char_uuid in [CHAR_WRITE, CHAR_WRITE_FAST, CHAR_RW]:
                print(f"\n   Testing writes to {char_uuid}:")
                for i, payload in enumerate(test_payloads):
                    try:
                        print(f"     Test {i+1}: {payload.hex()} -> ", end="")
                        await client.write_gatt_char(char_uuid, payload)
                        print("SUCCESS")
                        await asyncio.sleep(0.5)  # Small delay
                    except Exception as e:
                        print(f"FAILED: {e}")
            
            # 5. Try reading again after writes
            print("\n5. Reading RW characteristic again...")
            try:
                data = await client.read_gatt_char(CHAR_RW)
                print(f"   {CHAR_RW}: {data.hex()} (length: {len(data)})")
                if len(data) > 0:
                    try:
                        ascii_str = data.decode("utf-8", errors="ignore")
                        print(f"   As ASCII: {ascii_str}")
                    except:
                        pass
            except Exception as e:
                print(f"   Failed to read: {e}")
            
            print("\n✓ Exploration complete")
            
    except Exception as e:
        print(f"✗ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
