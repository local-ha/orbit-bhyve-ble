import asyncio
from bleak import BleakClient

MAC = "XX:XX:XX:XX:XX:XX"
UUIDS = [
    "00006c71-fe32-4f58-8b78-98e42b2c047f",
    "00006c72-fe32-4f58-8b78-98e42b2c047f", 
    "00006c73-fe32-4f58-8b78-98e42b2c047f",
    "00006c76-fe32-4f58-8b78-98e42b2c047f",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
]

async def main():
    print(f"Connecting to {MAC}...")
    try:
        async with BleakClient(MAC, timeout=15.0) as client:
            print(f"Connected: {client.is_connected}")
            
            # Get all services
            services = client.services
            print(f"Found {len(services)} services")
            
            for service in services:
                print(f"\nService: {service.uuid}")
                if service.description:
                    print(f"  Description: {service.description}")
                
                for char in service.characteristics:
                    print(f"  Characteristic: {char.uuid}")
                    if char.description:
                        print(f"    Description: {char.description}")
                    print(f"    Properties: {char.properties}")
                    if "read" in char.properties:
                        try:
                            value = await client.read_gatt_char(char.uuid)
                            print(f"    Value: {value.hex() if value else None}")
                        except Exception as e:
                            print(f"    Read error: {e}")
                    
                    for descriptor in char.descriptors:
                        print(f"    Descriptor: {descriptor.uuid}")
                        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
