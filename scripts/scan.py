import asyncio
from bleak import BleakScanner

async def main():
    for d in await BleakScanner.discover(timeout=10.0):
        print(d.address, "|", d.name)

asyncio.run(main())