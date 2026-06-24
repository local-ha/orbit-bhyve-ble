#!/usr/bin/env python3
"""
B-Hyve RSSI survey — scan and report signal strength for the known valves.

Purpose: map where each valve's signal is reachable (and how strong) from a
given spot, to decide where ESP32 BT proxies need to go for full HA coverage.
Run it from several locations; compare the RSSI column.

Reads the device list from the configured B-Hyve config (via $BHYVE_CONFIG) so
valves are shown by name. Anything not in the config is listed below as "other"
so you can still see what's around. Higher (less negative) RSSI = stronger.

    python3 scan_rssi.py            # 10s scan
    python3 scan_rssi.py --time 20  # longer scan (catches slow advertisers)
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bhyve as bh  # noqa: E402  (config loader)


async def survey(scan_time):
    from bleak import BleakScanner

    known = {}
    for d in (bh.load_config().get("devices") or []):
        mac = (d.get("mac") or "").upper()
        if mac:
            known[mac] = d.get("name", mac)

    found = await BleakScanner.discover(timeout=scan_time, return_adv=True)
    # address -> rssi
    seen = {addr.upper(): adv.rssi for addr, (_dev, adv) in found.items()}

    print(f"\n=== Known B-Hyve devices ({scan_time:.0f}s scan) ===")
    print(f"  {'name':<14} {'mac':<19} {'rssi':>6}  bar")
    for mac, name in known.items():
        rssi = seen.get(mac)
        if rssi is None:
            print(f"  {name:<14} {mac:<19} {'--':>6}  (not seen)")
        else:
            bars = max(0, min(20, (rssi + 100) // 3))  # ~-100..-40 -> 0..20
            print(f"  {name:<14} {mac:<19} {rssi:>6}  {'#' * bars}")

    others = sorted(((r, a) for a, r in seen.items() if a not in known),
                    reverse=True)
    print(f"\n=== Other BLE devices seen ({len(others)}) ===")
    for rssi, addr in others:
        print(f"  {addr:<19} {rssi:>6}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--time", "-t", type=float, default=10.0,
                    help="Scan duration in seconds (default 10)")
    args = ap.parse_args()
    asyncio.run(survey(args.time))


if __name__ == "__main__":
    main()
