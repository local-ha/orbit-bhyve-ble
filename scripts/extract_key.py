#!/usr/bin/env python3
"""
B-Hyve Network Key Extractor

Extracts the network_key from a paired Android device via ADB.
The phone/tablet must have the B-Hyve app installed and paired with the sprinkler.

Requirements:
  - ADB installed and device connected via USB
  - Device must be rooted (su access) OR the app data accessible

Usage:
    python3 extract_key.py                    # Auto-detect ADB device
    python3 extract_key.py --device SERIAL    # Specific ADB device
"""

import subprocess
import sys
import json
import re
import argparse


def adb(cmd, device=None):
    full = ["adb"]
    if device:
        full += ["-s", device]
    full += cmd.split()
    result = subprocess.run(full, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip()


def adb_shell(cmd, device=None, root=False):
    if root:
        cmd = f'su -c "{cmd}"'
    return adb(f"shell {cmd}", device)


def find_device():
    out, _ = adb("devices")
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def extract_from_http_cache(device, root=True):
    """Pull HTTP cache files and search for network_key."""
    print("Searching app HTTP cache...")

    # Copy app data to accessible location
    pkg = "com.orbit.orbitsmarthome"
    adb_shell(f"rm -rf /sdcard/bhyve_extract", device)
    adb_shell(f"cp -r /data/data/{pkg}/cache /sdcard/bhyve_extract", device, root=root)

    # Pull to local temp
    import tempfile, os
    tmpdir = tempfile.mkdtemp(prefix="bhyve_")
    adb(f"pull /sdcard/bhyve_extract {tmpdir}", device)
    adb_shell(f"rm -rf /sdcard/bhyve_extract", device)

    # Search all files for network_key
    results = []
    cache_dir = os.path.join(tmpdir, "bhyve_extract")
    if not os.path.exists(cache_dir):
        cache_dir = tmpdir

    for root_dir, dirs, files in os.walk(cache_dir):
        for fname in files:
            fpath = os.path.join(root_dir, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                if "network_key" in content:
                    # Extract JSON containing network_key
                    for match in re.finditer(r'\{[^{}]*"network_key"\s*:\s*"([^"]+)"[^{}]*\}', content):
                        key_b64 = match.group(1)
                        results.append(key_b64)
            except Exception:
                pass

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return list(set(results))


def extract_from_mmkv(device, root=True):
    """Search MMKV storage for network_key."""
    print("Searching app MMKV storage...")

    pkg = "com.orbit.orbitsmarthome"
    adb_shell(f"rm -rf /sdcard/bhyve_mmkv", device)
    adb_shell(f"cp -r /data/data/{pkg}/files/mmkv /sdcard/bhyve_mmkv", device, root=root)

    import tempfile, os
    tmpdir = tempfile.mkdtemp(prefix="bhyve_mmkv_")
    adb(f"pull /sdcard/bhyve_mmkv {tmpdir}", device)
    adb_shell(f"rm -rf /sdcard/bhyve_mmkv", device)

    results = []
    mmkv_dir = os.path.join(tmpdir, "bhyve_mmkv")
    if not os.path.exists(mmkv_dir):
        mmkv_dir = tmpdir

    for root_dir, dirs, files in os.walk(mmkv_dir):
        for fname in files:
            if fname.endswith(".crc"):
                continue
            fpath = os.path.join(root_dir, fname)
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                # Search for network_key in binary data
                text = data.decode("utf-8", errors="ignore")
                for match in re.finditer(r'"network_key"\s*:\s*"([^"]+)"', text):
                    results.append(match.group(1))
            except Exception:
                pass

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return list(set(results))


def scan_for_bhyve_devices():
    """Scan BLE for B-Hyve devices (advertised as 'ASR')."""
    print("\nTo find your device's MAC address, look for BLE devices named 'ASR'.")
    print("You can scan with: bluetoothctl → scan on → look for 'ASR'")
    print("Or use: python3 -c \"import asyncio; from bleak import BleakScanner; asyncio.run(BleakScanner.discover())\"")


def main():
    parser = argparse.ArgumentParser(description="Extract B-Hyve network key from paired Android device")
    parser.add_argument("--device", "-d", help="ADB device serial number")
    parser.add_argument("--no-root", action="store_true", help="Try without root (may not work)")
    args = parser.parse_args()

    # Find device
    if args.device:
        devices = [args.device]
    else:
        devices = find_device()
        if not devices:
            print("ERROR: No ADB devices found. Connect your Android device via USB and enable USB debugging.")
            sys.exit(1)
        print(f"Found ADB device(s): {', '.join(devices)}")

    device = devices[0]
    root = not args.no_root

    # Check if app is installed
    out, _ = adb_shell(f"pm list packages | grep orbit", device)
    if "orbitsmarthome" not in out:
        print(f"ERROR: B-Hyve app (com.orbit.orbitsmarthome) not installed on {device}")
        print("Install the app, pair with your sprinkler, then run this again.")
        sys.exit(1)

    print(f"B-Hyve app found on {device}")
    print()

    # Try extraction methods
    keys = []

    keys += extract_from_http_cache(device, root)
    if not keys:
        keys += extract_from_mmkv(device, root)

    if keys:
        import base64
        print(f"\n{'='*60}")
        print(f"NETWORK KEY FOUND!")
        print(f"{'='*60}")
        for key_b64 in keys:
            key_hex = base64.b64decode(key_b64).hex()
            print(f"\n  Base64:  {key_b64}")
            print(f"  Hex:     {key_hex}")
            print(f"\nTo use with bhyve_control.py, edit the NETWORK_KEY line:")
            print(f'  NETWORK_KEY = bytes.fromhex("{key_hex}")')
        print()
        scan_for_bhyve_devices()
    else:
        print("\nERROR: Could not find network_key in app data.")
        print("Make sure the B-Hyve app is installed, paired with the device,")
        print("and has been used at least once (to cache the API response).")
        if not root:
            print("\nTip: Try with root access (remove --no-root flag)")


if __name__ == "__main__":
    main()
