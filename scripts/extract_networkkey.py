#!/usr/bin/env python3
"""
Extract networkKey from B-Hyve Android app storage.

Run on <your_linux_host> AFTER pairing the app with the device on the Android tablet.
Requires: ADB connected to Lenovo (<TABLET_SERIAL>), app installed and paired.

Usage:
  python3 extract_networkkey.py

What it does:
  1. Pulls all app data from the Android tablet
  2. Searches MMKV, SharedPreferences, SQLite for networkKey
  3. Looks for any 6-32 byte sequences near the device MAC
"""
import subprocess
import os
import struct
import sys

ADB = "adb"
DEVICE = "<TABLET_SERIAL>"
PACKAGE = "com.orbit.orbitsmarthome"
TARGET_MAC = bytes.fromhex("446755D46834")
PULL_DIR = "/tmp/bhyve_app_data"
APP_DATA = f"/data/data/{PACKAGE}"


def adb(cmd, check=False):
    full = f"{ADB} -s {DEVICE} {cmd}"
    result = subprocess.run(full, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"ADB error: {result.stderr}")
    return result.stdout.strip(), result.stderr.strip()


def adb_root(cmd):
    out, err = adb(f'shell su -c "{cmd}"')
    return out, err


def pull_app_data():
    print(f"Pulling app data from {PACKAGE}...")
    os.makedirs(PULL_DIR, exist_ok=True)

    # Copy to world-readable location first
    adb_root(f"cp -r {APP_DATA} /sdcard/orbit_data")

    # Pull from sdcard
    subprocess.run(
        f"{ADB} -s {DEVICE} pull /sdcard/orbit_data {PULL_DIR}",
        shell=True, capture_output=True
    )
    adb("shell rm -rf /sdcard/orbit_data")
    print(f"  Pulled to {PULL_DIR}/")


def search_binary_for_mac(filepath):
    """Search a binary file for sequences near the device MAC."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return []

    results = []
    idx = 0
    while True:
        pos = data.find(TARGET_MAC, idx)
        if pos == -1:
            break
        # Extract context around MAC (potential networkKey nearby)
        start = max(0, pos - 32)
        end = min(len(data), pos + 48)
        context = data[start:end]
        results.append({
            "offset": pos,
            "context": context,
            "before": data[start:pos],
            "after": data[pos + 6:end],
        })
        idx = pos + 1
    return results


def search_mmkv(mmkv_dir):
    """Parse MMKV files looking for networkKey."""
    if not os.path.exists(mmkv_dir):
        print(f"  MMKV dir not found: {mmkv_dir}")
        return

    for fname in os.listdir(mmkv_dir):
        fpath = os.path.join(mmkv_dir, fname)
        print(f"  MMKV file: {fname}")
        hits = search_binary_for_mac(fpath)
        if hits:
            print(f"    Found {len(hits)} MAC reference(s)!")
            for h in hits:
                print(f"    Offset: 0x{h['offset']:x}")
                print(f"    Before MAC: {h['before'].hex()}")
                print(f"    MAC: {TARGET_MAC.hex()}")
                print(f"    After MAC:  {h['after'].hex()}")


def search_shared_prefs(prefs_dir):
    """Search SharedPreferences XML files."""
    if not os.path.exists(prefs_dir):
        print(f"  SharedPrefs dir not found: {prefs_dir}")
        return

    for fname in os.listdir(prefs_dir):
        if not fname.endswith(".xml"):
            continue
        fpath = os.path.join(prefs_dir, fname)
        try:
            with open(fpath, "r", errors="ignore") as f:
                content = f.read()
            mac_str = ":".join(f"{b:02x}" for b in TARGET_MAC).upper()
            if mac_str in content.upper() or "networkKey" in content or "network_key" in content:
                print(f"  Found reference in {fname}:")
                for line in content.splitlines():
                    if any(x in line.lower() for x in ["network", "key", "mac", "address", "446755"]):
                        print(f"    {line.strip()}")
        except Exception as e:
            print(f"  Error reading {fname}: {e}")


def search_databases(db_dir):
    """Search SQLite databases."""
    if not os.path.exists(db_dir):
        print(f"  Database dir not found: {db_dir}")
        return

    for fname in os.listdir(db_dir):
        if not fname.endswith(".db"):
            continue
        fpath = os.path.join(db_dir, fname)
        hits = search_binary_for_mac(fpath)
        if hits:
            print(f"  SQLite {fname}: {len(hits)} MAC reference(s)")
            for h in hits:
                print(f"    After MAC: {h['after'].hex()}")


def search_files_dir(files_dir):
    """Walk all files recursively looking for MAC."""
    if not os.path.exists(files_dir):
        print(f"  Files dir not found: {files_dir}")
        return

    for root, dirs, files in os.walk(files_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            hits = search_binary_for_mac(fpath)
            if hits:
                relpath = os.path.relpath(fpath, files_dir)
                print(f"  {relpath}: {len(hits)} MAC reference(s)")
                for h in hits:
                    print(f"    Before: {h['before'][-16:].hex()}")
                    print(f"    After:  {h['after'][:16].hex()}")


def main():
    print("=== B-Hyve networkKey Extractor ===\n")

    # Check device connected
    out, _ = adb("devices")
    if DEVICE not in out:
        print(f"ERROR: Device {DEVICE} not connected to ADB")
        print("Connect Android tablet to Fedora USB and enable USB debugging")
        sys.exit(1)

    print(f"Device {DEVICE} connected\n")

    # Check app installed
    out, _ = adb(f"shell pm list packages | grep {PACKAGE}")
    if PACKAGE not in out:
        print(f"ERROR: {PACKAGE} not installed on device")
        print("Install the B-Hyve app and pair with device first")
        sys.exit(1)

    print(f"App {PACKAGE} is installed\n")

    # Pull data
    pull_app_data()

    base = os.path.join(PULL_DIR, "orbit_data")

    print("\n=== Searching MMKV storage ===")
    search_mmkv(os.path.join(base, "files", "mmkv"))

    print("\n=== Searching SharedPreferences ===")
    search_shared_prefs(os.path.join(base, "shared_prefs"))

    print("\n=== Searching Databases ===")
    search_databases(os.path.join(base, "databases"))

    print("\n=== Searching all files ===")
    search_files_dir(base)

    print("\nDone. If no results found, ensure device is paired with the B-Hyve.")
    print("The networkKey is only stored after a successful pairing.")


if __name__ == "__main__":
    main()
