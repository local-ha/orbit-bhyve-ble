"""RE probe — two hardware validations, run from a host near a water source.

(A) `station`: does the active/running station show up at `#16.#6.#4`
    (`wateringStatus.currentStationId`) AND/OR `#16.#2.#2.#3.#1`
    (`timerMode.manualModeParams.stationInfo[0].stationId`)? Running a NON-first
    zone (e.g. zone 3 → station 2) disambiguates a real station id from a default 0.

(B) `flow`: dump the raw `#59` FlowSensorData while water flows, INCLUDING 32-bit
    float fields — specifically `#59.#4 currentFlowRateGpm` (a float, wire-type 5),
    which an integer-only decode skips. Tells us whether the device reports gpm
    directly (vs. our tick-slope derivation from `#59.#3`).

Uses `$BHYVE_CONFIG` device list + the `scripts/bhyve.py` primitives (imported).
Real water: durations are short, every run stops explicitly, and (B) always sends
the `#57{#1=0}` unsubscribe so no persistent flow stream is left behind.

    # first, confirm reachability + RSSI:
    python scripts/exploration/scan_rssi.py --time 20

    # A — active-station tracking on the XD (run a non-first zone!):
    python scripts/exploration/probe_station_and_flow.py station --device BT4ValveXD01 --zone 3

    # B — raw #59 flow (incl. the #4 gpm float) on a Gen2 while it waters:
    python scripts/exploration/probe_station_and_flow.py flow --device BTValve03 --zone 1
"""
import argparse
import asyncio
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bhyve as B  # noqa: E402


def _find_device(cfg, name):
    for d in cfg.get("devices", []):
        if d["name"].lower() == name.lower():
            return d
    raise SystemExit(f"device {name!r} not in $BHYVE_CONFIG (have: "
                     + ", ".join(d["name"] for d in cfg.get("devices", [])) + ")")


def _subpath(pb_bytes, *nums):
    """Descend nested length-delimited submessages by field number; return the
    leaf value (int for varint, bytes for wire-2), or None if any hop is missing."""
    cur = pb_bytes
    for i, n in enumerate(nums):
        fields = B.pb_parse(cur)
        if fields is None:
            return None
        val = B._pb_field(fields, n)
        if val is None:
            return None
        cur = val
    return cur


def _dump_16(st16):
    """Print the #16.#6 progress block subfields and the timerMode station path."""
    s = B.pb_parse(st16)
    run_state = B._pb_field(s, 1)
    print(f"    run_state(#16.#1) = {run_state}")
    blk6 = B._pb_field(s, 6)                        # #16.#6 wateringStatus/progress
    if isinstance(blk6, (bytes, bytearray)) and B.pb_parse(blk6) is not None:
        fields = {f: v for f, w, v in B.pb_parse(blk6) if w == 0}
        print(f"    #16.#6 varint subfields: "
              + ", ".join(f"#{f}={v}" for f, v in fields.items()))
        print(f"      -> currentStationId(#4) = {fields.get(4)}   "
              f"remaining(#5) = {fields.get(5)}   total(#7) = {fields.get(7)}")
    station_via_timermode = _subpath(st16, 2, 2, 3, 1)   # #16.#2.#2.#3.#1
    print(f"    timerMode station (#16.#2.#2.#3.#1) = {station_via_timermode}")


def _dump_59(pb_bytes):
    """Print every #59 field with int AND float (wire-5) interpretation."""
    top = B.pb_parse(pb_bytes)
    if top is None:
        return False
    blk = B._pb_field(top, 59)
    if not isinstance(blk, (bytes, bytearray)) or B.pb_parse(blk) is None:
        return False
    print("    #59 FlowSensorData:")
    for f, w, v in B.pb_parse(blk):
        if w == 0:
            print(f"      #{f} varint = {v}")
        elif w == 5 and isinstance(v, (bytes, bytearray)) and len(v) == 4:
            as_f = struct.unpack("<f", bytes(v))[0]
            as_i = struct.unpack("<I", bytes(v))[0]
            print(f"      #{f} i32 = {v.hex()}  (float={as_f:.4f}, uint={as_i})")
        else:
            print(f"      #{f} wire{w} = {v!r}")
    return True


async def _session(mac, key):
    from bleak import BleakClient, BleakScanner
    print(f"Scanning for {mac} ...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        raise SystemExit(f"{mac} not found in range")
    client = BleakClient(device, timeout=15.0)
    await client.__aenter__()
    await B._connect(client)
    collector = B._RxCollector()
    iv, counter = await B._init_session(client, key, collector)
    return client, collector, iv, [counter]


async def _send(client, key, iv, ctr, protobuf):
    msg = B.build_message(protobuf)
    ct, ctr[0] = B.aes_encrypt(key, iv, ctr[0], msg)
    await client.write_gatt_char(
        B.WRITE_CHAR, B.build_ble_frame(ct, B.compute_trailer(msg)), response=False
    )


async def run_station(dev, zone):
    key = bytes.fromhex(dev["network_key"])
    client, collector, iv, ctr = await _session(dev["mac"], key)
    try:
        print(f"\n>>> START zone {zone} (station {zone - 1}) for 150s")
        await _send(client, key, iv, ctr, B.build_start_protobuf(zone - 1, 150))
        await B._await_rx(collector, first_timeout=4.0)
        t0 = time.time()
        for off in (8, 35):
            wait = off - (time.time() - t0)
            if wait > 0:
                await asyncio.sleep(wait)
            base = len(collector.decoded)
            collector.event.clear()
            await _send(client, key, iv, ctr, B.build_request_status_protobuf())
            await B._await_rx(collector, first_timeout=5.0)
            print(f"\n=== read @ t+{time.time() - t0:.0f}s ===")
            shown = False
            for inner in collector.decoded[base:]:
                st16 = B._pb_field(B.pb_parse(inner["protobuf"]), 16)
                if isinstance(st16, (bytes, bytearray)) and B.pb_parse(st16) is not None:
                    _dump_16(st16)
                    shown = True
                    break
            if not shown:
                print("    (no #16 in this read)")
        print("\n>>> STOP")
        await _send(client, key, iv, ctr, B.build_stop_protobuf())
        await B._await_rx(collector, first_timeout=4.0)
        print(f"\nEXPECTATION: for zone {zone}, currentStationId(#16.#6.#4) and the "
              f"timerMode station should both read {zone - 1}.")
    finally:
        await client.stop_notify(B.READ_CHAR)
        await client.__aexit__(None, None, None)


async def run_flow(dev, zone):
    key = bytes.fromhex(dev["network_key"])
    client, collector, iv, ctr = await _session(dev["mac"], key)
    subscribed = False
    try:
        print(f"\n>>> START zone {zone} for 120s (to get water moving)")
        await _send(client, key, iv, ctr, B.build_start_protobuf(zone - 1, 120))
        await B._await_rx(collector, first_timeout=4.0)
        await asyncio.sleep(8)  # let flow ramp up
        print(">>> SUBSCRIBE flow (#57{#1=1000,#2=2})")
        await _send(client, key, iv, ctr, B.build_flow_subscribe_protobuf(1000))
        subscribed = True
        # Collect ~18s of #59 frames, dumping any that carry #59.
        end = time.time() + 18
        seen = set()
        while time.time() < end:
            collector.event.clear()
            try:
                await asyncio.wait_for(collector.event.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                pass
            for inner in collector.decoded:
                key_id = id(inner)
                if key_id in seen:
                    continue
                seen.add(key_id)
                if B._pb_field(B.pb_parse(inner["protobuf"]), 59) is not None:
                    print(f"\n=== #59 @ t+{time.time():.0f} ===")
                    _dump_59(inner["protobuf"])
        print("\nEXPECTATION: if currentFlowRateGpm(#59.#4) is live, a wire-5 float "
              "field #4 appears above, non-zero while water flows.")
    finally:
        if subscribed:
            print("\n>>> UNSUBSCRIBE flow (#57{#1=0}) + STOP")
            await _send(client, key, iv, ctr, B.build_flow_subscribe_protobuf(0))
            await asyncio.sleep(1)
        await _send(client, key, iv, ctr, B.build_stop_protobuf())
        await B._await_rx(collector, first_timeout=4.0)
        await client.stop_notify(B.READ_CHAR)
        await client.__aexit__(None, None, None)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("test", choices=["station", "flow"])
    ap.add_argument("--device", required=True, help="device name from $BHYVE_CONFIG")
    ap.add_argument("--zone", type=int, default=1, help="zone number (1-indexed)")
    args = ap.parse_args()
    cfg = B.load_config()
    dev = _find_device(cfg, args.device)
    print(f"Target {dev['name']} {dev['mac']}")
    if args.test == "station":
        asyncio.run(run_station(dev, args.zone))
    else:
        asyncio.run(run_flow(dev, args.zone))


if __name__ == "__main__":
    main()
