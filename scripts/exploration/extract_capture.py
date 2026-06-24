#!/usr/bin/env python3
"""Extract B-Hyve GATT frames from a tshark JSON export (-T json, raw bytes).

The fe32 data characteristics are resolved **by UUID** from the capture itself, so
this works on any session regardless of how the stack assigned handles:
    6c71 → AES init (WriteReq + ReadResp)
    6c72 → TX (host→device encrypted writes)
    6c73 → RX (device→host notifications)
If UUID resolution fails (e.g. a capture without the GATT discovery), it falls back
to the handles seen in the bundled reference capture (0x000d / 0x000f / 0x0011).

Usage:
    python extract_capture.py [capture.json]   # defaults to the bundled app capture
Prints the init handshake, ordered TX frames, and ordered RX frames as hex.
"""
import json
import sys
from pathlib import Path

DEFAULT_CAP = Path(__file__).resolve().parent / "captures" / "20260619_app_single_station.json"

# Fallback handles (the bundled reference capture) if UUID resolution comes up empty.
FALLBACK = {"6c71": "0x000d", "6c72": "0x000f", "6c73": "0x0011"}


def _first(d, k):
    v = d.get(k)
    return v[0] if isinstance(v, list) else v


def _hex(val):
    return val.replace(":", "").replace(" ", "") if val else ""


def _short_uuid(uuid128):
    """'00:00:6c:71:fe:32:...' → '6c71' (the 16-bit short form), else ''."""
    h = _hex(uuid128)
    return h[4:8] if len(h) >= 8 else ""


def _walk_handle_uuid(node, out):
    """Map every value attribute's handle → its short UUID (first wins).

    Only `btatt.uuid128` (a *value* attribute) is used; `characteristic_uuid128`
    (the 0x2803 declaration) is ignored so we map the value handle the app actually
    reads/writes/notifies on, not the declaration handle.
    """
    if isinstance(node, dict):
        handle = node.get("btatt.handle")
        if handle:
            short = _short_uuid(_find_uuid128(node))
            if short:
                out.setdefault(handle, short)
        for v in node.values():
            _walk_handle_uuid(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_handle_uuid(v, out)


def _find_uuid128(node):
    """Depth-first search for the first `btatt.uuid128` value under `node`."""
    if isinstance(node, dict):
        if "btatt.uuid128" in node:
            return _first(node, "btatt.uuid128")
        for v in node.values():
            found = _find_uuid128(v)
            if found:
                return found
    elif isinstance(node, list):
        for v in node:
            found = _find_uuid128(v)
            if found:
                return found
    return None


def resolve_handles(packets):
    """Return {'6c71': handle, '6c72': handle, '6c73': handle} from the capture."""
    handle_to_uuid = {}
    for p in packets:
        b = p["_source"]["layers"].get("btatt")
        if b:
            _walk_handle_uuid(b, handle_to_uuid)
    uuid_to_handle = {}
    for handle, short in handle_to_uuid.items():
        uuid_to_handle.setdefault(short, handle)
    return {u: uuid_to_handle.get(u, FALLBACK[u]) for u in ("6c71", "6c72", "6c73")}


def load(path):
    data = json.load(open(path))
    h = resolve_handles(data)
    h_init, h_tx, h_rx = h["6c71"], h["6c72"], h["6c73"]
    init_tx = init_rx = None
    tx, rx = [], []
    for p in data:
        l = p["_source"]["layers"]
        b = l.get("btatt")
        if not b:
            continue
        op = _first(b, "btatt.opcode")
        handle = _first(b, "btatt.handle")
        val = _hex(_first(b, "btatt.value"))
        fn = l["frame"]["frame.number"]
        t = l["frame"]["frame.time_relative"]
        if handle == h_init and op == "0x12" and val:      # WriteReq
            init_tx = val
        elif handle == h_init and op == "0x0b" and val:    # ReadResp
            init_rx = val
        elif handle == h_tx and op in ("0x12", "0x52") and val:
            tx.append((fn, t, val))
        elif handle == h_rx and op == "0x1b" and val:      # Notification
            rx.append((fn, t, val))
    return init_tx, init_rx, tx, rx


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_CAP)
    init_tx, init_rx, tx, rx = load(path)
    print(f"init_tx (6c71 write): {init_tx}")
    print(f"init_rx (6c71 resp):  {init_rx}")
    print(f"\nTX frames ({len(tx)}) on 6c72:")
    for fn, t, v in tx:
        print(f"  #{fn} t={t} ({len(v)//2}B) {v}")
    print(f"\nRX frames ({len(rx)}) on 6c73:")
    for fn, t, v in rx:
        print(f"  #{fn} t={t} ({len(v)//2}B) {v}")


if __name__ == "__main__":
    main()
