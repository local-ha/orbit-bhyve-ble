#!/usr/bin/env python3
"""Decode a multi-session B-Hyve BLE capture into per-frame protobuf.

A single long capture of the official app contains *several* BLE connections
(the app reconnects), each with its own AES handshake / IV / counters. This tool
splits the capture into sessions (one per 6c71 init write), derives each
session's IV + TX/RX counters from its handshake, and decodes every 6c72 TX and
6c73 RX frame to protobuf — timestamped so frames line up with the operator's
action log.

Input is a tshark JSON export filtered to ATT:
    tshark -r btsnoop_hci.log -Y btatt -T json -x > capture.json

Characteristic handles are resolved by 128-bit UUID when the GATT discovery is
present in the capture; otherwise we fall back to the B-Hyve standard handles
(0x0012 / 0x0014 / 0x0016) observed on fw0107 (XD) and fw0111 (Gen2).

Crypto/decode primitives are reused from the shipping CLI via bhyve_re (single
source of truth); this tool only adds capture parsing + session segmentation.

Usage:
    python decode_capture.py capture.json --device 1     # key from $BHYVE_CONFIG
    python decode_capture.py capture.json --key <32hex>
    python decode_capture.py capture.json --device 1 --only tx --compact
"""
import argparse
import json
import math
import sys

from bhyve_re import (
    MSG_HEADER,
    aes_ctr,
    decode_inner,
    derive_session,
    parse_ble_frame,
    pb_format,
    resolve_device,
)

# B-Hyve custom data service fe32. Short UUIDs of the three characteristics.
U_INIT, U_TX, U_RX = "6c71", "6c72", "6c73"
# Fallback value-attribute handles (fw0107/0111) when no uuid128 is in the capture.
FALLBACK_HANDLES = {U_INIT: "0x0012", U_TX: "0x0014", U_RX: "0x0016"}

OP_WRITE_REQ, OP_WRITE_CMD = "0x12", "0x52"   # host->device writes
OP_READ_RESP = "0x0b"                          # device read response (init_rx)
OP_NOTIFY = "0x1b"                             # device->host notification


def _flatten(node, out):
    """Collect every scalar leaf key->value under a btatt subtree (first wins)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(v, (dict, list)):
                out.setdefault(k, v)
            else:
                _flatten(v, out)
    elif isinstance(node, list):
        for v in node:
            _flatten(v, out)
    return out


def _hex(val):
    return val.replace(":", "").replace(" ", "") if isinstance(val, str) else ""


def _short_uuid(uuid128):
    h = _hex(uuid128)
    return h[4:8] if len(h) >= 8 else ""


def _packets(path):
    """Yield (frame_no, time_abs, time_rel, flat_btatt) for every ATT packet."""
    for p in json.load(open(path)):
        layers = p["_source"]["layers"]
        b = layers.get("btatt")
        if not b:
            continue
        flat = _flatten(b, {})
        frame = layers.get("frame", {})
        yield (
            frame.get("frame.number", "?"),
            frame.get("frame.time", ""),
            frame.get("frame.time_relative", ""),
            flat,
        )


def resolve_handles(packets):
    """Map the three short UUIDs to value handles, by uuid128 if present else fallback."""
    uuid_to_handle = {}
    for *_x, flat in packets:
        handle = flat.get("btatt.handle")
        u128 = next((v for k, v in flat.items() if "uuid128" in k and isinstance(v, str)), None)
        if handle and u128:
            short = _short_uuid(u128)
            if short in (U_INIT, U_TX, U_RX):
                uuid_to_handle.setdefault(short, handle)
    resolved = {u: uuid_to_handle.get(u, FALLBACK_HANDLES[u]) for u in (U_INIT, U_TX, U_RX)}
    used_fallback = [u for u in (U_INIT, U_TX, U_RX) if u not in uuid_to_handle]
    return resolved, used_fallback


class Session:
    __slots__ = ("idx", "t0", "init_tx", "init_rx", "tx", "rx")

    def __init__(self, idx, t0, init_tx):
        self.idx = idx
        self.t0 = t0
        self.init_tx = init_tx
        self.init_rx = None
        self.tx = []   # (frame_no, t_abs, raw)
        self.rx = []


def split_sessions(packets, handles):
    """Group frames into sessions. A new session begins at each init (6c71) write."""
    h_init, h_tx, h_rx = handles[U_INIT], handles[U_TX], handles[U_RX]
    sessions = []
    cur = None
    for fn, t_abs, _t_rel, flat in packets:
        op = flat.get("btatt.opcode")
        handle = flat.get("btatt.handle")
        raw = _hex(flat.get("btatt.value"))
        if not handle:
            continue
        if handle == h_init and op in (OP_WRITE_REQ, OP_WRITE_CMD) and len(raw) >= 40:
            cur = Session(len(sessions) + 1, t_abs, bytes.fromhex(raw))
            sessions.append(cur)
        elif handle == h_init and op == OP_READ_RESP and raw and cur and cur.init_rx is None:
            cur.init_rx = bytes.fromhex(raw)
        elif handle == h_tx and op in (OP_WRITE_REQ, OP_WRITE_CMD) and raw and cur:
            cur.tx.append((fn, t_abs, bytes.fromhex(raw)))
        elif handle == h_rx and op == OP_NOTIFY and raw and cur:
            cur.rx.append((fn, t_abs, bytes.fromhex(raw)))
    return sessions


def _clock(t_abs):
    """'2026-06-28T13:15:23.762048000-0400' -> '13:15:23.762' for terse output."""
    if "T" in t_abs:
        hms = t_abs.split("T", 1)[1]
        return hms[:12]
    return t_abs


def _lock_counter(key, iv, ct_block, base, lo=-8, hi=4096):
    """Find the counter near `base` whose keystream makes `ct_block` start a valid
    inner message (AA775A0F). Returns the counter or None."""
    for d in range(lo, hi):
        c = (base + d) % 0x100000000
        if aes_ctr(key, iv, c, ct_block)[0][:4] == MSG_HEADER:
            return c
    return None


def decode_stream(key, iv, base, frames):
    """Reassemble + decode one direction's frames.

    Long inner messages are streamed as consecutive 16-byte CTR blocks, each
    wrapped in its own `0x11|len|ct|trailer` outer frame, with the counter
    continuing across them. So we strip every frame to its ciphertext, then walk
    the per-direction ciphertext stream message-by-message: accumulate blocks
    until the running plaintext holds a complete inner message (its `payload_len`
    says how many bytes), emit it, and advance the counter by the blocks consumed.

    The first message's start counter is locked with a sweep (the capture's base
    is exact in practice); a CRC failure forces a re-lock for the next message so
    a dropped frame can't desync the rest of the session.

    Returns rows: (t, frame_label, nbytes, counter, status, protobuf|None).
    """
    items = []  # (fn, t, ct)
    for fn, t, raw in frames:
        p = parse_ble_frame(raw)
        items.append((fn, t, p[1] if p else b""))

    out = []
    ctr = base
    locked = False
    i, n = 0, len(items)
    while i < n:
        if not locked:
            c = _lock_counter(key, iv, items[i][2], base)
            if c is not None:
                ctr = c
                locked = True
        start = ctr
        buf = b""
        first_fn, first_t, _ = items[i]
        last_fn = first_fn
        total = None
        pt = b""
        while i < n:
            fn, _t, ct = items[i]
            buf += ct
            last_fn = fn
            i += 1
            pt = aes_ctr(key, iv, start, buf)[0]
            if pt[:4] != MSG_HEADER:
                break                      # desync — emit BAD, re-lock next msg
            if len(pt) >= 5:
                total = pt[4] + 6          # inner = AA775A0F|len|00|pb|crc
                if len(buf) >= total:
                    break
        inner = decode_inner(pt[:total]) if total else None
        label = f"{first_fn}" if first_fn == last_fn else f"{first_fn}..{last_fn}"
        if inner and inner["crc_ok"]:
            ctr = start + math.ceil(len(buf) / 16)
            out.append((first_t, label, total, start, "ok", inner["protobuf"]))
        else:
            locked = False
            out.append((first_t, label, len(buf), start, "CRC BAD", None))
    return out


def print_session(s, key, compact, only):
    print(f"\n{'='*70}\nSESSION {s.idx}   start {_clock(s.t0)}   "
          f"TX={len(s.tx)} RX={len(s.rx)}\n{'='*70}")
    if not s.init_tx or not s.init_rx:
        print("  ! incomplete handshake (missing init write/response) — cannot decode")
        return (0, 0, 0)
    iv, tx_ctr, rx_ctr = derive_session(s.init_tx, s.init_rx)
    print(f"  init_tx={s.init_tx.hex()}")
    print(f"  init_rx={s.init_rx.hex()}")
    print(f"  iv={iv.hex()} tx_ctr={tx_ctr} rx_ctr={rx_ctr}")

    rows = []
    if only in (None, "tx"):
        rows += [("TX", r) for r in decode_stream(key, iv, tx_ctr, s.tx)]
    if only in (None, "rx"):
        rows += [("RX", r) for r in decode_stream(key, iv, rx_ctr, s.rx)]
    rows.sort(key=lambda x: x[1][0])  # by absolute time

    ok = bad = 0
    for direction, (t, fn, n, ctr, status, pb) in rows:
        ok += status == "ok"
        bad += status != "ok"
        head = f"  [{_clock(t)}] {direction} #{fn} ({n}B) ctr={ctr} {status}"
        print(head)
        if pb is not None and not compact:
            print(pb_format(pb))
    return (ok, bad, len(rows))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json", help="tshark JSON (-Y btatt -T json -x)")
    ap.add_argument("--device", type=int, default=1, help="config device index (default 1)")
    ap.add_argument("--mac", help="override device MAC")
    ap.add_argument("--key", help="override 16-byte network key (hex)")
    ap.add_argument("--only", choices=("tx", "rx"), help="decode only one direction")
    ap.add_argument("--compact", action="store_true", help="one line per frame (no protobuf dump)")
    args = ap.parse_args()

    _name, _mac, key_hex = resolve_device(args)
    key = bytes.fromhex(key_hex)

    packets = list(_packets(args.json))
    handles, fallback = resolve_handles(packets)
    print(f"handles: {handles}"
          + (f"  (fallback for: {', '.join(fallback)})" if fallback else "  (resolved by UUID)"))
    sessions = split_sessions(packets, handles)
    print(f"{len(packets)} ATT packets -> {len(sessions)} BLE session(s)")

    tot_ok = tot_bad = tot = 0
    for s in sessions:
        ok, bad, n = print_session(s, key, args.compact, args.only)
        tot_ok += ok; tot_bad += bad; tot += n
    print(f"\n{'='*70}\nTOTAL frames={tot} decoded_ok={tot_ok} failed={tot_bad}")


if __name__ == "__main__":
    sys.exit(main())
