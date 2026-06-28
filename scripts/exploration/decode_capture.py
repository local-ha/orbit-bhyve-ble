#!/usr/bin/env python3
"""Decode a multi-session B-Hyve BLE capture into per-frame protobuf.

A single long capture of the official app contains *several* BLE connections
(the app reconnects), each with its own AES handshake / IV / counters. This tool
groups packets by device (ACL address), resolves each device's GATT handles by
observed ATT behavior, splits into sessions (one per 6c71 *full* init write), and
decodes every 6c72 TX and 6c73 RX frame to protobuf — timestamped so frames line
up with the operator's action log. Long inner messages are streamed as
consecutive 16-byte CTR blocks each in its own outer frame, so each direction's
ciphertext is reassembled into one continuous stream before decoding.

Input is a tshark JSON export filtered to ATT:
    tshark -r btsnoop_hci.log -Y btatt -T json -x > capture.json

*** Reconnect-resume limitation ***
A FULL handshake = a 20-byte write to 6c71 + a 20-byte read response (carries the
IV seed). On reconnect, the app often does an *empty* 6c71 write+read (len 0) and
the device **resumes a flash-persisted session** (IV + counter) that is NOT
derivable from the capture — so frames sent after such a resume CANNOT be decoded
here (they show as CRC BAD). To capture a target action decodably, keep it in the
session that began with a full handshake: stay connected (don't navigate away /
let it reconnect) between the connect and the action.

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
from collections import Counter, defaultdict
from typing import NamedTuple

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


class Pkt(NamedTuple):
    fn: str
    t_abs: str
    flat: dict       # flattened btatt fields
    src: str | None  # bthci_acl source bd_addr
    dst: str | None  # bthci_acl dest bd_addr


def _packets(path):
    """Yield a Pkt for every ATT packet (with its ACL src/dst addresses)."""
    for p in json.load(open(path)):
        layers = p["_source"]["layers"]
        b = layers.get("btatt")
        if not b:
            continue
        flat = _flatten(b, {})
        acl = _flatten(layers.get("bthci_acl", {}) or {}, {})
        frame = layers.get("frame", {})
        yield Pkt(
            frame.get("frame.number", "?"),
            frame.get("frame.time", ""),
            flat,
            acl.get("bthci_acl.src.bd_addr"),
            acl.get("bthci_acl.dst.bd_addr"),
        )


def group_by_device(packets):
    """Split a capture into per-device groups so handles resolve consistently
    even when the app talked to several valves in one capture.

    The host (phone) address appears in every connection, so it's the most
    common bd_addr; the device is the *other* address on each packet.
    """
    addr_count = Counter()
    for pk in packets:
        for a in (pk.src, pk.dst):
            if a:
                addr_count[a] += 1
    host = addr_count.most_common(1)[0][0] if addr_count else None
    groups = defaultdict(list)
    for pk in packets:
        peer = pk.src if pk.src and pk.src != host else pk.dst
        groups[peer or "?"].append(pk)
    return groups


def resolve_handles(packets):
    """Resolve the init / TX / RX value handles by ATT *behavior*, not UUID.

    UUID-based mapping is unreliable: a characteristic's declaration and its
    descriptors all carry the same 128-bit UUID, so the value handle is easily
    confused with a neighbouring descriptor handle (seen on the Gen2 capture).
    Behavior is unambiguous across devices/firmwares:
      - RX   = the handle that emits notifications (0x1b).
      - init = the read+write AES char (has a read response 0x0b; 20-byte writes).
      - TX   = the highest-volume write handle that isn't init.
    Falls back to the B-Hyve standard handles only if a role can't be observed.
    """
    notif, read_resp, writes, write20 = Counter(), Counter(), Counter(), Counter()
    for pk in packets:
        flat = pk.flat
        op = flat.get("btatt.opcode")
        handle = flat.get("btatt.handle")
        if not handle:
            continue
        vlen = len(_hex(flat.get("btatt.value"))) // 2
        if op == OP_NOTIFY:
            notif[handle] += 1
        elif op == OP_READ_RESP:
            read_resp[handle] += 1
        elif op in (OP_WRITE_REQ, OP_WRITE_CMD):
            writes[handle] += 1
            if vlen == 20:
                write20[handle] += 1

    h_rx = notif.most_common(1)[0][0] if notif else None
    h_init = max(read_resp, key=lambda h: (write20[h], read_resp[h]), default=None)
    tx_cands = {h: c for h, c in writes.items() if h != h_init}
    h_tx = max(tx_cands, key=tx_cands.get, default=None)

    resolved = {U_INIT: h_init, U_TX: h_tx, U_RX: h_rx}
    used_fallback = [u for u, v in resolved.items() if v is None]
    for u in used_fallback:
        resolved[u] = FALLBACK_HANDLES[u]
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
    for pk in packets:
        fn, t_abs, flat = pk.fn, pk.t_abs, pk.flat
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


def _align(key, iv, block, ctr):
    """Find the counter for `block` at/just after the running `ctr`. Fast common
    case first (the next message starts exactly where the last one ended), then a
    wide *forward* sweep to recover from a dropped/garbled frame. Crucially this
    searches from the running counter, not the session base, so re-locking still
    works deep into a long (hundreds of frames) session."""
    c = _lock_counter(key, iv, block, ctr, lo=-2, hi=6)
    if c is None:
        # Real re-lock gaps (a dropped/garbled frame) are small once we search
        # from the running counter; a modest window keeps undecodable traffic
        # (e.g. a background device on the wrong key) from exploding the cost.
        c = _lock_counter(key, iv, block, ctr, lo=-16, hi=512)
    return c


def decode_stream(key, iv, base, frames):
    """Reassemble + decode one direction's frames.

    Long inner messages are streamed as consecutive 16-byte CTR blocks, each
    wrapped in its own `0x11|len|ct|trailer` outer frame, with the counter
    continuing across them. So we strip every frame to its ciphertext, then walk
    the per-direction ciphertext stream message-by-message: align the counter to
    the message's first block, accumulate blocks until the running plaintext holds
    a complete inner message (its `payload_len` says how many bytes), emit it, and
    advance the counter by the blocks consumed.

    Returns rows: (t, frame_label, nbytes, counter, status, protobuf|None).
    """
    items = []  # (fn, t, ct)
    for fn, t, raw in frames:
        p = parse_ble_frame(raw)
        items.append((fn, t, p[1] if p else b""))

    out = []
    ctr = base
    i, n = 0, len(items)
    while i < n:
        start = _align(key, iv, items[i][2], ctr)
        if start is None:
            fn, t, ct = items[i]
            out.append((t, str(fn), len(ct), ctr, "CRC BAD", None))
            ctr += 1              # nudge past the unreadable block, keep scanning
            i += 1
            continue
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
                break                      # desync — emit BAD, re-align next msg
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
            ctr = start + max(1, math.ceil(len(buf) / 16))
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
    groups = group_by_device(packets)
    print(f"{len(packets)} ATT packets across {len(groups)} device(s): "
          f"{', '.join(sorted(groups))}")

    tot_ok = tot_bad = tot = 0
    sess_no = 0
    for peer in sorted(groups, key=lambda a: -len(groups[a])):
        pkts = groups[peer]
        handles, fallback = resolve_handles(pkts)
        print(f"\n########## DEVICE {peer}  ({len(pkts)} ATT pkts) ##########")
        print(f"handles: {handles}"
              + (f"  (fallback for: {', '.join(fallback)})" if fallback else "  (resolved by ATT behavior)"))
        sessions = split_sessions(pkts, handles)
        print(f"-> {len(sessions)} BLE session(s)")
        for s in sessions:
            sess_no += 1
            s.idx = sess_no
            ok, bad, n = print_session(s, key, args.compact, args.only)
            tot_ok += ok; tot_bad += bad; tot += n
    print(f"\n{'='*70}\nTOTAL frames={tot} decoded_ok={tot_ok} failed={tot_bad}")


if __name__ == "__main__":
    sys.exit(main())
