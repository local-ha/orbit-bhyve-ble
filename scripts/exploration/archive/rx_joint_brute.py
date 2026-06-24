#!/usr/bin/env python3
"""Joint RX-keystream brute against a full app capture (fast, batched AES).

Hypothesis: RX runs its own AES-CTR counter stream (independent of TX), same
network key, advancing by block-count per RX frame. We search the RX base
counter across structured IV candidates and require ALL RX frames to satisfy
the per-frame trailer oracle simultaneously -> ~ (#frames * 16) bits, no noise.

Speed: for each IV we AES-ECB the whole contiguous (iv||ctr) range in one call,
then slide a window over the resulting keystream blocks.
"""
import struct
import sys
from itertools import permutations
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bhyve as bh
import decode_frame as dec
import extract_capture as ex

CAP = sys.argv[1] if len(sys.argv) > 1 else \
    str(Path(__file__).resolve().parent / "captures" / "20260619_app_single_station.json")
KEY = bytes.fromhex(bh.load_config()["devices"][3]["network_key"])

init_tx, init_rx, tx, rx = ex.load(CAP)
init = bytes.fromhex(init_tx)
rxb = bytes.fromhex(init_rx)
base = struct.unpack("<I", init[12:16])[0]

chunks = {"A": rxb[:4], "B": init[:4], "C": init[4:8],
          "D": init[8:12], "E": init[12:16], "Z": b"\x00" * 4}
ivs = {}
for combo in permutations(chunks, 3):
    iv = b"".join(chunks[c] for c in combo)
    ivs.setdefault(iv, "+".join(combo))

frames = []
for _, _, v in rx:
    _, ct, tr = dec.parse_ble_frame(bytes.fromhex(v))
    frames.append((ct, tr, (len(ct) + 15) // 16))
total_blocks = sum(nb for _, _, nb in frames)

# Each frame's block offset within the stream (cumulative).
offsets = []
acc = 0
for _, _, nb in frames:
    offsets.append(acc)
    acc += nb


def trailer_ok(pt, tr):
    return ((sum(pt) + 0x11 + len(pt)) & 0xFFFF) == struct.unpack("<H", tr)[0]


def ks_range(iv, c0, ncounters):
    """AES-ECB(iv||ctr) for ctr in [c0, c0+ncounters): one batched call."""
    buf = b"".join(iv + struct.pack("<I", (c0 + i) & 0xFFFFFFFF)
                   for i in range(ncounters))
    enc = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    return enc.update(buf)  # 16*ncounters bytes


def search_window(lo, span, label):
    ncount = span + total_blocks + 1
    hits = []
    for iv, name in ivs.items():
        ks = ks_range(iv, lo, ncount)
        # slide base counter b from lo..lo+span
        for d in range(span):
            # frame 0 quick filter
            ct0, tr0, _ = frames[0]
            o = d * 16
            pt0 = bytes(a ^ b for a, b in zip(ct0, ks[o:o + len(ct0)]))
            if not trailer_ok(pt0, tr0):
                continue
            ok = True
            for (ct, tr, _), foff in zip(frames, offsets):
                start = (d + foff) * 16
                pt = bytes(a ^ b for a, b in zip(ct, ks[start:start + len(ct)]))
                if not trailer_ok(pt, tr):
                    ok = False
                    break
            if ok:
                b0 = (lo + d) & 0xFFFFFFFF
                print(f"ALL-MATCH IV={name} ({iv.hex()}) rx_base={b0} off={b0-base}")
                hits.append((name, iv, b0))
    print(f"[{label}] done, {len(hits)} joint hit(s)")
    return hits


if __name__ == "__main__":
    print(f"key OK, base_counter(TX)={base}, RX frames={len(frames)}, "
          f"total_blocks={total_blocks}")
    span = int(sys.argv[2]) if len(sys.argv) > 2 else 300000
    allh = []
    allh += search_window(base - span, 2 * span, f"around base +/-{span}")
    allh += search_window(0, span, "low window from 0")
    print("=" * 50)
    print(f"TOTAL joint hits: {len(allh)}")
