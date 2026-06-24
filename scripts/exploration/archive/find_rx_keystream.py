#!/usr/bin/env python3
"""
B-Hyve RX Keystream Finder (offline brute over structured IV candidates).

*** SOLVED 2026-06-19 — see rx_joint_brute.py and docs/encryption.md. ***
RX uses the SAME IV as TX (rx_response[:4] || init_tx[4:12]) with a SEPARATE counter
base = uint32_LE(init_tx[16:20]) (the last 4 init bytes, once thought "reserved"). This
brute never found it because the IV was never the variable and the RX counter base sits
~667M away from the TX base, far outside any counter window searched here. Kept for the
historical search record; rx_joint_brute.py is the tool that cracked it from a full
official-app capture.

Context: host→device (TX) frames decrypt with
    IV      = rx_response[:4] || init_tx[4:12]
    counter = uint32_LE(init_tx[12:16])
...but device→host (RX) notifications do NOT decode with that IV/counter, even
though the outer framing is identical and the network key is proven correct (our
TX self-decodes and the valve actuates). So the RX direction uses a different
keystream derivation. This tool recovers it.

Oracle: the outer trailer is `uint16_LE(sum(plaintext) + 0x11 + len)`, which does
NOT depend on the key or on the inner header. So for any candidate (IV, counter)
we decrypt the ciphertext and check whether the recomputed trailer matches the
frame's trailer. A match means we found the right keystream — regardless of what
the inner RX message structure turns out to be.

Search space: the IV is assembled from 4-byte chunks of the session handshake,
so we try ordered arrangements of those chunks (the prime suspect is a seed swap
vs. the TX IV) crossed with a counter window. Structured, not 2^96 brute.

The captured handshake + RX frames from a real session are embedded as defaults,
so you can just run:
    python3 find_rx_keystream.py --device 4         # key from saved config
    python3 find_rx_keystream.py --key <32hex>      # or pass the key directly

The key is only used locally to test candidates; it is never printed.
"""
import argparse
import struct
import sys
from itertools import permutations
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bhyve as bh          # noqa: E402  (config loader + GATT consts)
import decode_frame as dec  # noqa: E402  (parse/decode/pb_format helpers)


# ── Embedded sample (one real session; ciphertext+handshake are not secret) ──
SAMPLE = {
    "init_tx": "0a6aa6d43d7b1a05a4b29200ceae4afa94c54996",
    "rx":      "8075cc8100000000000000000000000000000000",
    # Known-good TX control frame: decodes with TX_IV @ base_counter.
    "tx_control": "1114be44c513026841f58f8b8adb1b694d3ac88f82d79a03",
    # The 5 device→host notifications that would not decode as TX.
    "rx_frames": [
        "114a1a9545e096ada0c50dcfb9903da6087231c4771c5ad17426e422a437ef43"
        "11399a0ae2644b86230ccfc525d95648f392a173a5c4e9111b43d4da84a5676e"
        "919d9c33bc94f02e6774ed306f18",
        "111bac4707b368a840bbfd687c2a5c21aca9f8dd60ca1f8925d0e5a64d9a09",
        "111b598b2f9806d2a025c3c9b2d1fa661f15644be0c6838dac1aae1fecef09",
        "11194959f7517de040ed742a9b4d86e958f35142b4a08c7477ca4a2009",
        "116842cba320709d0a5b4c9ffda96be75f742eedb0e142b3d29d481314a3e4fb"
        "1f6cbc2198a6842c64364a9f194a5bbf5415cd40396d4a88741f52a31af7f30c"
        "356f269d0d98796da47cb615d6d8ed2f953e81c8288cd9d7e64f8f4a64cfa54c5"
        "e8483c531cea9eeeb39da1a",
    ],
}


def keystream(key, iv, counter, nbytes):
    """AES-ECB-as-CTR keystream, one Cipher per call (hot path)."""
    nblocks = (nbytes + 15) // 16
    buf = b"".join(iv + struct.pack("<I", (counter + i) % 0x100000000)
                   for i in range(nblocks))
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(buf)[:nbytes]


def decrypt(key, iv, counter, ct):
    ks = keystream(key, iv, counter, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def trailer_matches(pt, trailer):
    total = (sum(pt) + 0x11 + len(pt)) & 0xFFFF
    return struct.pack("<H", total) == trailer


def build_iv_candidates(init_tx, rx):
    """Named 12-byte IVs from ordered arrangements of handshake chunks.

    Chunks (4 bytes each): A=rx[:4] (device seed), B=init_tx[:4] (host seed),
    C=init_tx[4:8], D=init_tx[8:12], E=init_tx[12:16] (counter seed), Z=zeros.
    TX_IV (known good for host→device) is A+C+D.
    """
    chunks = {
        "A": rx[:4],
        "B": init_tx[:4],
        "C": init_tx[4:8],
        "D": init_tx[8:12],
        "E": init_tx[12:16],
        "Z": b"\x00\x00\x00\x00",
    }
    seen = {}
    for combo in permutations(chunks, 3):
        name = "+".join(combo)
        iv = b"".join(chunks[c] for c in combo)
        seen.setdefault(iv, name)  # first name wins for identical bytes
    return [(name, iv) for iv, name in seen.items()]


def counter_window(base, span):
    """Counters to try: a window around the session base, plus a low window."""
    seen = set()
    order = []
    for c in list(range(base - 64, base + span)) + list(range(0, span)):
        c &= 0xFFFFFFFF
        if c not in seen:
            seen.add(c)
            order.append(c)
    return order


def search(key, init_tx, rx, frames, span):
    base = struct.unpack("<I", init_tx[12:16])[0]
    candidates = build_iv_candidates(init_tx, rx)
    counters = counter_window(base, span)
    print(f"Searching {len(candidates)} IV constructions x {len(counters)} counters "
          f"per frame (base_counter={base})...\n")

    hits = []
    for fi, raw in enumerate(frames):
        parsed = dec.parse_ble_frame(raw)
        if parsed is None:
            print(f"[frame {fi}] not a 0x11 frame, skipping")
            continue
        _, ct, trailer = parsed
        found = None
        for name, iv in candidates:
            for c in counters:
                pt = decrypt(key, iv, c, ct)
                if trailer_matches(pt, trailer):
                    found = (name, iv, c, pt)
                    break
            if found:
                break
        if found:
            name, iv, c, pt = found
            offset = (c - base) & 0xFFFFFFFF
            offset_s = f"base+{offset}" if offset < span else f"{c}"
            print(f"[frame {fi}] HIT  IV={name} ({iv.hex()})  counter={c} ({offset_s})")
            print(f"           plaintext: {pt.hex()}")
            inner = dec.decode_inner(pt)
            if inner:
                print(f"           inner CRC {'OK' if inner['crc_ok'] else 'BAD'}; "
                      f"protobuf: {inner['protobuf'].hex()}")
                print(dec.pb_format(inner["protobuf"]))
            else:
                print(f"           (no AA775A0F header — RX uses a different inner format)")
            hits.append(found)
        else:
            print(f"[frame {fi}] no match across the searched space")
        print()

    return hits


def main():
    ap = argparse.ArgumentParser(description="Recover the B-Hyve RX keystream offline.")
    ap.add_argument("--device", "-d", type=int, help="Config device index for the key")
    ap.add_argument("--key", help="Network key hex (overrides config)")
    ap.add_argument("--span", type=int, default=512,
                    help="Counter window size each side (default 512)")
    args = ap.parse_args()

    if args.key:
        key = bytes.fromhex(args.key)
    else:
        config = bh.load_config()
        devices = config.get("devices") or []
        idx = (args.device or 1) - 1
        if not devices or idx < 0 or idx >= len(devices):
            sys.exit("Pass --key, or --device N matching your saved config.")
        key = bytes.fromhex(devices[idx]["network_key"])
    if len(key) != 16:
        sys.exit(f"Key must be 16 bytes, got {len(key)}")

    init_tx = bytes.fromhex(SAMPLE["init_tx"])
    rx = bytes.fromhex(SAMPLE["rx"])
    frames = [bytes.fromhex(h) for h in SAMPLE["rx_frames"]]

    # Positive control: confirm the oracle + crypto on the known TX frame.
    tx = bytes.fromhex(SAMPLE["tx_control"])
    _, tx_ct, tx_tr = dec.parse_ble_frame(tx)
    tx_iv = rx[:4] + init_tx[4:12]
    base = struct.unpack("<I", init_tx[12:16])[0]
    ok = trailer_matches(decrypt(key, tx_iv, base, tx_ct), tx_tr)
    print(f"oracle self-check on TX control: {'PASS' if ok else 'FAIL'} "
          f"(IV=A+C+D, counter=base)\n")
    if not ok:
        sys.exit("Self-check failed — wrong key for this sample, or a logic bug.")

    hits = search(key, init_tx, rx, frames, args.span)
    print("=" * 60)
    if hits:
        names = {h[0] for h in hits}
        print(f"Found RX keystream(s). IV construction(s): {', '.join(sorted(names))}")
        print("If consistent across frames, that's the device->host scheme.")
    else:
        print("No structured IV matched. Next: the RX counter may be flash-stored")
        print("(arbitrary) with the TX IV — widen --span — or RX uses a derived key.")


if __name__ == "__main__":
    main()
