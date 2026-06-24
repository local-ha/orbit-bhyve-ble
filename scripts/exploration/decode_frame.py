#!/usr/bin/env python3
"""
B-Hyve BLE Frame Decoder (offline analysis tool)

Decrypts and pretty-prints a captured on-wire BLE frame so we can verify the
network key, inspect the inner message + protobuf, and diff our generated frames
against frames captured from the official app. Pure offline: no Bluetooth I/O —
feed it hex you already captured (Wireshark / the official app).

The crypto, frame parsing, and protobuf reader live in `bhyve_re.py` (shared by
all the tools); this file is just the CLI + report formatting and re-exports the
shared decode helpers for backward compatibility.

Frame format (see ../../docs/encryption.md):
    outer:  0x11 | len | ciphertext(len) | trailer(2, LE)
    inner:  AA 77 5A 0F | payload_len | 00 | protobuf | CRC16-CCITT(2, LE)

Supply the session IV + counter directly (--iv / --counter), or let the tool
derive them from the 20-byte 6c71 init write + read response (--init / --rx). When
derived, both the host→device (TX) and device→host (RX) counters are tried, so a
captured RX notification decodes without you working out which counter applies.

Examples:
    # Derive IV/counters from the captured init exchange, then decode any frame:
    python3 decode_frame.py --key <32hex> \\
        --init <20-byte 6c71 write hex> --rx <20-byte 6c71 response hex> \\
        11 2e <...ciphertext...> 80 04

    # IV/counter already known:
    python3 decode_frame.py --key <32hex> --iv <24hex> --counter 12345 <frame hex>
"""
import argparse
import struct
import sys

# Shared helpers (the UTF-8 console guard is installed on import of bhyve_re).
from bhyve_re import (  # noqa: F401  (re-exported for archived tools)
    MSG_HEADER,
    compute_trailer,
    crc16_ccitt,
    decode_inner,
    decrypt_frame,
    derive_session,
    parse_ble_frame,
    pb_format,
    pb_parse,
)


# ─── Top-level decode + report ────────────────────────────────────────────

def dump_frame(raw, key, iv, counters):
    """Decode and print a frame. `counters` is an int or an iterable of bases to try."""
    if isinstance(counters, int):
        counters = (counters,)
    print(f"raw frame ({len(raw)}B): {raw.hex()}")
    parsed = parse_ble_frame(raw)
    if parsed is None:
        print("  not a 0x11 BLE frame — nothing to decode")
        return
    length, ct, trailer = parsed
    print(f"  len={length}  trailer={trailer.hex()}")

    counter = pt = inner = None
    for base in counters:
        counter, pt, inner = decrypt_frame(key, iv, ct, base)
        if pt is not None:
            break
    if pt is None:
        print("  decrypt: NO counter in the search window produced the AA775A0F header")
        print("           → wrong network key, or a different IV/counter scheme")
        return
    print(f"  decrypted (@counter={counter}): {pt.hex()}")
    exp = compute_trailer(pt)
    print(f"  trailer: got {trailer.hex()} expected {exp.hex()} "
          f"[{'OK' if exp == trailer else 'MISMATCH'}]")
    if inner is None:
        print("  inner: header matched but the message was truncated/unparseable")
        return
    print(f"  inner CRC: {'OK' if inner['crc_ok'] else 'BAD'} "
          f"(rx={inner['crc_rx']:#06x} calc={inner['crc_calc']:#06x})")
    print(f"  protobuf ({len(inner['protobuf'])}B): {inner['protobuf'].hex()}")
    print(pb_format(inner["protobuf"]))


def _hex(s):
    return bytes.fromhex(s.replace(":", "").replace(" ", ""))


def main():
    ap = argparse.ArgumentParser(
        description="Decode a captured B-Hyve BLE frame (offline).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("frame", nargs="+",
                    help="Outer frame hex (spaces allowed, e.g. '11 2e ... 80 04')")
    ap.add_argument("--key", required=True, help="16-byte network key (hex)")
    ap.add_argument("--iv", help="12-byte session IV (hex)")
    ap.add_argument("--counter", type=int, help="Session-init counter (uint32)")
    ap.add_argument("--init", help="20-byte 6c71 init write (hex) — to derive IV/counters")
    ap.add_argument("--rx", help="20-byte 6c71 read response (hex) — to derive IV")
    args = ap.parse_args()

    key = _hex(args.key)
    if len(key) != 16:
        ap.error(f"--key must be 16 bytes, got {len(key)}")

    if args.iv is not None and args.counter is not None:
        iv = _hex(args.iv)
        counters = (args.counter,)
    elif args.init and args.rx:
        init_tx, rx = _hex(args.init), _hex(args.rx)
        if len(init_tx) < 20 or len(rx) < 4:
            ap.error("--init must be >=20 bytes and --rx >=4 bytes")
        iv, tx_counter, rx_counter = derive_session(init_tx, rx)
        counters = (tx_counter, rx_counter)   # try host→device, then device→host
        print(f"derived IV={iv.hex()} tx_counter={tx_counter} rx_counter={rx_counter}\n")
    else:
        ap.error("provide either (--iv and --counter) or (--init and --rx)")

    if len(iv) != 12:
        ap.error(f"IV must be 12 bytes, got {len(iv)}")

    raw = _hex(" ".join(args.frame))
    dump_frame(raw, key, iv, counters)


if __name__ == "__main__":
    sys.exit(main())
