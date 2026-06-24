#!/usr/bin/env python3
"""
B-Hyve Live Test — send a real command (or a start→hold→stop sequence) and decode
whatever comes back. Replaces the old retest_live.py + verify_stop.py (one tool now).

Built on bhyve_re.LiveSession, so it uses the shipping CLI's exact frame
construction and session-init, captures RX notifications on 6c73, and decodes them
with the *RX* counter (device→host). Both the sent frames and the RX burst are
printed via decode_frame's report.

Modes:
  default        send one command (start, or --stop) and watch for RX.
  --stop-verify  start with a long on-device timer, hold, then STOP within the SAME
                 session (continued counter) — proves the stop command closes the
                 valve early (well before the safety auto-close).
  --dry-run      no Bluetooth: build + self-decode the frames offline (smoke test).

Usage:
    python3 live_test.py --device 2 --zone 1 --duration 30
    python3 live_test.py --device 2 --stop
    python3 live_test.py --device 2 --stop-verify --hold 15 --duration 120
    python3 live_test.py --mac 44:67:55:XX:XX:XX --key <32hex> --zone 1
    python3 live_test.py --device 2 --dry-run        # offline; no hardware needed

⚠️  Real water on a real spigot — use a short duration; the device enforces it.
"""
import argparse
import asyncio
import os
import sys

import bhyve_re as bre
import decode_frame as dec


def _print_tx(label, frame, key, iv, counter):
    print(f"\n=== TX ({label}) @ counter={counter} ===")
    dec.dump_frame(frame, key, iv, counter)


def _print_rx(session):
    print(f"\n=== RX ({len(session.rx_frames)} notification(s)) ===")
    any_decoded = False
    for i, (dt, raw) in enumerate(session.rx_frames):
        print(f"\n[{i}] +{dt:.2f}s")
        dec.dump_frame(raw, session.key, session.iv, session.rx_counter)
        _, pt, _ = session.decode_rx(raw)
        any_decoded = any_decoded or pt is not None
    return any_decoded


def dry_run(zone, duration):
    """Offline: derive a synthetic session, build start+stop, self-decode."""
    key = os.urandom(16)
    init_tx = bytearray(os.urandom(20))
    init_tx[11] = 0x00
    iv, tx_counter, rx_counter = bre.derive_session(bytes(init_tx), os.urandom(4))
    print(f"dry-run synthetic session: iv={iv.hex()} tx_counter={tx_counter} "
          f"rx_counter={rx_counter}\n")

    used = tx_counter
    frame, tx_counter = bre.build_command_frame(
        key, iv, tx_counter, bre.bh.build_start_protobuf(zone - 1, duration))
    _print_tx(f"Zone {zone} ON {duration}s", frame, key, iv, used)
    used = tx_counter
    frame, tx_counter = bre.build_command_frame(
        key, iv, tx_counter, bre.bh.build_stop_protobuf())
    _print_tx("STOP", frame, key, iv, used)
    print("\n=== Verdict ===")
    print("  Both frames self-decoded above (trailer + CRC OK) → the encode/decode")
    print("  codec path is intact. (No Bluetooth was used.)")


async def run_oneshot(name, mac, key, action, zone, duration):
    print(f"B-Hyve live test — {name}  ({mac})")
    print(f"Scanning for {mac} (press the device button if it's asleep)...")
    async with bre.LiveSession(mac, key) as s:
        print(f"Connected (MTU={s.mtu}). Session iv={s.iv.hex()} "
              f"tx_counter={s.tx_counter} rx_counter={s.rx_counter}")
        if action == "stop":
            protobuf, label = bre.bh.build_stop_protobuf(), "STOP"
        else:
            protobuf, label = bre.bh.build_start_protobuf(zone - 1, duration), \
                f"Zone {zone} ON {duration}s"
        used = s.tx_counter
        frame = await s.send(protobuf)
        _print_tx(label, frame, s.key, s.iv, used)
        print("\nSent. Waiting 6s for any RX notification...")
        await asyncio.sleep(6.0)

    any_decoded = _print_rx(s)
    print("\n=== Verdict ===")
    if not s.rx_frames:
        print("  Zero RX. → notification-path / sleep behavior. Get an app capture.")
    elif any_decoded:
        print("  RX decoded cleanly with the RX counter → two-way protocol confirmed.")
    else:
        print("  RX received but did NOT decode with the derived RX counter — unexpected")
        print("  now that RX is solved; re-check the capture / counter derivation.")
    print("\n  Did the valve physically actuate? That's the ground truth this can't see.")


async def run_stop_verify(name, mac, key, zone, duration, hold):
    print(f"B-Hyve stop-verify — {name}  ({mac})")
    print(f"Scanning for {mac} (press the device button if it's asleep)...")
    async with bre.LiveSession(mac, key) as s:
        print(f"Connected (MTU={s.mtu}). Session iv={s.iv.hex()} "
              f"tx_counter={s.tx_counter} rx_counter={s.rx_counter}")

        used = s.tx_counter
        frame = await s.send(bre.bh.build_start_protobuf(zone - 1, duration))
        _print_tx(f"START zone {zone}, {duration}s", frame, s.key, s.iv, used)
        print(f"\n>>> Sent START. VALVE SHOULD OPEN NOW. Holding {hold}s before STOP...")
        await asyncio.sleep(hold)

        used = s.tx_counter   # continued counter — the real CLI path
        frame = await s.send(bre.bh.build_stop_protobuf())
        _print_tx("STOP (continued counter)", frame, s.key, s.iv, used)
        print("\n>>> Sent STOP. VALVE SHOULD CLOSE NOW. Watching 6s for RX...")
        await asyncio.sleep(6.0)

    _print_rx(s)
    print("\n=== Verdict (physical observation required) ===")
    print(f"  Did the valve OPEN ~t=0 and CLOSE ~t={hold}s, well before {duration}s?")
    print("  CLOSE-at-hold = stop command works. CLOSE-at-duration = only the")
    print("  on-device timer fired (stop had no effect).")


def main():
    ap = argparse.ArgumentParser(
        description="Live B-Hyve command test with RX capture + decode.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--device", "-d", type=int, help="Device index in config (1-based)")
    ap.add_argument("--mac", help="Override MAC (requires --key)")
    ap.add_argument("--key", help="Override network key, hex (requires --mac)")
    ap.add_argument("--zone", "-z", type=int, default=1, help="Zone/station (1-based)")
    ap.add_argument("--duration", type=int, default=30,
                    help="Run time / on-device safety timer in seconds (default 30)")
    ap.add_argument("--stop", action="store_true", help="Send the stop command instead of on")
    ap.add_argument("--stop-verify", action="store_true",
                    help="start → hold → stop within one session (proves early close)")
    ap.add_argument("--hold", type=int, default=15,
                    help="stop-verify: seconds open before STOP (default 15)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Offline: build + self-decode frames, no Bluetooth")
    args = ap.parse_args()

    if args.dry_run:
        dry_run(args.zone, args.duration)
        return

    name, mac, key = bre.resolve_device(args)
    if args.stop_verify:
        # stop-verify defaults to a longer safety timer than a one-shot.
        duration = args.duration if args.duration != 30 else 120
        asyncio.run(run_stop_verify(name, mac, key, args.zone, duration, args.hold))
    else:
        action = "stop" if args.stop else "on"
        asyncio.run(run_oneshot(name, mac, key, action, args.zone, args.duration))


if __name__ == "__main__":
    sys.exit(main())
