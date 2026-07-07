"""RE probe — Workstream 0 for the watering-programs build-out.

Characterizes the program **READ path** (the design-gating unknown) and the
adjacent capability probes, using the `scripts/bhyve.py` primitives. The key new
piece is a **multi-frame RX reassembler**: the production `_RxCollector` decodes
each 0x11 frame independently, which cannot reassemble a long `#19`
`setProgramSchedule` that streams as consecutive 16-byte CTR blocks, each in its
own outer frame with the RX counter continuing across them. This probe keeps the
raw frames and rebuilds the per-direction plaintext stream so we can SEE the
ground-truth framing the eventual reassembler must handle.

Every mode uses a FRESH connection (the probing hazard: a malformed/unknown
protobuf field desyncs the RX CTR counter for the rest of the connection).

    # confirm reachability first:
    python scripts/exploration/scan_rssi.py --time 20

    # --- READ-PATH characterization (run on the XD; it has real A-D schedules) ---
    # #10 syncRequest — prime candidate for a one-shot program dump:
    python scripts/exploration/probe_programs.py sync   --device BT4ValveXD01
    # connect-time unsolicited burst (send nothing, just listen):
    python scripts/exploration/probe_programs.py burst  --device BT4ValveXD01
    # #77 getActivePrograms — reads the enable bitmask (#20/#78):
    python scripts/exploration/probe_programs.py active --device BT4ValveXD01

    # --- adjacent capability probes (safe, no water) ---
    python scripts/exploration/probe_programs.py identify --device BTValve03 --seconds 5
    python scripts/exploration/probe_programs.py close    --device BTValve03

Modes that WRITE a program (`writeecho`) live in a separate, explicitly-gated
mode and target BTValve03 (single-station, safe) with a throwaway slot D; see
`--help`. The full 3-write run handshake (W0 step 3) is `runprog`.
"""
import argparse
import asyncio
import math
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import bhyve as B  # noqa: E402

# Windows consoles default to cp1252, which can't encode the status emoji below.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


# ─── device lookup ──────────────────────────────────────────────────────────

def _find_device(cfg, name):
    for d in cfg.get("devices", []):
        if d["name"].lower() == name.lower():
            return d
    raise SystemExit(f"device {name!r} not in $BHYVE_CONFIG (have: "
                     + ", ".join(d["name"] for d in cfg.get("devices", [])) + ")")


# ─── message builders (mirror bhyve.py's hand-rolled protobuf toolkit) ───────

def build_sync_request():
    """#10 syncRequest — empty message (OrbitPbApi_SyncRequest {})."""
    return B.pb_field_bytes(10, b"")


def build_get_active_programs():
    """#77 getActivePrograms — empty; device replies #78 activePrograms / #20 bitmask."""
    return B.pb_field_bytes(77, b"")


def build_close_connection(reconnect_sec=None):
    """#11 closeConnection { #1 reconnectTimeSec? }. Empty is valid."""
    body = B.pb_field_varint(1, reconnect_sec) if reconnect_sec else b""
    return B.pb_field_bytes(11, body)


COLOR = {"red": 0, "green": 1, "blue": 2}


def build_identify_device(seconds=5, period_ms=None, sequence=None):
    """#47 identifyDevice { #1 identifyTimeSec (REQUIRED), #2 identifyPeriodMs?,
    #3 identifySequence[] { #1 colorFlags (red0/green1/blue2), #2 durationMs } }.

    LED is RGB. `sequence` = list of (color_int, duration_ms) flash steps. Requesting
    a NON-red color is the decisive identify-vs-fault test (a fault LED is only red).
    """
    body = B.pb_field_varint(1, seconds)
    if period_ms:
        body += B.pb_field_varint(2, period_ms)
    for color, dur in (sequence or ()):
        step = B.pb_field_varint(1, color) + B.pb_field_varint(2, dur)
        body += B.pb_field_bytes(3, step)
    return B.pb_field_bytes(47, body)


# ── program write / enable / mode builders (W0.3 handshake) ──────────────────

# day-mode discriminators inside #19 (exactly one):
DOW_ALL = 0x7F  # dayFlags bit0=Sun..bit6=Sat; 0x7F = every day (fires today)


def build_program(slot, start_mins, zones, name, day_flags=DOW_ALL, budget=100):
    """#19 setProgramSchedule — a full runnable program.

    slot: 1=A..4=D. day-mode = #3 dayOfWeek{#1=day_flags}. start_mins: list of
    mins-from-midnight (#8 repeated). zones: list of (station_id_0idx, run_sec)
    → #9 StationInfo{#1,#2} repeated. name → #17. budget → #10.
    """
    body = B.pb_field_varint(1, slot)
    body += B.pb_field_bytes(3, B.pb_field_varint(1, day_flags))       # #3 dayOfWeek
    for m in start_mins:
        body += B.pb_field_varint(8, m)                                # #8 repeated
    for sid, sec in zones:
        body += B.pb_field_bytes(9, B.pb_field_varint(1, sid) + B.pb_field_varint(2, sec))
    body += B.pb_field_varint(10, budget)                              # #10 budgetPercent
    body += B.pb_field_bytes(17, name.encode())                        # #17 programName
    return B.pb_field_bytes(19, body)


def build_program_clear(slot):
    """Clear a slot back to NotSet: #19 { #1 slot, #2 programTypeNotSet{} } — no #8/#9."""
    return B.pb_field_bytes(19, B.pb_field_varint(1, slot) + B.pb_field_bytes(2, b""))


def build_set_active_programs(flags):
    """#20 setActivePrograms { #1 activeProgramFlags (bitmask; A=bit0) }.

    Byte-exact to the app's capture (A.3: `a2 01 02 08 00` = disable all); the
    app sends only #1 (device fills #2/#3 lastChange* itself)."""
    return B.pb_field_bytes(20, B.pb_field_varint(1, flags))


def build_timer_mode(mode):
    """#14 timerMode { #1 mode (0=off,1=auto,2=manual), #2 manualModeParams{} EMPTY }.

    The EMPTY #2 (`12 00`) is REQUIRED even for off/auto — a #14 omitting f2 is
    silently ignored (anahnymous, live-verified both modes)."""
    return B.pb_field_bytes(14, B.pb_field_varint(1, mode) + B.pb_field_bytes(2, b""))


# ─── multi-frame RX reassembly (the W0 deliverable) ─────────────────────────

def _dedup_consecutive(frames):
    """Drop a byte-identical re-delivery of the previous frame (the dup-frame
    hazard that advances rx_ctr and desyncs the stream)."""
    out = []
    for f in frames:
        if not out or f != out[-1]:
            out.append(f)
    return out


def reassemble(key, iv, base_rx_counter, raw_frames, sweep=48):
    """Rebuild the per-direction plaintext stream from a burst of 0x11 frames.

    The device streams a long inner message as consecutive 16-byte CTR blocks,
    each in its own `0x11|len|ct|trailer` frame, the RX counter advancing per
    block. We decrypt FRAME-BY-FRAME at a block-aligned counter (base + blocks
    consumed so far) so a short final frame doesn't misalign the next message,
    then concatenate and scan for `aa775a0f`-delimited inner messages.

    We sweep the base counter (a prior unsolicited push may have consumed some)
    and pick the base that yields the most CRC-valid inner messages. Returns
    (best_base, pt_stream, messages) where messages is a list of dicts:
    {offset, total, crc_ok, protobuf, span_frames_hint}.
    """
    cts = []
    for raw in raw_frames:
        parsed = B.parse_ble_frame(raw)
        if parsed is not None:
            cts.append(parsed[1])
    if not cts:
        return None, b"", []

    def decode_at(base):
        parts, blocks = [], 0
        for ct in cts:
            pt, _ = B.aes_encrypt(key, iv, (base + blocks) % 0x100000000, ct)
            parts.append(pt)
            blocks += math.ceil(len(ct) / 16) or 1
        stream = b"".join(parts)
        msgs = _split_inner(stream)
        score = sum(1 for m in msgs if m["crc_ok"])
        return stream, msgs, score

    best = None
    for d in range(0, sweep):
        for base in ((base_rx_counter + d) % 0x100000000,
                     (base_rx_counter - d) % 0x100000000):
            stream, msgs, score = decode_at(base)
            if best is None or score > best[0]:
                best = (score, base, stream, msgs)
            if d == 0:
                break
    _score, base, stream, msgs = best
    return base, stream, msgs


def _split_inner(pt):
    """Scan a decrypted stream for every `aa775a0f`-headed inner message."""
    msgs = []
    i = 0
    while i + 6 <= len(pt):
        hdr = pt.find(B.MSG_HEADER, i)
        if hdr < 0:
            break
        if hdr + 6 > len(pt):
            break
        payload_len = pt[hdr + 4]
        total = payload_len + 6
        if payload_len < 2 or hdr + total > len(pt):
            # incomplete trailing message — record what we can, stop
            msgs.append({"offset": hdr, "total": None, "crc_ok": False,
                         "protobuf": None, "raw": pt[hdr:].hex()})
            break
        inner = B.decode_inner(pt[hdr:hdr + total])
        msgs.append({
            "offset": hdr,
            "total": total,
            "crc_ok": bool(inner and inner["crc_ok"]),
            "protobuf": inner["protobuf"] if inner else None,
        })
        i = hdr + total
    return msgs


# ─── session helpers (mirror probe_station_and_flow) ────────────────────────

class _RawCollector:
    """Like B._RxCollector but keeps ALL raw frames for offline reassembly and
    fires an event on each notification so callers can drain a burst."""

    def __init__(self):
        self.raw = []
        self.event = asyncio.Event()

    def handle(self, _sender, data):
        self.raw.append(bytes(data))
        self.event.set()


async def _open(mac, key):
    from bleak import BleakClient, BleakScanner
    print(f"Scanning for {mac} ...")
    device = await BleakScanner.find_device_by_address(mac, timeout=25.0)
    if device is None:
        raise SystemExit(f"{mac} not found in range")
    client = BleakClient(device, timeout=15.0)
    await client.__aenter__()
    await B._connect(client)
    coll = _RawCollector()
    await client.start_notify(B.READ_CHAR, coll.handle)
    init_tx = bytearray(os.urandom(20))
    init_tx[11] = 0x00
    init_tx = bytes(init_tx)
    await client.write_gatt_char(B.AES_CHAR, init_tx)
    rx = await client.read_gatt_char(B.AES_CHAR)
    iv, tx_ctr, rx_ctr = B.derive_session(init_tx, rx)
    print(f"Session established (rx_ctr base = {rx_ctr})")
    return client, coll, iv, [tx_ctr], rx_ctr


def _blocks(frames):
    n = 0
    for f in frames:
        parsed = B.parse_ble_frame(f)
        if parsed:
            n += math.ceil(parsed[0] / 16) or 1
    return n


class Session:
    """One BLE session with running RX-counter tracking so multiple
    request/replies on the SAME connection each reassemble correctly (the RX
    counter advances by block-count across every reply)."""

    def __init__(self, client, coll, key, iv, tx, rx_ctr):
        self.client, self.coll, self.key, self.iv, self.tx = client, coll, key, iv, tx
        self.rx_ctr = rx_ctr

    async def send(self, protobuf):
        await _send(self.client, self.key, self.iv, self.tx, protobuf)

    async def request(self, protobuf, window=3.5, label=""):
        """Send a request, drain the reply burst, reassemble, advance rx_ctr."""
        n0 = len(self.coll.raw)
        await self.send(protobuf)
        await _drain(self.coll, window)
        new = _dedup_consecutive(self.coll.raw[n0:])
        if not new:
            if label:
                print(f"    [{label}] no reply frames")
            return []
        base, _stream, msgs = reassemble(self.key, self.iv, self.rx_ctr, new, sweep=20)
        self.rx_ctr = (base + _blocks(new)) % 0x100000000
        crc_ok = sum(1 for m in msgs if m["crc_ok"])
        if label:
            print(f"    [{label}] {len(new)} frame(s) -> {len(msgs)} msg ({crc_ok} crc-ok)")
        return msgs


async def _open_session(mac, key, tries=3):
    last = None
    for attempt in range(tries):
        try:
            client, coll, iv, tx, rx_ctr = await _open(mac, key)
            return Session(client, coll, key, iv, tx, rx_ctr)
        except Exception as e:  # noqa: BLE001 — transient WinRT connect drops
            last = e
            print(f"  connect attempt {attempt+1} failed ({e}); retrying...")
            await asyncio.sleep(3)
    raise SystemExit(f"could not connect to {mac}: {last}")


async def _close(sess):
    try:
        await sess.client.stop_notify(B.READ_CHAR)
    except Exception:  # noqa: BLE001
        pass
    await sess.client.__aexit__(None, None, None)


# ─── #16 / program decode helpers ───────────────────────────────────────────

def parse16(msgs):
    """Pull the interesting #16 status fields out of a reassembled message list."""
    for m in msgs:
        if not m.get("protobuf"):
            continue
        top = B.pb_parse(m["protobuf"])
        if top is None:
            continue
        st16 = B._pb_field(top, 16)
        if isinstance(st16, (bytes, bytearray)) and B.pb_parse(st16) is not None:
            s = B.pb_parse(st16)
            return {
                "clock": B._pb_field(top, 7),
                "run_state": B._pb_field(s, 1),          # #16.#1 (1 idle,3 rd,4 run)
                "mode": B._pb_path(s, 2, 1),             # #16.#2.#1 timerMode.mode
                "fault_noflow": B._pb_path(s, 7, 6),     # #16.#7.#6 valveOnNoFlowDetected
                "fault_block": B._pb_field(s, 7),        # #16.#7 raw faultStatus
                "nextstart_flags": B._pb_field(s, 9),    # #16.#9 nextStartProgramFlags
                "nextstart_epoch": B._pb_field(s, 10),   # #16.#10 nextStartTimeSecEpochUTC
                "active_station": B._pb_path(s, 6, 4),   # #16.#6.#4 currentStationId
                "remaining": B._pb_path(s, 6, 5),        # #16.#6.#5
                "battery_mv": B._pb_path(s, 14, 3),      # #16.#14.#3
            }
    return None


def slots_from_msgs(msgs):
    """Map slot-id -> the raw #19 body from a sync dump."""
    out = {}
    for m in msgs:
        if not m.get("protobuf"):
            continue
        top = B.pb_parse(m["protobuf"])
        p19 = B._pb_field(top, 19) if top else None
        if isinstance(p19, (bytes, bytearray)) and B.pb_parse(p19) is not None:
            sid = B._pb_field(B.pb_parse(p19), 1)
            out[sid] = p19
    return out


def _fmt16(s):
    if not s:
        return "no #16 decoded"
    fault = f"NO-FLOW" if s.get("fault_noflow") else "ok"
    return (f"run_state={s['run_state']} mode={s['mode']} fault={fault} "
            f"nextStartFlags={s['nextstart_flags']} nextStart={s['nextstart_epoch']} "
            f"activeStation={s['active_station']} batt={s['battery_mv']}mV clock={s['clock']}")


async def _send(client, key, iv, ctr, protobuf):
    msg = B.build_message(protobuf)
    ct, ctr[0] = B.aes_encrypt(key, iv, ctr[0], msg)
    await client.write_gatt_char(
        B.WRITE_CHAR, B.build_ble_frame(ct, B.compute_trailer(msg)), response=False
    )


async def _drain(coll, window, quiet=1.5):
    """Collect frames for up to `window` s, returning `quiet` s after the last one."""
    deadline = time.time() + window
    last = time.time()
    while time.time() < deadline:
        coll.event.clear()
        try:
            await asyncio.wait_for(coll.event.wait(), timeout=quiet)
            last = time.time()
        except asyncio.TimeoutError:
            if time.time() - last >= quiet:
                break


def _report(key, iv, rx_ctr, raw_frames, label):
    """Print raw frames + the reassembled inner messages."""
    frames = _dedup_consecutive(raw_frames)
    print(f"\n=== {label}: {len(raw_frames)} raw frame(s) "
          f"({len(frames)} after dedup) ===")
    for i, f in enumerate(frames):
        parsed = B.parse_ble_frame(f)
        ln = parsed[0] if parsed else "?"
        print(f"  frame[{i:2}] wire_len={ln:<3} raw={f.hex()}")
    if not frames:
        print("  (no frames)")
        return []
    base, stream, msgs = reassemble(key, iv, rx_ctr, frames)
    print(f"\n  reassembled @ base_ctr={base} ({rx_ctr - base:+} vs handshake), "
          f"stream={len(stream)}B")
    print(f"  stream hex: {stream.hex()}")
    crc_ok = sum(1 for m in msgs if m["crc_ok"])
    print(f"  inner messages found: {len(msgs)} ({crc_ok} CRC-valid)")
    for j, m in enumerate(msgs):
        if m["protobuf"] is None:
            print(f"\n  msg[{j}] @off={m['offset']} INCOMPLETE raw={m.get('raw','')}")
            continue
        fields = B.pb_parse(m["protobuf"])
        top_field = fields[0][0] if fields else "?"
        print(f"\n  msg[{j}] @off={m['offset']} total={m['total']}B "
              f"crc_ok={m['crc_ok']} top_field=#{top_field}")
        print(B.pb_format(m["protobuf"], indent=2))
    return msgs


# ─── modes ──────────────────────────────────────────────────────────────────

async def run_burst(dev, seconds):
    """Send NOTHING after the handshake; log the unsolicited connect-time push."""
    key = bytes.fromhex(dev["network_key"])
    client, coll, iv, tx, rx_ctr = await _open(dev["mac"], key)
    try:
        print(f">>> listening {seconds}s for the unsolicited connect-time burst "
              f"(no TX)...")
        await _drain(coll, seconds)
        _report(key, iv, rx_ctr, coll.raw, "connect-time burst")
    finally:
        await client.stop_notify(B.READ_CHAR)
        await client.__aexit__(None, None, None)


async def run_request(dev, protobuf, label, seconds):
    """Send one request protobuf, then reassemble the reply burst."""
    key = bytes.fromhex(dev["network_key"])
    client, coll, iv, tx, rx_ctr = await _open(dev["mac"], key)
    try:
        print(f">>> TX {label}: {protobuf.hex()}")
        await _send(client, key, iv, tx, protobuf)
        await _drain(coll, seconds)
        _report(key, iv, rx_ctr, coll.raw, f"{label} reply")
    finally:
        await client.stop_notify(B.READ_CHAR)
        await client.__aexit__(None, None, None)


async def run_ab(dev, seconds):
    """A/B: #10 syncRequest vs #15 getDeviceStatusInfo on fresh connections."""
    print("\n######## A: #10 syncRequest ########")
    await run_request(dev, build_sync_request(), "#10 syncRequest", seconds)
    await asyncio.sleep(2)
    print("\n######## B: #15 getDeviceStatusInfo ########")
    await run_request(dev, B.build_request_status_protobuf(),
                      "#15 getDeviceStatusInfo", seconds)


async def run_disable(dev):
    """Disable ALL programs (#20{0}) + set offMode (#14{0}); attempt fault-clear;
    re-read status. Leaves the device in offMode with no active programs."""
    key = bytes.fromhex(dev["network_key"])
    sess = await _open_session(dev["mac"], key)
    try:
        before = parse16(await sess.request(B.build_request_status_protobuf(), label="#15 pre"))
        print(f"  BEFORE: {_fmt16(before)}")
        await sess.request(build_set_active_programs(0), label="#20{0} disable-all")
        await sess.request(build_timer_mode(0), label="#14{0} offMode")
        await asyncio.sleep(1.5)
        after = parse16(await sess.request(B.build_request_status_protobuf(), label="#15 post"))
        print(f"  AFTER:  {_fmt16(after)}")
        if before and after:
            print(f"  -> programs {'disabled' if after['mode'] == 0 else 'mode='+str(after['mode'])}; "
                  f"no-flow fault {'CLEARED' if before.get('fault_noflow') and not after.get('fault_noflow') else 'unchanged'}")
    finally:
        await _close(sess)


async def run_identify(dev, seconds, period_ms, color, watch):
    """Interactive #47 identify probe: announce the send, hold the connection while
    the user watches the physical device, and time the effect. `color` names the
    Sequence color (decisive test: green/blue can't be a fault)."""
    key = bytes.fromhex(dev["network_key"])
    seq = [(COLOR[color], period_ms or 500)] if color else None
    pb = build_identify_device(seconds, period_ms, seq)
    sess = await _open_session(dev["mac"], key)
    try:
        print(f"\n  >>> WATCH {dev['name']} NOW <<<")
        print(f"  sending #47 identify: time={seconds}s, period={period_ms}ms, "
              f"color={color or 'default'}  (pb={pb.hex()})")
        t0 = time.time()
        msgs = await sess.request(pb, label="#47 identify", window=3.0)
        print(f"  [t+{time.time()-t0:.1f}s] sent; reply frames={len(msgs)}")
        print(f"  holding connection {watch}s — tell me: color? started when? stopped when?")
        end = time.time() + watch
        while time.time() < end:
            await asyncio.sleep(5)
            print(f"    ...t+{time.time()-t0:.0f}s (still watching)")
        # identify LATCHES on fw0111 (doesn't auto-stop) — always send the stop so
        # no probe leaves a device flashing. (#1=0 is itself the stop; skip then.)
        if seconds != 0:
            print("  >>> sending #47{#1=0} STOP")
            await sess.request(build_identify_device(0), label="#47 stop")
    finally:
        await _close(sess)


async def run_setmode(dev, mode):
    """Set the controller timerMode (0=off,1=auto,2=manual). autoMode(1) is the
    app's 'Enable Watering' — the normal resting state (scheduled watering on).
    offMode(0) is the device-wide 'controller off'."""
    name = {0: "offMode", 1: "autoMode(Enable Watering)", 2: "manualMode"}.get(mode, str(mode))
    key = bytes.fromhex(dev["network_key"])
    sess = await _open_session(dev["mac"], key)
    try:
        before = parse16(await sess.request(B.build_request_status_protobuf(), label="#15 pre"))
        print(f"  BEFORE: {_fmt16(before)}")
        await sess.request(build_timer_mode(mode), label=f"#14{{{mode}}} {name}")
        await asyncio.sleep(1.0)
        after = parse16(await sess.request(B.build_request_status_protobuf(), label="#15 post"))
        print(f"  AFTER:  {_fmt16(after)}")
        print(f"  -> timerMode set to {name}; mode now = {after['mode'] if after else '?'}")
    finally:
        await _close(sess)


async def run_prog(dev, slot, run_sec, fire_in_min, tz_offset, watch_sec, zones=(0,)):
    """W0.3+W0.4: full 3-write run handshake on an empty slot, then watch it fire,
    then ALWAYS clean up (clear slot + disable all + offMode). Dry valve only.

    `zones` = 0-indexed station ids (repeated #9). Multi-zone runs sequentially, so
    the auto-run active-station should step through them (the non-first-zone test)."""
    key = bytes.fromhex(dev["network_key"])
    flag = 1 << (slot - 1)
    letter = "ABCDEF"[slot - 1]
    prog = None
    scheduled = False
    t_setup = time.time()
    try:
        # ---- Connection 1: setup + 3-write handshake ----
        sess = await _open_session(dev["mac"], key)
        try:
            st = parse16(await sess.request(B.build_request_status_protobuf(), label="#15"))
            print(f"  status: {_fmt16(st)}")
            if st and st["run_state"] == 4:
                raise SystemExit("device is watering (run_state=4) — abort; retry when idle")
            clock = st["clock"]
            # disable any existing programs so only our slot fires
            await sess.request(build_set_active_programs(0), label="#20{0} disable-all")

            local = (clock + tz_offset) % 86400
            mins = ((local // 60) + fire_in_min) % 1440
            print(f"  device clock={clock}; local mins-from-midnight now={local//60}; "
                  f"scheduling slot {letter} start at {mins} (=+{fire_in_min}min), run {run_sec}s")

            prog = build_program(slot, [mins], [(z, run_sec) for z in zones], f"W0Test{letter}")
            print(f"  zones (0-idx stations) = {list(zones)} @ {run_sec}s each (sequential)")
            print(f"  STORE #19: {prog.hex()}")
            await sess.request(prog, label="#19 store", window=3.5)

            # read back the stored program via #10 (encoder round-trip check)
            dump = await sess.request(build_sync_request(), label="#10 readback", window=5.0)
            slots = slots_from_msgs(dump)
            if slot in slots:
                print(f"  READBACK slot {letter}:")
                print(B.pb_format(slots[slot], indent=2))
            else:
                print(f"  ⚠ slot {letter} NOT found in #10 readback (slots present: {sorted(slots)})")

            # enable + autoMode, then RE-SEND store+enable (device computes next-start
            # only when store+enable arrive while already in autoMode)
            await sess.request(build_set_active_programs(flag), label=f"#20{{{flag}}} enable")
            await sess.request(build_timer_mode(1), label="#14{1} autoMode")
            await sess.request(prog, label="#19 re-store", window=3.5)
            await sess.request(build_set_active_programs(flag), label=f"#20{{{flag}}} re-enable")

            conf = parse16(await sess.request(B.build_request_status_protobuf(), label="#15 confirm", window=4.0))
            print(f"  CONFIRM: {_fmt16(conf)}")
            scheduled = bool(conf and conf.get("nextstart_flags"))
            if scheduled:
                ns = conf["nextstart_epoch"]
                dt = (ns - conf["clock"]) if ns and conf["clock"] else None
                print(f"  ✅ next-start COMPUTED: flags={conf['nextstart_flags']} "
                      f"(expect {flag}), epoch={ns} (~{dt}s out)")
            else:
                print("  ⚠ no nextStartProgramFlags — device did not compute a next-start")
        finally:
            await _close(sess)

        # ---- wait for the scheduled minute, then watch it fire ----
        if scheduled and watch_sec > 0:
            wait = max(0, fire_in_min * 60 - (time.time() - t_setup) - 12)
            print(f"\n  (disconnected) waiting {wait:.0f}s for the scheduled start, "
                  f"then polling up to {watch_sec}s for the run...")
            await asyncio.sleep(wait)
            sess = await _open_session(dev["mac"], key)
            try:
                deadline = time.time() + watch_sec
                fired = 0
                while time.time() < deadline:
                    s = parse16(await sess.request(B.build_request_status_protobuf(),
                                                   label="#15 watch", window=3.0))
                    tag = _fmt16(s)
                    rs = s["run_state"] if s else None
                    print(f"    t+{time.time()-t_setup:5.0f}s  {tag}")
                    if rs == 4:
                        fired += 1
                        print(f"    🔥 RUNNING (auto): mode={s['mode']} (expect 1=auto), "
                              f"activeStation={s['active_station']} remaining={s['remaining']}")
                        if fired >= 2:
                            break
                    await asyncio.sleep(12)
                if not fired:
                    print("    ⚠ never observed run_state=4 in the watch window "
                          "(tz offset off? or missed the minute) — next-start was still computed")
            finally:
                await _close(sess)
    finally:
        # ---- cleanup: stop any run, clear the throwaway slot, restore autoMode ----
        # NB: offMode (#14{0}) is the device-wide "controller off" (app: "automatic
        # watering disabled") — NOT a per-run stop. Halt with the manual stop
        # (#14{2,{}}) and leave the controller in autoMode(1), its normal resting state.
        print("\n  CLEANUP: stop run + clear slot + disable throwaway + restore autoMode...")
        try:
            sess = await _open_session(dev["mac"], key)
            try:
                await sess.request(B.build_stop_protobuf(), label="#14{2,{}} stop run")
                await sess.request(build_set_active_programs(0), label="#20{0} disable throwaway")
                if prog is not None:
                    await sess.request(build_program_clear(slot), label=f"#19 clear {letter}")
                await sess.request(build_timer_mode(1), label="#14{1} autoMode (restore)")
                final = parse16(await sess.request(build_sync_request(), label="#10 verify", window=5.0))
                dump = await sess.request(build_sync_request(), label="#10 slots", window=5.0)
                print(f"  FINAL: {_fmt16(final)}")
                print(f"  slots now: {sorted(slots_from_msgs(dump))} "
                      f"(slot {letter}={slot} should be gone)")
            finally:
                await _close(sess)
        except SystemExit as e:
            print(f"  ⚠ cleanup connect failed: {e} — RE-RUN `disable`/`cleanup` to be safe!")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=[
        "sync", "burst", "active", "status", "ab", "identify", "close",
        "disable", "runprog", "automode", "offmode"])
    ap.add_argument("--device", required=True, help="device name from $BHYVE_CONFIG")
    ap.add_argument("--seconds", type=int, default=8,
                    help="RX collection window (default 8)")
    ap.add_argument("--reconnect", type=int, default=None,
                    help="close: reconnectTimeSec (default: empty body)")
    ap.add_argument("--slot", type=int, default=4,
                    help="runprog: program slot 1=A..4=D (default 4=D)")
    ap.add_argument("--run-sec", type=int, default=120,
                    help="runprog: zone run time seconds (default 120; DRY valve only)")
    ap.add_argument("--fire-in", type=int, default=2,
                    help="runprog: minutes from now to schedule the start (default 2)")
    ap.add_argument("--tz-offset", type=int, default=-14400,
                    help="runprog: device local UTC offset sec (default -14400 = EDT)")
    ap.add_argument("--watch-sec", type=int, default=210,
                    help="runprog: seconds to poll for the run to fire (default 210)")
    ap.add_argument("--zones", default="1",
                    help="runprog: comma list of 1-indexed zones, e.g. '2,3' (default '1')")
    ap.add_argument("--color", choices=["red", "green", "blue"], default=None,
                    help="identify: Sequence color (green/blue = decisive vs fault)")
    ap.add_argument("--period", type=int, default=None,
                    help="identify: identifyPeriodMs / step durationMs")
    ap.add_argument("--watch", type=int, default=30,
                    help="identify: seconds to hold the connection while you watch")
    args = ap.parse_args()
    cfg = B.load_config()
    dev = _find_device(cfg, args.device)
    print(f"Target {dev['name']} {dev['mac']}  (fw {dev.get('firmware')})")

    if args.mode == "burst":
        asyncio.run(run_burst(dev, args.seconds))
    elif args.mode == "sync":
        asyncio.run(run_request(dev, build_sync_request(), "#10 syncRequest", args.seconds))
    elif args.mode == "active":
        asyncio.run(run_request(dev, build_get_active_programs(),
                                "#77 getActivePrograms", args.seconds))
    elif args.mode == "status":
        asyncio.run(run_request(dev, B.build_request_status_protobuf(),
                                "#15 getDeviceStatusInfo", args.seconds))
    elif args.mode == "ab":
        asyncio.run(run_ab(dev, args.seconds))
    elif args.mode == "identify":
        asyncio.run(run_identify(dev, args.seconds, args.period, args.color, args.watch))
    elif args.mode == "close":
        asyncio.run(run_request(dev, build_close_connection(args.reconnect),
                                "#11 closeConnection", 4))
    elif args.mode == "disable":
        asyncio.run(run_disable(dev))
    elif args.mode == "automode":
        asyncio.run(run_setmode(dev, 1))
    elif args.mode == "offmode":
        asyncio.run(run_setmode(dev, 0))
    elif args.mode == "runprog":
        zones = tuple(int(z.strip()) - 1 for z in args.zones.split(",") if z.strip())
        asyncio.run(run_prog(dev, args.slot, args.run_sec, args.fire_in,
                             args.tz_offset, args.watch_sec, zones))


if __name__ == "__main__":
    main()
