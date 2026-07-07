# BLE Protocol Reference

Technical reference for the Orbit B-Hyve XD BLE protocol as observed and reconstructed during the project. For the narrative of how this was figured out, see [`reverse_engineering_journey.md`](reverse_engineering_journey.md).

## GATT Service & Characteristics

The device advertises one custom GATT service:

| Service UUID | Notes |
|---|---|
| `0000fe32-0000-1000-8000-00805f9b34fb` | Used for HA's BLE auto-discovery |

The service exposes five characteristics. The three used in normal operation are:

| Handle | UUID | Properties | Purpose |
|---|---|---|---|
| 0x0012 | `00006c71-fe32-4f58-8b78-98e42b2c047f` | read, write | AES session initialization (always 20-byte writes) |
| 0x0014 | `00006c72-fe32-4f58-8b78-98e42b2c047f` | write-without-response, write | Encrypted data channel — outgoing (TX) |
| 0x0016 | `00006c73-fe32-4f58-8b78-98e42b2c047f` | notify | Encrypted data channel — incoming (RX, via notifications) |
| 0x0017 | (CCCD for 0x0016) | write | Enable notifications on RX (write `0x0100`) |
| 0x0018 | `00006c76-fe32-4f58-8b78-98e42b2c047f` | write | Unknown — ATT 0x80 (Application Error) for any write without proper auth context |

## Connection Sequence

A working session looks like this:

1. **Connect** to the device's BLE address (no BLE bonding required — the device does not maintain a paired-peer table).
2. **Service discovery**.
3. **MTU negotiation.** The application requests an MTU around 262; the device accepts up to about 672 bytes. In practice 247 is plenty.
4. **AES session init.** Write a 20-byte buffer to characteristic `0x6c71` (handle 0x0012). The structure of the buffer is described in the Encryption section below. Read `0x6c71` back; the device returns a 20-byte response whose first 4 bytes are a session-specific value used to derive the session IV.
5. **Enable notifications on `0x6c73`** by writing `0x0100` to its CCCD (handle 0x0017).
6. **Exchange encrypted frames.** Outgoing on `0x6c72`; incoming on `0x6c73` notifications. Each frame uses the framing described next.

## Frame Format (data channel)

```
+------+--------+--------------------------+----------+----------+
| 0x11 | length | encrypted_payload (length bytes)    | trailer  |
+------+--------+--------------------------+----------+----------+
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ 2 bytes LE
```

- **`0x11`** — fixed magic header byte (decimal 17).
- **`length`** — single byte. Length of the encrypted payload **only**; does not include the trailer.
- **encrypted payload** — `length` bytes of AES-encrypted data (see [`encryption.md`](encryption.md) for the cipher construction).
- **trailer** — 2 bytes, little-endian, content-dependent checksum. Algorithm:
  ```
  trailer_uint16 = (sum(plaintext_bytes) + 0x11 + length) mod 65536
  ```
  Where `plaintext_bytes` is the unencrypted inner message (the bytes that were encrypted to produce the encrypted payload).

Total frame size on the wire = `2 + length + 2` = `length + 4` bytes.

## Inner Message (plaintext) Format

After decryption, the inner message is itself wrapped:

```
+----+----+----+----+--------+------+------+----------------+--------------+
| AA | 77 | 5A | 0F | length |  00  |  00  | protobuf bytes | CRC16-CCITT  |
+----+----+----+----+--------+------+------+----------------+--------------+
```

- **`AA 77 5A 0F`** — 4-byte fixed inner-frame header.
- **`length`** — payload length including the 2 trailing CRC bytes.
- **`00 00`** — reserved.
- **protobuf bytes** — encoded `OrbitPbApi_Message` (or `OrbitPbApi_IpcMsg`); see [`../protobuf/orbit_ble.proto`](../protobuf/orbit_ble.proto).
- **CRC-16 CCITT** — checksum over the protobuf bytes only, using the standard CCITT polynomial `0x1021` and lookup table.

## Host→Device (TX) Command Messages

Commands are encoded as the same `OrbitPbApi_*` protobuf, wrapped in the inner message and
outer frame described above, and written to `0x6c72`. The validated control commands are
reconstructed from `scripts/bhyve.py` (`build_start_protobuf` / `build_stop_protobuf`).

| Command | Protobuf (field tree) | Wire bytes |
|---|---|---|
| **Start watering** | `#14 timerMode { #1 mode=2 (manual); #2 manualParams { #3 stationInfo { #1 stationId; #2 runTimeSec } } }` | varies with `stationId` / `runTimeSec` |
| **Stop watering** | `#14 timerMode { #1 = 2; #2 manualParams {} (empty) }` | `72 04 08 02 12 00` |

- **Station addressing.** `stationId = zone − 1`. Single-station valves use `stationId = 0`;
  the XD 4-port uses `0–3`. `runTimeSec` is the run duration in seconds.
- **Stop** is the same `timerMode` message with an **empty** `manualParams` (no
  `stationInfo`), which halts the active run.

As with the RX table below, treat these field semantics as **reconstructed and
behaviorally-validated** (the valve physically actuates), not vendor-confirmed.

## Device→Host (RX) Notifications

Notifications on `0x6c73` use the same outer frame and inner-message format as host→device,
encrypted with the **same session IV but a separate counter** seeded from `init_tx[16:20]`
(see [`encryption.md`](encryption.md)). Each notification is a **complete** inner message
(`AA775A0F … CRC16`) — unlike long host→device messages, RX is not fragmented across
notifications.

### RX message wrapper

Every decoded RX protobuf shares an outer wrapper, then carries exactly one payload field
whose **field number selects the message type**:

```
#1  bytes(6)  device MAC (e.g. 44:67:55:XX:XX:XX — Orbit OUI 44:67:55)
#7  varint    device clock, Unix epoch seconds
#N  message   one payload submessage; N identifies the type (table below)
```

### Observed RX message types (capture: B-Hyve 21205 single-station valve, fw `0111`, one app session)

| `#N` | Meaning (observed) | Key inner fields |
|---|---|---|
| `#16` | **Device status / state** (pushed on connect and on every state change) | `#1` mode (`1`=idle, `3`=rain-delay, `4`=manual running); `#2` active-run echo (`{#1=2, #2{#3{stationId, runSec}}}`); **`#6` run progress `{#5 remaining sec (counts down), #7 total sec (constant)}`** (present only while watering; HW-verified 2026-07-05); `#10` next-event Unix ts; `#13 {#1 min, #3 last-event ts, #4}`; **`#14 {#3 = battery mV}`**; `#16` 8-byte constant token |
| `#46` | **Battery report** (standalone) | `#3 = battery mV` (same `{#3: mV}` shape as `#16.#14`) |
| `#23` | **Device info** | `#2` model string (`HT25G2-0001`); `#3` firmware string (`0111`) |
| `#19` | **Program / schedule** | `#10`, `#11` Unix ts; `#17` program name (UTF-8, e.g. `"Blueberries And Strawberries"`) |
| `#59` | **Watering / flow status** (periodic, after a `#57` subscribe) | `#1` flow-active (`1` = water currently flowing — **not** "valve open"); `#2` seq (optional); `#3` **cumulative** per-run volume counter (raw device units, resets each valve-open) |
| `#30` / `#31` | **Command ack / flag** (small, around start/stop) | `#1`/`#6` boolean-ish |

Battery is the highest-value field for Home Assistant: it appears both standalone (`#46`)
and inside the status block (`#16.#14.#3`), encoded in millivolts (observed `2690` ≈ 2.69 V,
consistent with 2×AA). Treat the exact field semantics above as **reconstructed, not
vendor-confirmed** — they match one session and should be re-verified against the app UI
(battery %, next-run time) before being surfaced as authoritative.

### RX push behavior (when the device volunteers data)

Observed live across single-station valves (fw `0111`) and the XD 4-port (fw `0107`):

- **Solicited (reliable).** Whenever the host writes a command on `6c72` (e.g. start/stop),
  the device answers with a burst that includes a full `#16` status block — so a start/stop
  reliably reads back the resulting run-state and battery. This is the dependable way to read
  state.
- **Unsolicited connect-time push (idle: reliable; active: not).** On connect, an **idle**
  device reliably pushes a `#16` status (the CLI's `status` command depends on this). When the
  device is **active** — **actively watering (run-state 4)** *or* with a **rain delay active
  (run-state 3)** — the connect-time push is unreliable: sometimes only a minimal clock-bearing
  ack arrives, sometimes nothing, so a passive `status`/`rain-delay get` may come up empty even
  though the connection succeeded. (Hardware-confirmed 2026-06-30: a fresh-session `rain-delay
  get` against a Gen2 valve holding an active 24 h delay returned no decodable status twice in a
  row, then read back correctly once a `#15{}` request was sent first.)

**Implication (resolved).** A dependable status read in any state needs a benign **"request
status" TX** (`#15 {}`, the empty status request in the catalog above) to elicit the `#16` burst
rather than waiting for a volunteered push. The CLI's `rain-delay` command now sends `#15{}`
right after the handshake for exactly this reason; the HA side adopts it as the canonical
`refresh_state()` in the status-poll-refresh phase.

## Capability Command Catalog (2026-06-28 XD full-surface app capture)

Decoded from a single official-app session driving the XD 4-port (HT34A-0001, fw `0107`)
with the Wi-Fi hub unplugged (forcing the local BLE path). Source artifacts:
`captures/20260628_app_full_surface/` (notes repo) — `decoded_xd.txt` (156/156 frames
CRC-valid) + the timestamped `action_log.md`. Decoder:
`scripts/exploration/decode_capture.py`. Field semantics are **reconstructed and
behaviorally cross-checked against the operator's action log**, not vendor-confirmed.

> **Message framing note (CTR streaming).** Long inner messages are transmitted as
> consecutive 16-byte CTR blocks, **each wrapped in its own `0x11|len|ct|trailer` outer
> frame** (typically `len=0x10`), with the AES counter continuing across them. To decode,
> strip each frame's header/trailer, concatenate the ciphertext per direction, and decrypt
> as one continuous stream (see `decode_capture.py`). This supersedes the earlier "RX is
> never fragmented" note — short replies fit one frame, but program/status payloads span
> several.

### TX commands (host→device, on `6c72`)

| Capability | Protobuf (field tree) | Notes |
|---|---|---|
| **Start watering** | `#14 { #1=2; #2 { #3 { #1=stationId; #2=runTimeSec } } }` | `stationId = zone−1`; seconds. (Confirmed: zone1/60 s, zone3/120 s.) |
| **Stop watering** | `#14 { #1=2; #2={} }` | `72 04 08 02 12 00`. |
| **Request status** | `#15 {}` (empty) | Elicits a full `#16` status burst — **works mid-run** (the dependable poll the old TODO wanted). |
| **Set clock (timestamp-sync)** | `#18 { #1 = "YYYY-MM-DDThh:mm:ss±hh:mm" }` | ISO-8601 local string; the app sends it on connect. **HW-verified 2026-07-06: IGNORED over BLE on both fw0107 (XD) and fw0111 (Gen2)** — a deliberate +1 h set left the clock unchanged and drew no reply. The device wall clock (`#7`, read-only) is **cloud/hub-managed and not locally settable**; an off-app device drifts (BTValve03 was ~20 h off). Consequence for **programs**: start-times fire at *device-local* time, so a drifted clock fires schedules at the wrong real-world hour — surface the skew, but it can only be corrected via the cloud/app/hub. |
| **Set / clear rain delay** | `#17 { #1=minutes; #3=expiryUnixUTC; #4=1 }` | `minutes=0` clears. `expiry = deviceClock + minutes·60`. Confirmed 1440=24 h, 2880=48 h. **The device honors `#3` literally and stores `#1` independently** (skew probe 2026-06-30: sent `#1=360 min` with a skewed `#3=clock+1h`; the device echoed back `#1=360` *and* `#3=clock+1h` unchanged — it enforces the absolute `#3`, it does **not** recompute it from `#1`). ⇒ **`#3` must be anchored to the *device* clock** (`#7`), not the host clock; with a clock-skewed device a host-anchored expiry ends the delay early/late by the skew. Keep `#1` and `#3` consistent (`#3 = deviceClock + #1·60`). |
| **Create / edit / replace program** | `#19 { … }` | Write the full program to its slot (`#1`). **Replace** = write the replacement's content to the target slot — no special opcode. Full schema below. |
| **Delete program** | `#19 { #1=slot; #2 {} }` | Write `programTypeNotSet` (`#2` empty) to the slot — clears it to empty. HW-verified 2026-07-06 (`9a010408041200` cleared slot D; `#10` readback showed `#2` NotSet). (The old app capture also cleared slots by stripping `#8`/`#9`; writing `#2 {}` is the clean canonical form.) |
| **Subscribe / unsubscribe flow** | `#57 { #1=intervalMs; #2=type }` | **Subscribe** = `#57 { #1=1000; #2=2 }` (protobuf `ca030508e8071002`) → device streams periodic `#59` ~1/s. **This is a PERSISTENT stream** that survives reconnects and, crucially, **suppresses the `#16` status response** — while subscribed, `#15` returns only `#59`, never `#16` (hardware, 2026-07-03: a valve left subscribed answered every `#15` with `#59`/`run_state=None`, and unbounded per-poll re-subscription eventually **wedged** it). **Unsubscribe** = `#57 { #1=0; #2=2 }` (interval 0, protobuf `ca030408001002`) — **verified 2026-07-03**: after sending it the `#59` stream stopped and the very next `#15` returned a clean full `#16` (`run_state=1`). So any flow read MUST unsubscribe when done. Implemented as CLI `flow` + HA `read_flow()` (Gen2 only, `has_flow`), which always sends `#57{#1=0}` in a `finally`. **Flow is Gen2-only — hardware-confirmed 2026-07-02:** `#57` to the XD (`44:67:55:D8:55:D2`) yielded **zero `#59`** over 10 s vs. 7 frames from a Gen2. |
| **Enable programs** | `#20 { #1=activeProgramFlags }` | **Program-ENABLE bitmask** (corrected 2026-07-06 — NOT a "commit"). uint32 bitmask, program **A = bit 0** (`1 << (slot-1)`: A=1, B=2, C=4, D=8, E=16); write the OR of all enabled slots, `#1=0` disables all. The `n` values 8/9/12/13 recorded earlier were bitmasks. Also `#2 lastChangeDateSecEpochUtc`, `#3 lastChangeId`. Returned on read too (via `#10`/`#77`). |
| **Sync request (full dump)** | `#10 {}` (empty) | **The program-READ path.** One `#10` streams a full state dump: every `#19` program slot + a `#16` status block + the `#20` enable bitmask (+ `#29` settings) as back-to-back messages. Verified on XD + Gen2 (2026-07-06): 9 frames → 9 CRC-valid messages, all 6 slots (A–F) returned. A strict superset of `#15` (heavier; keep `#15` for the routine poll). |
| **Read enable state** | `#77 {}` (empty) | Cheap targeted read — replies with just the `#20` enable bitmask (`getActivePrograms`). |
| **Set controller mode** | `#14 { #1=mode; #2={} }` | **Device-global.** `mode 1`=autoMode ("Enable Watering", normal resting state), `0`=offMode ("controller off / automatic watering disabled"), `2`=manualMode (with `#2.#3`=start a station; empty `#2`=stop). **The empty `#2` (`12 00`) is REQUIRED** — a `#14` omitting field 2 is silently ignored. Byte refs: auto `720408011200`, off `720408001200`, stop `720408021200`. **RULE: never leave the controller in offMode after a run/stop/cleanup — stop with `#14{2,{}}` and return to autoMode(1).** |
| **Identify (LED locate)** | `#47 { #1=seconds }` | Gen2 (fw0111): `#1>0` starts a red flash and **LATCHES**, `#1=0` stops it; custom `#3` color sequence ignored. XD (fw0107, LCD): **no-op**. Fire-and-forget (no reply). |
| **Close connection** | `#11 {}` | Graceful pre-disconnect; empty body valid; no reply, no desync. |
| Connect-time queries | `#15 {}`, `#22 {}`, `#45 {}`, `#120 {}` (empty), `#18` clock, `#75 {#1=unixTs; #2=mask}`, `#19` reads of existing programs, device-info → RX `#23` | Sent during the handshake to sync clock + read current state. |

**Making a program run — the 3-write handshake (HW-verified 2026-07-06, both families).** A stored
program does not run by itself. In order, then store+enable re-sent: **(1) store** `#19` (full body);
**(2) enable** `#20 { #1=1<<(slot-1) }`; **(3) run-mode** `#14 { #1=1 (auto); #2={} }`. The device
computes a next-start only if store+enable arrive **while already in autoMode**, so the app does
store→enable→autoMode→**re-send store+enable**, then reads `#16.#9 nextStartProgramFlags` /
`#16.#10 nextStartTimeSecEpochUTC` to confirm. **No `getProgramSchedule` exists over BLE** — reads
go through `#10` (above), not write-and-echo.

### Watering program message (`#19`)

Captured by editing one advanced program (name `OurAdvancedProgram`) through every day-mode.

| Field | Meaning | Observed |
|---|---|---|
| `#1` | program **slot id** (`programId` enum) | 0=manual, A=`1`, B=`2`, C=`3`, D=`4`, E=`5`, F=`6` |
| `#2` | `programTypeNotSet {}` | present on an **empty / deleted** slot (delete = write `{ #1=slot; #2={} }`) |
| `#8` (repeated varint) | **start times**, minutes-of-day (device-local) | `360` (06:00), `1080` (18:00); round-trips via `#10` readback |
| `#9 { #1=zoneIndex; #2=runSec; #3=groupId }` (repeated) | **per-zone run durations** | Z0=300, Z1=420, Z2=540, Z3=660 (5/7/9/11 min); multi-zone round-trips |
| `#10` | budget / seasonal-adjust % | `100` |
| `#11` / `#12` | ⚠ **DEPRECATED** startDate/stopDate | cloud-managed; not stored on our fleet (current pair is `#21`/`#22`) |
| `#13` / `#14` | lastChangeDate / lastChangeId (`InterfaceId`) | `#14=2` (wifiInterface) on seeded slots |
| `#17` | program **name** (UTF-8) | `OurAdvancedProgram` |
| `#18` | `intervalHours` | `0` on slot B |
| `#19` / `#20` | `basicProgramMode` / `databaseId` (inner scope) | note: this inner `#20` is **not** the enable message |
| `#21` / `#22` | `originDateSecEpochUtc` / `endDateSecEpochUtc` | current schedule anchor/end (none stored locally on our fleet) |

**Watering-days mode (mutually exclusive — exactly one present):**

| Mode | Encoding | Evidence |
|---|---|---|
| Specific weekdays | `#3 { #1 = bitmask }`, **bit0=Sun … bit6=Sat** | all=`127`, Mon/Wed/Fri=`42` (bits 1,3,5) |
| Every N days | `#4 { #1 = N; #2 = anchor ISO date }` | N=`3`; `#4.#2` is marked deprecated in knobunc's schema but is **still LIVE on fw0107/0111** (slot B populated it, `#21 originDate` was not) — emit `#4.#2` |
| Odd days | `#5 {}` (empty marker) | — |
| Even days | `#6 {}` (empty marker) | — |
| Run once | `#7 { #1 = programFlags }` | `programTypeRunOnce` (knobunc/anahnymous) |

### RX additions (device→host, on `6c73`)

- **Run-state `#16.#1`:** extend the table to `1`=idle, **`3`=rain-delay active**, `4`=running
  (manual **or** program — HW-verified 2026-07-06 an auto/program run also reports `#16.#1=4`, so
  `is_watering` covers program runs). `0`=controller off (offMode). A **program** run is
  distinguishable from a manual run by `#16.#2.#1` (the echoed `timerMode.mode`): **1=auto** on a
  scheduled/program run, **2=manual** on a manual run.
- **`#16.#13` rain-delay status:** `{ #1=minutes, #3=expiryUnix, #4=enabled(0/1) }` — echoes the
  `#17` set command. **Clear shapes vary and `#4` is often absent** (hardware-confirmed
  2026-06-30): an idle read may return `{ #1=0, #4=0 }`, but a **freshly cleared** delay echoes a
  **bare `{ #1=0 }` with no `#4` at all**. So a decoder must **not** gate "active" on `#4` being
  present — derive `active = (minutes > 0)` when `#4` is absent, else a clear leaves a stale
  "active" value (this was a real HA bug: the `#4 is not None` guard dropped the clear). Separately,
  a **full `#16` status with run-state ≠ 3 and no `#16.#13` block at all** means the delay expired /
  cleared out-of-band (the device omits the block once inactive) → treat as cleared. Bare acks
  (`#30`), `#46`, and `#59` frames carry no run-state and must **not** clear it.
- **`#16.#2`** echoes the active manual run: `{ #1=2, #2 { #3 { #1=stationId, #2=runSec } } }`. The
  running **zone is `#16.#2.#2.#3.#1` (`stationId`, 0-indexed → zone = id + 1)**; on the 4-station
  XD this is the *only* place the specific running station is reported. HA decodes it into
  `DeviceState.active_zone` (`status.py`, `e0aa80b`) so only the running zone renders open —
  without it a poll-/app-discovered run left `active_zone=None` and **every** XD zone rendered
  watering. **`#16.#6`** carries run progress: **`#5` = seconds remaining (counts DOWN), `#7` =
  total run-time seconds (constant)**, plus a nested `#6{…}` (also total). Present only while watering.
  - **HW-verified 2026-07-05 (Gen2 fw0111 + XD fw0107), correcting an earlier mislabel:** during a
    live 180 s run `#16.#6.#5` counted down `174→138→102` (1/s) while `#16.#6.#7` held constant at
    `180`. So `#5` = remaining, `#7` = total — matching knobunc's vendor names
    `currentTimeRemainingSec` / `totalRunTimeSec`. Our earlier decode read **`#16.#6.#7` as
    "remaining"**, so it reported a static total the whole run — the "static remaining" that the
    auto-close drift-guard was built to paper over was this mislabel, not firmware. There is **no
    Gen2↔XD layout flip**: both families use `#16.#6.#5` (`#16.#7` is empty/`{#6=1}`, knobunc's
    `faultStatus`).
  - ⚠️ **Upstream likely shares this bug:** ljmerza's v2.1.0 XD decode (`6b131f9`,
    `devices/ht34a.py:_parse_status`) reportedly reads `#16.#6.#7` as *seconds remaining* — i.e. the
    total field — so upstream's remaining probably sits static too. Worth an upstream issue/PR once
    re-confirmed against their code.
  - **Now fixed here:** HA `devices/status.py` and CLI `scripts/bhyve.py:extract_status` both read
    `#16.#6.#5` → `seconds_remaining` (counts down), plus `#16.#2.#2.#3.#1` → `active_zone`
    (`e0aa80b`); the wall-clock auto-close + drift-guard remain as a safety net.
- **`#16.#9 nextStartProgramFlags` / `#16.#10 nextStartTimeSecEpochUTC`** — populated whenever a
  program is enabled: `#9` is the slot bitmask that fires next (A=bit0), `#10` its epoch. This is the
  **success signal for the run-handshake** (HW 2026-07-06: after enabling slot D, `#9=8` and
  `#10=clock+90s`) and a natural HA "next run" sensor. On fire, `#10` rolls forward to the next
  occurrence.
- **`#16.#7 faultStatus`** (knobunc `OrbitPbApi_FaultStatus`) — an **empty message means no faults**;
  scalar bools flag specific faults: `#6 valveOnNoFlowDetected` ("No Flow", HW-sampled 2026-07-06 on a
  dry Gen2 valve — **sticky**, needs a real wet run/reset to clear), `#5 valveOffFlowDetected`, `#7`
  low, `#8` high, `#1 pumpFault`, `#4 voltageBoostCircuitFail`, `#10 batteryFault`. Feeds the Goal's
  "Alerts & status" sensor. (Note: a fault does **not** light the Gen2 red LED — that's `#47` identify.)
- **`#16.#12 programDelayType`** — why a program is delayed: 0 none / 1 user / 2 rain / 3 wind / 4 freeze.
- **`#19` program** is echoed back on read/save (start times re-emitted as `#8 { #45 = value }`).
- **`#30`** small command ack around start/stop/clear. **A stop reply is *only* this bare ack**
  (hardware-confirmed 2026-06-30: `f201 02 0801` = `#30 { #1=1 }`) — it carries **no `#16` status
  block**, so a stop cannot be confirmed from its own reply. Confirm a stop by issuing a follow-up
  `#15{}` and decoding the resulting `#16` run-state (idle=1 *or* rain-delay=3 both read
  "not watering"); treat the `#30 {#1=1}` ack as provisional success and rely on the on-device
  auto-close as the safety net. (A start reply, by contrast, usually *does* carry `#16`.)
- **`#59` watering/flow status:** `{ #1=flow-active(0/1), #2=seq(optional), #3=cumulative }` —
  emitted periodically (~1/s) after a `#57` subscribe. **Vendor field names** (per knobunc's
  `OrbitPbApi_FlowSensorData`): `#1 currentFlowRateFrequency_Hz`, `#2 currentCycleRunTimeSec`,
  `#3 currentCycleVolumeTicks`, `#4 currentFlowRateGpm` (float), `#5 currentCycleVolumeGal` (float).
  Our `#1`≈flow-active reading is really the Hz field (~0 when dry); the direct `#4` gpm float is
  unverified-populated here (we derive gpm from the `#3` slope). **Hardware-characterized 2026-07-02
  on a live Gen2 run (BTValve01):**
  - **`#59.#3` is a CUMULATIVE per-run volume counter, NOT an instantaneous rate.** It climbs
    monotonically for the life of one valve-open (observed `33 → 489 → … → 2340` across a session),
    faster/slower as supply flow is varied, and resets on the next open. The **rate** is its slope
    (Δcounts/Δt). Decoded into `DeviceStatus.flow_total` (CLI) / `DeviceState.flow_total` (HA).
  - **`#59.#1` means "water currently flowing", NOT "valve open".** With the valve open but supply
    throttled to ~0, `#59.#1` reads `0` while the counter is flat. **Consequence for state decode:**
    `#59.#1` may only *assert* watering (flow ⇒ watering); it must never negate it (no-flow is
    ambiguous — the valve can be open and dry). `#16.#1` run-state is the authority for valve-open.
  - **Calibration (measured 2026-07-03):** `counts / FLOW_COUNTS_PER_GALLON` = gallons, with
    **`FLOW_COUNTS_PER_GALLON = 433`** — a 44.5 s window on BTValve01 logged **+1443 counts** while a
    bucket collected **3.33 gal** over the same window (`1443 / 3.33 = 433`); self-consistent, since
    3.33 gal / 44.5 s = 4.49 gpm matches the counter's slope at 433 counts/gal.
  - **HA surfacing = instantaneous gpm gauge, never a passive cumulative meter.** Because the counter
    only advances while a `#57` subscription is live, HA can't see a whole run passively — so instead
    of a `TOTAL_INCREASING` water meter (which would badly undercount), `read_flow()` samples the
    counter's slope over ~4 s and stores an instantaneous **`flow_gpm`**. Surfaced as a **"Flow rate"**
    sensor (gpm, **`state_class=MEASUREMENT`** → honest avg/min/max long-term stats, since each reading
    is a real slope of actual flow), updated automatically on the watering poll (live during a run)
    and on demand via a **"Check flow"** button / automation (spot check, or a leak check while idle:
    nonzero flow with the valve closed = a stuck valve). The counts→gallons scale is the configurable
    **"Flow calibration"** option (`CONF_FLOW_COUNTS_PER_GALLON`, default 433). For **cumulative
    gallons**, point users at HA's built-in Riemann-sum Integration helper on the gauge (README) —
    robust regardless of the counter's subscription-gap behaviour. The CLI `flow` command prints the
    same slope/gpm for bench checks.
- **`#7` device clock (wrapper field):** the device's own Unix epoch clock. Decoded by both the CLI
  (`DeviceStatus.device_clock`) and HA (`DeviceState.device_clock`, 2026-07-02) and used to anchor
  the rain-delay absolute expiry `#3` to the device rather than the host (the device honors `#3`
  literally — a host/device skew would otherwise end the delay early/late).

### Gen2 (HT25G2) parity + flow (2026-06-28 re-capture)

A Gen2 single-station valve (BTValve03, HT25G2-0001 fw `0111`) was driven through the same
subset (`captures/20260628_app_full_surface/decoded_g2.txt`, 70/70 frames CRC-valid). The
Gen2 uses a **different GATT handle layout** (notify on `0x0011`, not the XD's `0x0016`; the
decoder resolves handles by ATT behavior), but the **application protocol is byte-identical**:

- **Manual start** `#14{#1=2,#2{#3{#1=0,#2=120}}}`, **rain delay** `#17{#1=720(=12 h),…}`
  (RX `#16.#1=3`), and **program** `#19{#1=2 (slot B), #5{} (odd), #8=185 (03:05), …}` all
  match the XD encodings exactly — confirming one protocol across the HT34A/HT25G2 family.
- **Flow sensor is Gen2-only — hardware-confirmed 2026-07-02.** The Gen2 answered the `#57` poll
  with live `#59` flow frames; the XD, sent the same `#57` directly over BLE, returned **no `#59`
  at all** (10 s listen) — confirming it has no flow sensor (not just the app hiding the screen).
- Pre-existing programs are **read back on connect** (e.g. RX `#19` "Tomatoes And Peppers",
  even-days) — a basis for a future "get programs".

### Not observed over BLE (likely cloud-side attributes)

With the hub unplugged, two app actions produced **no BLE traffic**: the **zone rename**
(`ZoneTESTalpha` never appears on the wire) and the **per-zone default manual run-time**
(step 7). Treat these as cloud/account attributes, not local-BLE settable — confirm before
promising them as local features. (Program *names* do transmit, so naming per se is not the
blocker.) Smart-watering enable also failed in-app ("device has no internet connection"), so
its enable path is likewise cloud-gated.

## Notes on Behavior

- **No BLE bonding.** The device does not write to the host's `bt_config.conf` paired-devices table. It does not enforce link-layer pairing or LE Secure Connections.
- **No MAC enforcement.** The device does not validate the BLE link-layer source MAC of incoming writes. Confirmed by experiment with a spoofed adapter MAC.
- **ATT Write Command vs Write Request.** The device accepts both for short payloads. For longer payloads (≈ 25+ bytes), the device returns ATT Error 0x80 (Application Error) on Write Request but accepts Write Command. The custom integration uses Write Command for compatibility.
- **Replay protection.** The session-init handshake establishes a per-session IV/counter. Replaying a captured init message from a previous session does not work — the device tracks something across sessions (likely a counter in flash).
- **Duplicate RX notifications desync the CTR counter (transport gotcha, fix required).** Over an
  ESPHome BT proxy — especially while the vendor app is contending for the device's single BLE
  session — the *same* RX frame can be **re-delivered** as multiple identical notifications (observed
  2026-07-01: one XD dup after a valid decode; a Gen2 storm of ~60 byte-identical frames in 30 ms).
  Because RX is a continuous CTR stream, decrypting each delivery advances the per-direction counter
  once per frame, so every frame **after** the dup fails CRC and no further state is decoded. The
  fix (`connection.py::_on_notify`, `e0aa80b`) is to **drop a byte-identical re-delivery of the
  immediately-preceding frame** before buffering/decrypting/advancing. This is safe because the same
  plaintext at a new counter always yields *different* ciphertext, so identical consecutive
  ciphertext is definitionally a re-delivery. Reset the dedup marker on each new session (handshake
  and disconnect). Root cause of the re-delivery storm: the vendor app holding the device's single
  BLE session while the proxy also connects — close the app for clean captures.
- **A `#59` flow stream can desync the pooled RX counter (fix: reconnect to resync).** After a `#57`
  subscribe the device streams `#59` ~1/s and keeps going after the caller's drain window closes. On a
  long-lived pooled connection a single dropped `#59` (proxy loss) desyncs the per-direction RX
  counter, after which **every** later frame — the next `#59`, a `#15` reply, anything — fails CRC and
  decodes to garbage (hardware-observed 2026-07-03: an on-demand flow read on a *reused* session
  returned only undecodable frames, while the next poll, which reconnects fresh, decoded fine). A
  **fresh handshake re-seeds IV + counter and resyncs**. Fix: if a solicited read yields *no* decodable
  frame at all (distinct from a valid "flow 0" reply), drop the connection and retry once on a new
  session — `read_flow` does this, and the on-demand "Check flow" button connects fresh; the periodic
  poll already reconnects each cycle, so it's naturally immune.

## Verifying Your Connection

The simplest live test, after establishing a session:

- Send a timestamp-sync message setting the device clock to a recognizable value (e.g. `2000-01-01T00:00:00Z`). The B-Hyve LCD should immediately update to show that date/time.
- This confirms encryption, framing, trailer, and protobuf encoding are all correct, even if no valve actuates.
