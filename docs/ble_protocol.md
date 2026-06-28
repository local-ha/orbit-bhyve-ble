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
| `#16` | **Device status / state** (pushed on connect and on every state change) | `#1` mode (`1`=idle, `4`=manual running); `#10` next-event Unix ts; `#13 {#1, #3 last-event ts, #4}`; **`#14 {#3 = battery mV}`**; `#16` 8-byte constant token |
| `#46` | **Battery report** (standalone) | `#3 = battery mV` (same `{#3: mV}` shape as `#16.#14`) |
| `#23` | **Device info** | `#2` model string (`HT25G2-0001`); `#3` firmware string (`0111`) |
| `#19` | **Program / schedule** | `#10`, `#11` Unix ts; `#17` program name (UTF-8, e.g. `"Blueberries And Strawberries"`) |
| `#59` | **Watering status** (periodic) | `#1` active flag (`0` = not watering); `#3` |
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
  device reliably pushes a `#16` status (the CLI's `status` command depends on this). While a
  zone is **actively watering**, the connect-time push is unreliable — sometimes only a minimal
  clock-bearing ack arrives, sometimes nothing — so a passive mid-run `status` may come up
  empty even though the connection succeeded.

**Implication / TODO.** A dependable *mid-run* status read needs a benign **"request status"
TX** to elicit the burst rather than waiting for a volunteered push. The app's timestamp-sync
message (see "Verifying Your Connection") is a known status-eliciting write and a good RE
starting point; capture it and add it to the TX command catalog.

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
| **Set clock (timestamp-sync)** | `#18 { #1 = "YYYY-MM-DDThh:mm:ss±hh:mm" }` | ISO-8601 local string; sent on connect. Benign liveness check. |
| **Set / clear rain delay** | `#17 { #1=minutes; #3=expiryUnixUTC; #4=1 }` | `minutes=0` clears. `expiry = deviceClock + minutes·60`. Confirmed 1440=24 h, 2880=48 h. |
| **Create / edit program** | `#19 { … }` | Full schema below. |
| Connect-time queries (unconfirmed) | `#20 {#1=0}`, `#75 {#1=unixTs; #2=mask}`, `#120 {#1: empty}`, device-info request → RX `#23` | Sent during handshake; exact purpose TBD. |

### Watering program message (`#19`)

Captured by editing one advanced program (name `OurAdvancedProgram`) through every day-mode.

| Field | Meaning | Observed |
|---|---|---|
| `#1` | program slot id | `1` |
| `#8` (repeated varint) | **start times**, minutes-of-day | `360` (06:00), `1080` (18:00) |
| `#9 { #1=zoneIndex; #2=runSec }` (repeated) | **per-zone run durations** | Z0=300, Z1=420, Z2=540, Z3=660 (5/7/9/11 min) |
| `#10` | budget / seasonal-adjust % | `100` |
| `#11` | schedule **start** date (Unix) | set |
| `#12` | schedule **end** date (Unix) | present for a date; **omitted ⇒ "Never"** |
| `#17` | program **name** (UTF-8) | `OurAdvancedProgram` |
| `#14`,`#15`,`#16`,`#18`,`#21`,`#22` | enable/flags + date boundaries | small varints / midnight Unix ts |

**Watering-days mode (mutually exclusive — exactly one present):**

| Mode | Encoding | Evidence |
|---|---|---|
| Specific weekdays | `#3 { #1 = bitmask }`, **bit0=Sun … bit6=Sat** | all=`127`, Mon/Wed/Fri=`42` (bits 1,3,5) |
| Every N days | `#4 { #1 = N; #2 = anchor ISO date }` | N=`3` |
| Odd days | `#5 {}` (empty marker) | — |
| Even days | `#6 {}` (empty marker) | — |

### RX additions (device→host, on `6c73`)

- **Run-state `#16.#1`:** extend the table to `1`=idle, **`3`=rain-delay active**, `4`=manual running.
- **`#16.#13` rain-delay status:** `{ #1=minutes, #3=expiryUnix, #4=enabled(0/1) }` — echoes the
  `#17` set command (idle shape is the shorter `{ #1=0, #4=0 }`).
- **`#16.#2`** echoes the active manual run (`{#1=2, #2{#3{stationId,runSec}}}`); **`#16.#6`**
  carries run progress (`#5` total sec, `#7` remaining sec, `#6{…}`).
- **`#19` program** is echoed back on read/save (start times re-emitted as `#8 { #45 = value }`).
- **`#30`** small command ack around start/stop/clear.

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

## Verifying Your Connection

The simplest live test, after establishing a session:

- Send a timestamp-sync message setting the device clock to a recognizable value (e.g. `2000-01-01T00:00:00Z`). The B-Hyve LCD should immediately update to show that date/time.
- This confirms encryption, framing, trailer, and protobuf encoding are all correct, even if no valve actuates.
