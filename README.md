# Orbit B-Hyve BLE — Home Assistant integration

**Local BLE control for Orbit B-Hyve hose-tap and XD timers.** The Orbit cloud
is contacted only once, at setup, to discover your devices and fetch their BLE
network keys. After that every command, status poll, and schedule read happens
**over Bluetooth Low Energy** — your timers keep working when the WAN goes down,
and no telemetry leaves your network.

This branch (`integration`) is the capability-complete line: on top of local
valve control it decodes and exposes **real device state** (not optimistic),
**rain delay**, **flow** (Gen2), **watering programs A–D**, the **controller
mode**, and device **clock-sync** — all local. A standalone
[command-line tool](#command-line-tool) (`scripts/bhyve.py`) speaks the same
protocol for scripting and diagnostics.

---

## Contents

- [Supported hardware](#supported-hardware)
- [Capabilities by device family](#capabilities-by-device-family)
- [Install](#install)
- [Entities you get](#entities-you-get)
- [Services](#services)
- [Watering programs](#watering-programs)
- [For automations & agents](#for-automations--agents)
- [Options](#options)
- [Battery impact & polling cadences](#battery-impact--polling-cadences)
- [Cumulative water usage](#cumulative-water-usage-integration-helper)
- [How it works](#how-it-works)
- [Command-line tool](#command-line-tool)
- [Credits](#credits) · [Legal](#legal--ethical-notice)

---

## Supported hardware

| Family                | Hardware       | Firmware tested | Status |
|-----------------------|----------------|-----------------|--------|
| Hose-tap timer        | `HT25-0000`    | `0085`          | ✅ Actuated end-to-end (mesh protocol) |
| Hose-tap timer        | `HT25-0000`    | `0041`          | ✅ Actuated end-to-end (per-device mesh-ID addressing) |
| Hose-tap timer (Gen2) | `HT25G2-0001`  | `0111`          | ✅ Full stack, hardware-verified (protobuf protocol) |
| 4-port XD             | `HT34A-0001`   | `0107`          | ✅ Full stack, hardware-verified (protobuf protocol) |
| 4-port XD             | `HT34-0001`    | `0058`          | ⚠️ Shares the XD protobuf protocol; not tested here |
| 2-port XD             | `HT32A-0001`   | `0107`          | ✅ Actuated end-to-end (shares the HT34A XD protobuf protocol) |
| Hose-tap timer        | `HT31-0001`    | `0058`          | ✅ Actuated end-to-end (shares the HT34A XD protobuf protocol) |

> ⚠️ **Do NOT update your B-Hyve device firmware.** This integration was
> reverse-engineered against the firmware versions above. A firmware update may
> change the encryption protocol or trailer algorithm and break it. If the
> official B-Hyve app prompts you to update, decline.

Hubs (`BH1-0001` / `bridge` type) are filtered out at discovery — they don't
actuate anything, so they never appear in the device picker or registry.

## Capabilities by device family

There are **two protocol families**, and the advanced capabilities live on the
**protobuf family** only. Everything routes automatically by hardware/firmware —
you don't configure this.

| Capability | Mesh (`HT25-0000`, fw 0041/0085) | Protobuf (`HT25G2` Gen2, `HT34A`/`HT34`/`HT32A` XD) |
|---|:---:|:---:|
| Valve open/close + **real** run-state | ✅ (state is more optimistic) | ✅ device-truth (decoded `#16`) |
| Battery %, voltage, RSSI, diagnostics | ✅ | ✅ |
| Active-zone / seconds-remaining / auto-close | — | ✅ |
| **Rain delay** | — | ✅ |
| **Watering programs A–D** (read/write/enable) | — | ✅ |
| **Automatic-watering** (controller mode) | — | ✅ |
| **Flow rate + check-flow** | — | ✅ **Gen2 only** (XD has no flow sensor) |
| **Identify** (LED locate) | — | ✅ (no-op on the XD, harmless) |
| Clock-sync on poll | — | ✅ |

---

## Install

### HACS (recommended)

1. **HACS → Integrations → ⋮ → Custom repositories**
2. URL: `https://github.com/ljmerza/orbit-bhyve-ble` — Category: **Integration**
3. **Install** → **Orbit B-Hyve BLE** → **Restart Home Assistant**
4. **Settings → Devices & Services → Add Integration → “Orbit B-Hyve BLE”**
5. Enter your Orbit cloud **email + password**. The integration discovers every
   device on the account and fetches each one's BLE network key, then talks BLE
   only from then on.

### Manual

1. Copy `custom_components/orbit_bhyve/` into `<config>/custom_components/`
2. Restart HA → **Add Integration → “Orbit B-Hyve BLE”** → sign in.

**Range:** devices are reached through Home Assistant's Bluetooth stack, so any
**ESPHome Bluetooth proxy** (or the host's own adapter) in range of a valve will
carry it. No proxy needs to be dedicated to this integration.

---

## Entities you get

Entities use the standard `has_entity_name` scheme, so their IDs look like
`<platform>.<device>_<entity>` (e.g. `switch.btvalve01_program_a`). Slugs derive
from your device name/area, so treat the examples below as patterns.

**All BLE devices (mesh + protobuf):**

- **Valve** — one per physical station (`Zone` on single-station units, `Zone 1…4`
  on the XD). `valve.open_valve` / `valve.close_valve`. On the protobuf family the
  open/closed state is **decoded from the device** (`#16` run-state + active zone),
  not optimistic — so a run started by a schedule, the app, or a physical button
  shows up too. Attributes: `station`, `seconds_remaining`, `rain_delay_minutes`,
  `rain_delay_ends`, `last_command`, `last_command_at`.
- **Battery (%)** and **Battery voltage (mV)** — live, BLE-decoded on each poll.
  Voltage is disabled by default. (% is a linear approximation of the discharge
  curve; for NiMH cells trust the voltage — see the caveat in `docs/`.)
- **Signal strength (RSSI)** — from HA's Bluetooth manager; disabled by default.
- **Connected** (diagnostic) — true when the *last poll reached the device*
  (under the ephemeral model the link is torn down between polls, so this means
  poll-reachability, not a live socket).
- **Watering** — running/idle for the whole device.
- **Watering ends** (timestamp) — when the active run is expected to auto-close.
- **Last successful poll** (timestamp) and **Consecutive timeouts** (count) —
  diagnostics for BLE health.
- **Watering duration** (`number`, minutes) — the duration a valve uses when
  opened without an explicit one. Restored across restarts.
- **Sync** button — forces a fresh BLE connect + status read on demand.

**Protobuf family only (Gen2 + XD):**

- **Rain delay** (`number`, hours; 0 = off) + **Rain delay ends** (timestamp).
- **Program A / B / C / D** (`sensor`) — state is `enabled` / `disabled` /
  `empty`; the schedule detail is in attributes (`name`, `days`, `start_times`,
  `zones: [{zone, minutes}]`, `budget`). Populated from the periodic schedule
  read (see [freshness](#freshness--gotchas)).
- **Program A / B / C / D** (`switch`) — enable/disable a stored program. A slot
  with no program stored shows **unavailable**.
- **Automatic watering** (`switch`) — the device-global controller mode. On =
  scheduled programs run (autoMode); Off = all automatic watering disabled
  (offMode). Turning it off does **not** delete programs. When automatic
  watering is off, activating a Zone manually will turn it back on. This is
  from the device level, not the integration.
- **Next run** (timestamp) — the next scheduled program start; `programs`
  attribute lists which slot(s). `unknown` when nothing is armed (or the
  controller is off).
- **Identify** button — flashes the device LED to locate it (Gen2; a harmless
  no-op on the XD).

**Gen2 (`HT25G2`) only:**

- **Flow rate** (gal/min) + **Check flow** button — the only family with an
  inline flow sensor. Instantaneous rate sampled from the flow counter's slope;
  updates live during watering, or on demand via the button / an automation
  (leak-check while idle, "is water actually moving?"). It's a rate, not a meter —
  see [Cumulative water usage](#cumulative-water-usage-integration-helper).

---

## Services

| Service | Target | Purpose |
|---|---|---|
| `orbit_bhyve.start_watering` | valve `entity_id` | Start a zone for `duration` seconds (optional). |
| `orbit_bhyve.stop_all` | — | Stop watering on every configured device. |
| `orbit_bhyve.set_program` | `device_id` | Create/replace a program in slot A–D (protobuf family). |
| `orbit_bhyve.delete_program` | `device_id` | Clear a program slot A–D. |
| `orbit_bhyve.get_program` | `device_id` | **Returns a response** with the stored A–D schedules (reads live). |
| `orbit_bhyve.refresh_devices` | — | Re-query the cloud for new/changed devices + key rotation. Manual. |

There are also debug-only services (`probe_status`, `probe_send`, `probe_magic`)
used for protocol work — ignore them for normal use.

See [For automations & agents](#for-automations--agents) for exact call shapes,
the `get_program` response schema, and state semantics.

---

## Watering programs

Programs are the on-device schedules (the app calls them **A–D**; the hardware
has six slots and the integration also reads E/F via `get_program`). Each program
has **one day-mode**, one or more **start times** (device-local), and a per-zone
**run time**.

**Day-modes** (exactly one per program):

| `day_mode` | Meaning | Extra fields |
|---|---|---|
| `weekdays` | Specific weekdays | `weekdays: [mon, wed, fri]` |
| `interval` | Every N days | `interval_days: 3`, optional `interval_anchor` (ISO date) |
| `odd` | Odd calendar days | — |
| `even` | Even calendar days | — |
| `once` | One-time run | — |

**How “make it run” works.** Storing a program does not by itself schedule it —
the device computes a next start only once the program is **stored + enabled while
the controller is in autoMode**. The integration handles this for you:

- `set_program` with `enabled: true` runs the full store→enable→autoMode
  handshake and confirms a **Next run** was computed.
- The **Program A–D enable switch** arms/disarms an already-stored program
  (turning it on computes the next start; hardware-verified).
- The **Automatic watering** switch is the master control: with it **off**
  (offMode) nothing runs regardless of per-program enable flags, and **Next run**
  reads `unknown`.

Reads are **live** via `get_program`; the per-slot **sensors** reflect the last
periodic schedule read (see below).

### Freshness & gotchas

- **Program sensors/switches** are refreshed on the **idle poll** (default 15 min)
  or immediately after any program service/switch action or a **Sync** press.
  Right after a restart they read `empty` until the first schedule read lands —
  that's expected, not data loss.
- On a weak BLE link a schedule read can come back incomplete; the integration
  **keeps the last-known schedule** rather than blanking it, and refills on the
  next good cycle. For a guaranteed-current view, call `get_program` (it reads the
  device directly).
- Zones are **1-indexed** everywhere in the HA surface (Zone 1 = first station);
  run times are in **minutes** in services and sensor attributes.

---

## For automations & agents

This section is the machine-facing contract: exact call shapes, the response
schema, and state semantics.

### Targeting

- **Valve actions** (`start_watering`, `open`/`close`) target a **valve
  `entity_id`**.
- **Program actions** (`set_program`, `delete_program`, `get_program`) and the
  switches target a **device** (pass `device_id`, or use the UI device target).

### `set_program`

```yaml
action: orbit_bhyve.set_program
data:
  device_id: <device id>        # required (a single id or a list)
  slot: A                       # A | B | C | D  (required)
  day_mode: weekdays            # weekdays | interval | odd | even | once (required)
  weekdays: [mon, wed, fri]     # for day_mode: weekdays
  interval_days: 3              # for day_mode: interval
  interval_anchor: "2026-07-01T00:00:00-04:00"   # optional, for interval
  start_times: ["06:00", "18:00"]                # HH:MM device-local (required)
  zones:                        # required; per-zone run time in MINUTES
    - {zone: 1, minutes: 10}
    - {zone: 2, minutes: 7}
  name: "Front lawn"            # optional
  budget: 100                   # optional seasonal-adjust %, default 100
  enabled: true                 # optional; true = also arm it (compute Next run)
```

### `delete_program`

```yaml
action: orbit_bhyve.delete_program
data: { device_id: <device id>, slot: D }
```

### `get_program` (returns a response)

```yaml
action: orbit_bhyve.get_program
data: { device_id: <device id> }   # optional: slot: A  (omit for all slots)
response_variable: progs
```

Response shape:

```json
{
  "devices": {
    "BTValve01": [
      {
        "slot": "A", "empty": false, "enabled": true,
        "name": "Tomatoes And Peppers",
        "day_mode": "weekdays", "weekday_mask": 42,
        "interval_days": null, "interval_anchor": null,
        "start_times": ["05:00"],
        "zones": [{ "zone": 1, "minutes": 120 }],
        "budget": 100
      },
      { "slot": "E", "empty": true }
    ]
  }
}
```

`weekday_mask` is a bitmask, **bit 0 = Sunday … bit 6 = Saturday** (42 =
`0b0101010` = Mon+Wed+Fri). Empty slots return `{"slot": …, "empty": true}`.

### State semantics (for reading)

| Entity | State | Key attributes |
|---|---|---|
| `valve.*` | `open` / `closed` | `station`, `seconds_remaining` |
| `binary_sensor.*_watering` | `on` / `off` | — |
| `sensor.*_program_<a..d>` | `enabled` / `disabled` / `empty` | `name`, `days`, `start_times`, `zones`, `budget` |
| `switch.*_program_<a..d>` | `on` / `off` / `unavailable` | (`unavailable` = slot empty) |
| `switch.*_automatic_watering` | `on` (autoMode) / `off` (offMode) | — |
| `sensor.*_next_run` | timestamp / `unknown` | `programs` (list of slot letters) |
| `sensor.*_rain_delay_ends` | timestamp / `unknown` | — |
| `number.*_rain_delay` | hours (0 = off) | — |
| `sensor.*_flow_rate` | gal/min (Gen2) | — |

### Behavioral notes for agents

- **Enable ≠ run-now.** Enabling a program (switch on, or `enabled: true`)
  schedules its **next** start; it does not water immediately. To water now, use
  `orbit_bhyve.start_watering` on a valve.
- **Idempotent writes.** `set_program` replaces the slot wholesale; re-sending the
  same body is safe. `delete_program` on an empty slot is a no-op.
- **Confirm via read-back.** After a program write, the integration polls the
  device to confirm; for certainty, read `get_program` or the slot sensor after.
- **Clock is auto-synced.** Every poll sets the device clock to HA's time, so
  `start_times` fire at the intended real-world local time.

---

## Options

Configure under **Settings → Devices & Services → Orbit B-Hyve BLE → Configure**.
Changes apply **live, without a reload** — safe to tune mid-run.

- **Default watering duration** (sec) — for `start_watering` without a duration.
- **Disconnect after idle** (sec) — pooled BLE connection closes after this idle
  window to free the proxy slot.
- **Polling interval — idle** (sec, default 900) — state refresh cadence when
  nothing is watering. Also when the A–D schedules refresh.
- **Polling interval — watering** (sec, default 30) — faster cadence while a zone
  runs.
- **Flow calibration** (counts per gallon, default 433) — Gen2 flow-rate scale.
  Re-calibrate by running a known volume and dividing the flow-counter delta by
  the gallons collected. **A smaller number reports a *higher* gal/min** (rate =
  counts ÷ this ÷ time), so to *halve* the reading, *double* the number.

## Battery impact & polling cadences

Orbit valves run on 2× AA (~2,500–3,000 mAh). Each BLE poll is ~1.5–2 s of radio
(~12 mA avg). Two cadences balance responsiveness against battery life:

| Mode | Default | Conns/hr | ~Consumption | Expected AA life |
|:--|:--|:--|:--|:--|
| **Idle** | 900 s (15 min) | ~4 | ~0.02 mAh/hr | **12+ months** standby |
| **Watering** | 30–60 s | ~60 | ~0.35 mAh/hr | negligible (~0.7 mAh for a 2-hr run) |

> [!TIP]
> Heavy live-flow / auto-close tracking? Tightening **Watering** to 30 s is safe.
> Keep **Idle** at 900 s+ for battery longevity.

## Cumulative water usage (Integration helper)

The **Flow rate** sensor is an instantaneous rate, not a totalizer (the device's
flow counter only advances while HA is actively subscribed, and HA polls rather
than staying connected to spare batteries). For **gallons used** with proper
long-term stats, feed the Flow rate entity into HA's built-in
[Riemann-sum Integral](https://www.home-assistant.io/integrations/integration/)
helper — **Time unit: minutes** (the rate is gal/**min**), method left or
trapezoidal. The result carries `total_increasing` statistics for the
Energy/history dashboards. Accuracy is good for steady irrigation; the only error
source is flow variation *between* polls.

## How it works

1. **Setup (cloud, once):** sign in → fetch the device list → fetch one AES
   network key per mesh → cache it all in the config entry. No cloud traffic after.
2. **Connect-on-demand (ephemeral sessions):** for each command or poll the
   integration opens a fresh BLE connection, runs the AES-128 handshake + per-model
   init, sends the encrypted frame, reads the reply, then **cleanly disconnects**.
   This avoids ESPHome-proxy slot starvation, keeps the crypto counter from going
   stale, and spares batteries. Marginal links get a bounded handshake with a few
   clean retries instead of a wedged connection.
3. **Real state-sync (protobuf family):** each poll solicits the device's `#16`
   status and decodes run-state, active zone, seconds-remaining, battery,
   rain-delay, controller mode, and the next scheduled start — so HA reflects runs
   it didn't start (schedule / app / button) and auto-closes on the device's own
   timer. The poll doubles as a **clock-sync** (sets the device clock to HA time)
   so schedules fire at the right wall-clock hour.
4. **Multi-frame reads:** a full schedule dump streams as many BLE frames; the
   transport reassembles them, with a self-heal for counter desync and de-dup for
   proxy frame re-delivery.

The cipher (AES-128-ECB as a CTR keystream; frame trailer = `sum(plaintext) +
magic + len`) and the message catalog were reverse-engineered from captured
companion-app traffic and validated on owned hardware. Adding a model = drop a
`devices/htXX.py` and register it in `devices/__init__.py`.

Deep protocol docs: `docs/ble_protocol.md`, `docs/encryption.md`, and
`protobuf/orbit_ble.proto`.

## Command-line tool

`scripts/bhyve.py` (on this branch) is a standalone CLI that speaks the same
protocol using the host's own BLE adapter — handy for scripting and diagnostics
without HA. It reads device MAC/keys from a config file (`$BHYVE_CONFIG`).

```
python scripts/bhyve.py status                 # battery + run-state
python scripts/bhyve.py on 1 300               # zone 1 for 5 minutes
python scripts/bhyve.py off                    # stop
python scripts/bhyve.py rain-delay set 24      # 24-hour rain delay
python scripts/bhyve.py program list           # dump all program slots
python scripts/bhyve.py program set A --days mon,wed,fri --start 06:00 \
       --zones 1:300 --name Front --enable
python scripts/bhyve.py clock sync             # set the device clock
```

Run `python scripts/bhyve.py --help` for the full command set. The CLI is the
byte-level reference the HA integration mirrors (a test suite asserts they emit
identical frames).

## Credits

The marginal-link connection hardening (bounded handshake + retry, capped
write-ack), the per-command re-bind for HT25 actuation, the RSSI and
connectivity/watering sensors, and the HT34/HT34A battery + watering-status decode
were ported from
[@stuartdenne](https://github.com/stuartdenne/ha-orbit-bhyve-ble-old)'s fork.
Protocol cross-checks build on prior community reverse-engineering (wxfield,
knobunc, and others).

## Legal & ethical notice

This project documents the protocol of a device the authors lawfully purchased and
own. Reverse engineering for interoperability with hardware you own is protected in
the United States under 17 U.S.C. §1201(f). The protocol descriptions here were
reconstructed from observation of the device's wire-level BLE traffic and from
analysis of the publicly distributed companion mobile application. The authors are
not affiliated with Orbit Irrigation Products Inc.

[MIT](LICENSE).
