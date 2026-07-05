# Orbit B-Hyve BLE — Home Assistant integration

**Local BLE control for Orbit B-Hyve hose-tap and XD timers.** Cloud is
contacted only at setup to discover devices and fetch network keys. After
setup, every command and state poll is BLE-only — your timers keep working
when the WAN goes down.

## Supported hardware

| Family            | Hardware       | Firmware tested | Status                                  |
|-------------------|----------------|------------------|------------------------------------------|
| Hose-tap timer    | `HT25-0000`    | `0085`           | ✅ Actuated end-to-end                   |
| Hose-tap timer    | `HT25-0000`    | `0041`           | ✅ Actuated end-to-end (per-device mesh-ID addressing) |
| Hose-tap timer (Gen2) | `HT25G2-0001` | `0111`          | ✅ Actuated end-to-end (protobuf protocol) |
| 4-port XD         | `HT34A-0001`   | `0107`           | ✅ Actuated end-to-end (community-verified) |
| 4-port XD         | `HT34-0001`    | `0058`           | ⚠️ Shares the XD protobuf protocol; not tested here |
| 2-port XD         | `HT32A-0001`   | `0107`           | ⚠️ Shares the HT34A XD protobuf protocol; not tested here |

> ⚠️ **Do NOT update your B-Hyve device firmware.** This integration was
> reverse-engineered against the firmware versions above. A firmware update
> may change the encryption protocol or trailer algorithm. If the official
> B-Hyve app prompts you to update, decline.

## Install via HACS (recommended)

1. **HACS → Integrations → ⋮ menu → Custom repositories**
2. URL: `https://github.com/ljmerza/orbit-bhyve-ble` — Category: **Integration**
3. Click **Install** on **Orbit B-Hyve BLE**
4. Restart Home Assistant
5. **Settings → Devices & Services → Add Integration → "Orbit B-Hyve BLE"**
6. Enter your Orbit cloud email + password — the integration discovers all
   devices on the account and fetches each one's BLE network key

## Manual install

1. Copy `custom_components/orbit_bhyve/` into `<config>/custom_components/`
2. Restart HA
3. **Settings → Devices & Services → Add Integration → "Orbit B-Hyve BLE"**

## What you get

Per discovered sprinkler device:

- **Valve** per physical station (HT25 = 1, HT34A/HT34 = up to 4) — uses
  `valve.open_valve` / `valve.close_valve`. Open/closed state is
  **optimistic** (derived from the last command, not from a decoded
  device status).
- **Battery (%)** sensor — live, BLE-sourced. Decoded from the device's
  info-ack frame on every poll, no cloud round-trip after setup.
- **Battery voltage (mV)** sensor — same source as the percent sensor;
  disabled by default, enable it from the entity's settings if you want
  the raw reading.
- **Signal strength (RSSI)** sensor — the BLE advertisement RSSI from
  Home Assistant's bluetooth manager (works even while disconnected);
  disabled by default.
- **Connected** and **Watering** binary sensors — device connectivity
  (diagnostic) and whether a station is currently running, for automations
  and dashboards.
- **Default watering duration** (`number` entity, minutes) — per device.
  The valve uses this when `start_watering` is called without an
  explicit duration. Restored across HA restarts.
- **Sync** button per device — forces a fresh BLE connect + init
  handshake. Useful after a long idle, or to refresh the battery
  reading on demand without waiting for the next poll.
- **Flow rate** sensor (gal/min) + **Check flow** button — **Gen2 (HT25G2)
  only**, which is the only model with an inline flow sensor. The rate is
  sampled from the device's flow counter and updates live during watering; the
  button (or an automation) triggers an on-demand spot check — handy to confirm
  water is actually moving, or as a leak check while idle. It's an instantaneous
  rate, not a meter — see *Cumulative water usage* below for gallons.
- Manufacturer / model / firmware / MAC are exposed via the device's
  "Device info" panel.

Hubs (`BH1-0001`) are filtered out at discovery — they don't actuate
anything, so they don't appear in the device picker or the device
registry.

## Services

- `orbit_bhyve.start_watering` — `entity_id` + optional `duration` (sec)
- `orbit_bhyve.stop_all` — stop everything on the targeted device
- `orbit_bhyve.refresh_devices` — re-query the cloud (for new devices, key
  rotation, or fw changes); manual, no background polling

## Options flow

- **Default watering duration** (sec) — used when `start_watering` is called
  without an explicit duration
- **Disconnect after idle** (sec) — pooled BLE connection closes after this
  many seconds idle to free the proxy slot
- **Polling interval — idle** (sec) — how often to refresh state when no
  station is watering
- **Polling interval — watering** (sec) — faster polling while a station is
  active
- **Flow calibration** (sensor counts per gallon) — Gen2 flow-rate scale. The
  default (433) was measured on real hardware; re-calibrate for your own valve by
  running a known volume and dividing the flow counter's delta by the gallons
  collected (the `flow` CLI prints the delta). Only affects the Flow rate sensor.
  Note: a smaller number reports a *higher* gal/min (rate = counts ÷ this ÷ time),
  so to *halve* the reading you *double* the number.

Option changes apply **live, without a reload** — they take effect on the next
poll, so you can tune them mid-run without disturbing an active watering. (The
options *form* itself only appears after the first restart that installs a new
version.)

### Battery Impact & Polling Cadences

Because Orbit B-Hyve valves run on 2× AA batteries (roughly ~2,500–3,000 mAh capacity), every BLE poll involves ~1.5–2 seconds of radio activity (~12 mA average current during connection). To balance responsiveness against battery life, the integration uses two separate polling schedules:

| Cadence Mode | Default Interval | Connections / Hour | Est. Battery Consumption | Expected AA Battery Life |
| :--- | :--- | :--- | :--- | :--- |
| **Passive (Idle)** | 900 seconds (15 min) | ~4 conns / hr | ~0.02 mAh / hour | **12+ months** (normal standby) |
| **Active (Watering)** | 60 seconds (1 min) | ~60 conns / hr | ~0.35 mAh / hour | **Negligible impact** during typical runs (~0.7 mAh for a 2-hr run; < 0.03% of total battery capacity) |

> [!TIP]
> If you rely heavily on live flow gauges or rapid auto-close tracking during long watering sessions, you can safely tighten the **Watering** poll interval to 30 seconds without noticeably degrading seasonal battery life. For **Idle** periods, keeping the interval at 900 seconds (or higher) is recommended to maximize battery longevity.

## Cumulative water usage (Integration helper)

The **Flow rate** sensor is an instantaneous rate, not a totalizer — the device's
flow counter only advances while HA is actively subscribed, and HA polls (rather
than staying connected) to spare the valve's batteries, so a passive water-meter
reading would badly undercount. To get **gallons used** with proper long-term
statistics, integrate the rate with Home Assistant's built-in
[Riemann sum integral](https://www.home-assistant.io/integrations/integration/)
helper:

1. **Settings → Devices & Services → Helpers → Create Helper → Integral sensor**.
2. **Input sensor:** the device's *Flow rate* entity. **Metric prefix:** none;
   **Time unit:** minutes (the rate is gal/**min**); **Integration method:** left
   (or trapezoidal). Name it e.g. *BTValve01 Water used*.
3. The resulting sensor accumulates gallons and carries `total_increasing`
   statistics, so it can feed the Energy/water dashboard and long-term history.

Accuracy is good for steady irrigation (e.g. drip zones); the only error source
is flow variation *between* polls — tighten the watering poll interval if you
want finer resolution (at some battery cost).

## How it works

1. **Setup**: log into Orbit cloud once → fetch device list → fetch one AES
   network key per mesh → cache everything in the config entry
2. **Connect-on-Demand (Ephemeral)**: whenever a command is sent or a scheduled status poll occurs, the integration opens a fresh BLE connection, completes the AES-128 handshake and model init sequence, sends the encrypted frame, and reads back the confirmation.
3. **Radio & Proxy Release**: as soon as the command or status read completes, the BLE connection is cleanly closed (`disconnect`). This prevents proxy slot starvation on ESPHome devices, eliminates cryptographic counter desynchronization from stale sessions, and spares valve batteries. Marginal proxy links get a bounded handshake with a few clean retries instead of a wedged connection.

The cipher (AES-128-ECB used as a CTR-style keystream, frame trailer =
`sum(plaintext) + magic + len`) was reverse-engineered against captured
phone-app traffic. Different hardware families (HT25 vs HT34A) use different
inner plaintext formats and different magic bytes; the per-model device
classes encode that. Adding a new model = drop a `devices/htXX.py` and
register it.

## Credits

The marginal-link connection hardening (bounded handshake + retry, capped
write-ack), the per-command re-bind for HT25 actuation, the RSSI and
connectivity/watering sensors, and the HT34/HT34A battery + watering-status
decode were ported from
[@stuartdenne](https://github.com/stuartdenne/ha-orbit-bhyve-ble-old)'s fork.

## Legal & ethical notice

This project documents the protocol of a device the project authors
lawfully purchased and own. Reverse engineering for the purpose of
interoperability with hardware you own is protected in the United States
under 17 U.S.C. §1201(f). The protocol descriptions in this repository
were reconstructed from observation of the device's wire-level BLE traffic
and from analysis techniques applied to the publicly distributed companion
mobile application. The authors are not affiliated with Orbit Irrigation
Products Inc.

[MIT](LICENSE).
