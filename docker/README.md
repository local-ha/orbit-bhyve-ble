# Dockerized MQTT Bridge

This directory contains a `Dockerfile` and `docker-compose.yml` for running the standalone B-Hyve ↔ MQTT bridge in a container, suitable for setups that prefer MQTT-based control over the native Home Assistant integration.

## When to Use This vs. the HA Integration

**Use the HA integration** (`custom_components/orbit_bhyve_ble/`) if:
- You want auto-discovery, a config flow UI, and zero MQTT plumbing.
- You don't need to expose the device to non-HA systems.

**Use the MQTT bridge** if:
- You want the device addressable from any MQTT client (Node-RED, OpenHAB, custom dashboards, etc.).
- Your HA instance does not have direct Bluetooth access but a separate Linux box near the device does.
- You prefer to run BLE control on a small dedicated host (Raspberry Pi, mini-PC) and have Home Assistant talk to it via MQTT.

## Configuration

Copy `docker-compose.yml` and edit the environment variables:

| Variable | Meaning |
|---|---|
| `MQTT_BROKER` | Hostname or IP of your MQTT broker. |
| `MQTT_PORT` | MQTT broker port. Default 1883 (unencrypted). |
| `MQTT_USER` | MQTT broker username. |
| `MQTT_PASS` | MQTT broker password. |
| `BHYVE_MAC` | The B-Hyve BLE MAC address. |
| `BHYVE_KEY` | Your account's network key (32 hex chars). |
| `BHYVE_DURATION` | Default watering duration in seconds (used when an MQTT command does not specify one). |
| `BHYVE_ZONES` | Number of zones on your device (1, 2, or 4). |
| `BLE_ADAPTER` | Linux Bluetooth adapter to use (default `hci0`). |

## Running

```bash
docker compose up -d
docker compose logs -f
```

## MQTT Topics Exposed

| Topic | Direction | Payload |
|---|---|---|
| `bhyve/zone/<N>/set` | inbound | `"ON"` / `"OFF"` or `{"state":"ON","duration":300}` |
| `bhyve/all/set` | inbound | `"OFF"` (stop all) |
| `bhyve/zone/<N>/state` | retained | `"ON"` / `"OFF"` |
| `bhyve/status` | retained, LWT | `"online"` / `"offline"` |

`<N>` is the 1-indexed zone number.

## Example Home Assistant `configuration.yaml`

```yaml
mqtt:
  switch:
    - name: "B-Hyve Zone 1"
      command_topic: "bhyve/zone/1/set"
      state_topic: "bhyve/zone/1/state"
      payload_on: "ON"
      payload_off: "OFF"
      availability_topic: "bhyve/status"
    - name: "B-Hyve Zone 2"
      command_topic: "bhyve/zone/2/set"
      state_topic: "bhyve/zone/2/state"
      payload_on: "ON"
      payload_off: "OFF"
      availability_topic: "bhyve/status"
    # ... and so on for zones 3, 4
```

## Bluetooth Inside Docker — Caveats

The container needs access to the host's Bluetooth stack. The provided `docker-compose.yml` uses `network_mode: host` and `privileged: true` to keep configuration simple, plus mounts `/run/dbus` so BlueZ can be reached. This is the most reliable setup but is permissive.

A more locked-down setup is possible using Linux capabilities (`NET_ADMIN`, `NET_BIND_SERVICE`, optionally `NET_RAW`) and a specific bind for the host's HCI device, but it requires more host-side configuration. Refer to the BlueZ-in-Docker community guides if you want to go that route.

## Troubleshooting

**"Cannot connect to bhyve" in logs.**
- Confirm the device is in BLE range of the host.
- Confirm `BHYVE_MAC` matches your device.
- Try `bluetoothctl scan on` from the host to see if the device is visible at all.

**"AES decrypt failed" or "checksum mismatch".**
- Almost always a wrong `BHYVE_KEY`. Double-check it is 32 hex characters with no separators.

**"Zone N command had no effect".**
- Confirm you are using the latest version of this repository — the trailer-checksum fix is required for all zones beyond Zone 1 to work.
