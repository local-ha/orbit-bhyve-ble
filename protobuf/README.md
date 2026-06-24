# Reconstructed Protobuf Schema

The file [`orbit_ble.proto`](orbit_ble.proto) in this directory is a **reconstructed interface description** for the messages used by the Orbit B-Hyve XD on its BLE data channel. It is not a copy of any vendor source code.

## How It Was Reconstructed

The schema was assembled from the following observations:

1. **Wire-format inspection.** Decrypted plaintexts (see [`../docs/encryption.md`](../docs/encryption.md)) were fed to `protoc --decode_raw` to dump field numbers and wire types. This produces a structural skeleton (e.g. `1: 0, 2: 600, 14: { ... }`) without field names.
2. **Behavioral inference.** Field numbers were correlated with observed device behavior — sending a message with field 1 set to N caused station N to actuate, sending field 2 set to S caused the run time to be S seconds, etc.
3. **Cross-referencing observable strings.** Where the official mobile application exposes message-class names through public Android APIs (e.g. via `android.util.Log` traces or `getClass().getSimpleName()` calls visible in BLE-write contexts), those names were used to label the corresponding reconstructed messages. Names like `OrbitPbApi_Message`, `TimerMode`, `ManualModeParams`, and `StationInfo` were obtained this way.
4. **Empirical validation.** The reconstructed schema was used to *encode* messages and send them to the device. If the device responded as expected, the field interpretation was validated. If not, the schema was adjusted until behavior matched.

The schema was therefore built from a combination of:

- Wire-level traffic that any owner of the device can capture with standard Android developer tools (HCI snoop log).
- Public-API-observable class names from the mobile application running on the project authors' own hardware.
- Targeted experiments with the device the project authors lawfully own.

No proprietary firmware or vendor source code was redistributed.

## Coverage

The schema in this repository covers what is needed to control a B-Hyve XD locally:

- `OrbitPbApi_Message` — the top-level message exchanged on the BLE data channel.
- `TimerMode` and `ManualModeParams` — for valve activation.
- `StationInfo` — to specify which valve and for how long.
- `DeviceControl` — for stop-watering and skip-current-station commands.
- `BleInitMsg` — used in the IPC top-level wrapper that surrounds device messages.

Many top-level fields exist in the protocol that this project did **not** reverse — anything related to scheduling, weather, sensors, programs, etc. — because they were not needed to satisfy the project's goal of HA-integrated manual zone control. If you extend this work, the schema will likely need extending too.

## Limitations of This Schema

- **Field names are approximations.** Where a name is not observable from public APIs, the schema uses descriptive English names (e.g. `runTimeSec` rather than the unknown internal token).
- **Field types may be looser than the vendor's.** The vendor likely uses `required` on many fields where this schema uses optional fields, because over-permissive types do not affect interoperability and are safer when names/constraints are uncertain.
- **No oneOf or oneof reconstruction.** Where the vendor likely uses `oneof` to group mutually-exclusive options, this schema uses optional fields. The device tolerates this.
- **Enum values were determined empirically** — `mode = 2` for manual mode was found by experiment, not extracted from any vendor source.

## Working With the Schema

To use the schema in Python:

```bash
pip install protobuf
protoc --python_out=. orbit_ble.proto
```

This produces `orbit_ble_pb2.py`, which you can import to construct messages programmatically. Alternatively, the integration in this repository builds the protobuf wire-format manually using `_pb_field_varint` and `_pb_field_bytes` helpers in `custom_components/orbit_bhyve_ble/bhyve_device.py` and avoids the `protobuf` runtime dependency entirely. That approach is simpler to vendor and less likely to break across `protoc` versions.
