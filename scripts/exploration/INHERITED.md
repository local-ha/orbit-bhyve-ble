# Inherited upstream-era scripts (flag only — not yet touched)

These scripts predate our work (committed in the initial upstream release, untouched since)
and are now largely **superseded** by the consolidated tooling. They are left in place for
now; pruning them is a separate fork-hygiene decision (they are upstream-authored, so removing
them has implications for the upstream relationship). Listed here so the redundancy is tracked.

| Inherited script | Superseded by | Notes |
|---|---|---|
| `scripts/bhyve_control.py` | `scripts/bhyve.py` | The old standalone CLI; `bhyve.py` is our fixed/maintained CLI. Duplicate send path. |
| `scripts/scan.py` | `scripts/exploration/scan_rssi.py` | 7-line bare scan; `scan_rssi.py` labels known valves + RSSI. |
| `scripts/exploration/explore_bhyve.py` | `decode_frame.py` / `live_test.py` | Early GATT exploration probe. |
| `scripts/exploration/explore_bhyve2.py` | `decode_frame.py` / `live_test.py` | Early GATT exploration probe. |
| `scripts/exploration/deep_explore.py` | `decode_frame.py` / `live_test.py` | Early GATT exploration probe. |
| `scripts/exploration/auth_probe.py` | `live_test.py` (session init) | Hardcodes an upstream device MAC. |
| `scripts/exploration/init_probe.py` | `live_test.py` (session init) | Hardcodes an upstream device MAC. |
| `scripts/exploration/protobuf_probe.py` | `decode_frame.py` (pb reader) | Early protobuf experiment. |
| `scripts/exploration/test_bhyve.py` | `live_test.py` | Ad-hoc connectivity test. |
| `scripts/extract_key.py`, `scripts/extract_networkkey.py` | — | Key-extraction utilities (still potentially useful; keep). |
| `scripts/bhyve_mqtt_bridge.py` | — | Upstream's MQTT bridge; out of scope for our BLE work. |

**Decision deferred.** If/when we do a fork-hygiene pass, prefer archiving over deleting for
the upstream-authored probes, and reconcile `bhyve_control.py` vs `bhyve.py` deliberately.
