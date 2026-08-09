"""Record-merge + picker-selection rules for cloud re-discovery.

No Home Assistant imports at module level — same rule as diagnostics.py — so
these rules stay unit-testable under tests/conftest.py's HA-less namespace shim.

Shared by the reconfigure flow (config_flow.py) and the refresh_devices service
(refresh.py) so both apply identical semantics: new devices get added, devices
the user excluded stay excluded, and a degraded cloud response never destroys a
working device record.
"""
from __future__ import annotations

from typing import Any

# Fields where a blank fresh value must NOT clobber a good stored one.
# cloud._join_device legitimately returns None for all of these on a partial
# response, and each one is load-bearing:
#   network_key        base.py reads it to derive the AES session; no key, no BLE
#   mesh_device_id     ht25.mesh_address raises RuntimeError when it's missing
#   hub_mesh_device_id ht25.hub_mesh_address falls back to a 0x0000 placeholder,
#                      which silently drops START frames on some meshes
#   bridge_device_id   hub_mesh_device_id is derived from it (cloud.py:227-230)
#   mesh_id / mac      identity; a blank is always a cloud-schema gap
#   stations           valve.py sizes the zone list off it, so 0 deletes zones
STICKY_FIELDS = (
    "network_key",
    "mesh_device_id",
    "hub_mesh_device_id",
    "bridge_device_id",
    "mesh_id",
    "mac",
    "stations",
)


def _blank(value: Any) -> bool:
    """None / "" / 0 all mean "the cloud didn't tell us" for a sticky field."""
    return value is None or value == "" or value == 0


def merge_device_record(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Fresh discovery wins, except a blank fresh value on a STICKY_FIELDS key.

    Volatile fields (name, firmware, battery_pct, ...) are never sticky — a
    battery_pct of 0 is a real reading, not a missing one.
    """
    merged = {**old, **new}
    for field in STICKY_FIELDS:
        if _blank(merged.get(field)) and not _blank(old.get(field)):
            merged[field] = old[field]
    return merged


def merge_device_lists(
    stored: list[dict[str, Any]],
    discovered: list[dict[str, Any]],
    selected_ids: set[str],
) -> list[dict[str, Any]]:
    """Build the new entry.data["devices"] from a picker selection.

    Discovered records are merged onto their stored counterpart; selected
    devices the cloud no longer returns are carried over VERBATIM so they keep
    working over BLE. Order is discovery order, then stored-only survivors, so
    the list stays stable across runs.
    """
    by_stored = {r["cloud_id"]: r for r in stored if r.get("cloud_id")}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in discovered:
        cid = rec.get("cloud_id")
        if not cid or cid not in selected_ids:
            continue
        old = by_stored.get(cid)
        out.append(merge_device_record(old, rec) if old else rec)
        seen.add(cid)
    for rec in stored:
        cid = rec.get("cloud_id")
        if cid and cid in selected_ids and cid not in seen:
            out.append(rec)
    return out


def default_selection(
    stored_ids: list[str],
    known_ids: list[str] | None,
    catalogue_ids: list[str],
) -> list[str]:
    """Picker pre-check set: currently-kept devices ∪ never-seen-before devices.

    known_ids is None on entries created before CONF_KNOWN_CLOUD_IDS existed.
    Those entries never recorded what the user excluded, so the fallback treats
    every unknown id as new and pre-checks it ONCE — the alternative (pre-check
    only what's kept) would mean a legacy user's newly-bought device isn't
    pre-checked, i.e. the feature fails on exactly the entries that need it.
    """
    kept = set(stored_ids)
    known = set(known_ids) if known_ids is not None else kept
    return [cid for cid in catalogue_ids if cid in kept or cid not in known]


def next_known_ids(
    known_ids: list[str] | None,
    stored_ids: list[str],
    catalogue_ids: list[str],
) -> list[str]:
    """Everything ever offered, so exclusions stick from this submit onward."""
    return sorted(set(known_ids or []) | set(stored_ids) | set(catalogue_ids))
