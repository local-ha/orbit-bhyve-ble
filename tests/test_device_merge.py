"""Cloud re-discovery merge rules: never lose a working device record.

Covers merge.py, shared by the reconfigure flow and the refresh_devices service.
The load-bearing case is a partial cloud response returning None for a field the
BLE layer depends on — under a naive fresh-wins merge that silently bricks a
working HT25 with only a log warning. No hardware or Home Assistant required.
"""
from __future__ import annotations

from orbit_bhyve.merge import (
    default_selection,
    merge_device_lists,
    merge_device_record,
    next_known_ids,
)

KEY = "0123456789abcdef0123456789abcdef"


def _rec(cloud_id="a", **over):
    rec = {
        "cloud_id": cloud_id,
        "name": "Deck",
        "mac": "AA:BB:CC:DD:EE:FF",
        "type": "sprinkler_timer",
        "hardware": "HT25-0000",
        "firmware": "0085",
        "stations": 1,
        "mesh_id": "mesh-1",
        "mesh_device_id": 0x47D7,
        "bridge_device_id": "bridge-1",
        "hub_mesh_device_id": 0xEB42,
        "network_key": KEY,
        "battery_pct": 88,
        "battery_mv": 3100,
    }
    rec.update(over)
    return rec


# --- merge_device_record: sticky fields ------------------------------------

def test_blank_fresh_hub_mesh_device_id_does_not_clobber_stored():
    # The regression this whole module exists for: cloud.get_mesh walks three
    # endpoint schemas and not all carry bridge_device_id, so hub_mesh_device_id
    # comes back None. Losing it drops HT25 to the 0x0000 placeholder and
    # watering commands get silently dropped.
    merged = merge_device_record(_rec(), _rec(hub_mesh_device_id=None))
    assert merged["hub_mesh_device_id"] == 0xEB42


def test_blank_fresh_network_key_does_not_clobber_stored():
    # _b64_to_hex swallows every exception and returns None on a decode failure.
    assert merge_device_record(_rec(), _rec(network_key=None))["network_key"] == KEY
    assert merge_device_record(_rec(), _rec(network_key=""))["network_key"] == KEY


def test_zero_mesh_device_id_treated_as_blank():
    # 0x0000 is ht25.py's placeholder, never a real mesh id.
    merged = merge_device_record(_rec(), _rec(mesh_device_id=0))
    assert merged["mesh_device_id"] == 0x47D7


def test_zero_stations_does_not_delete_zones():
    # cloud._join_device does int(num_stations or 0); valve.py sizes zones off it.
    merged = merge_device_record(_rec(stations=4), _rec(stations=0))
    assert merged["stations"] == 4


def test_blank_bridge_device_id_and_mesh_id_are_sticky():
    merged = merge_device_record(_rec(), _rec(bridge_device_id=None, mesh_id=""))
    assert merged["bridge_device_id"] == "bridge-1"
    assert merged["mesh_id"] == "mesh-1"


def test_non_blank_fresh_wins_on_sticky_field():
    # Key rotation must actually take effect.
    rotated = "f" * 32
    merged = merge_device_record(_rec(), _rec(network_key=rotated))
    assert merged["network_key"] == rotated


def test_volatile_fields_always_take_fresh_value():
    merged = merge_device_record(
        _rec(),
        _rec(name="Front Yard", firmware="0098", battery_pct=0, battery_mv=None),
    )
    assert merged["name"] == "Front Yard"
    assert merged["firmware"] == "0098"
    # 0% is a real battery reading, not a missing one — must not be restored.
    assert merged["battery_pct"] == 0
    assert merged["battery_mv"] is None


def test_stored_only_keys_survive_the_merge():
    merged = merge_device_record(_rec(extra="keep-me"), _rec())
    assert merged["extra"] == "keep-me"


# --- merge_device_lists ----------------------------------------------------

def test_merge_lists_adds_new_and_drops_unselected():
    stored = [_rec("a")]
    discovered = [_rec("a"), _rec("b"), _rec("c")]
    got = merge_device_lists(stored, discovered, {"a", "b"})
    assert [r["cloud_id"] for r in got] == ["a", "b"]


def test_merge_lists_keeps_vanished_device_verbatim():
    # Cloud discovery is not authoritative about existence: discover() silently
    # skips bridges and anything without a mesh_id. A device missing from one
    # response must not lose its key.
    stored = [_rec("a"), _rec("b", network_key=KEY, mesh_device_id=0x1234)]
    got = merge_device_lists(stored, [_rec("a")], {"a", "b"})
    survivor = next(r for r in got if r["cloud_id"] == "b")
    assert survivor == stored[1]


def test_merge_lists_order_is_discovery_then_survivors():
    stored = [_rec("z"), _rec("a")]
    discovered = [_rec("a"), _rec("m")]
    got = merge_device_lists(stored, discovered, {"a", "m", "z"})
    assert [r["cloud_id"] for r in got] == ["a", "m", "z"]


def test_merge_lists_applies_sticky_merge_per_record():
    stored = [_rec("a")]
    discovered = [_rec("a", hub_mesh_device_id=None, name="Renamed")]
    got = merge_device_lists(stored, discovered, {"a"})
    assert got[0]["hub_mesh_device_id"] == 0xEB42
    assert got[0]["name"] == "Renamed"


def test_merge_lists_empty_selection_yields_empty_list():
    assert merge_device_lists([_rec("a")], [_rec("a")], set()) == []


# --- default_selection -----------------------------------------------------

def test_default_selection_keeps_exclusions_excluded():
    assert default_selection(["a"], ["a", "b"], ["a", "b"]) == ["a"]


def test_default_selection_prechecks_never_seen_device():
    assert default_selection(["a"], ["a"], ["a", "c"]) == ["a", "c"]


def test_default_selection_legacy_entry_prechecks_everything():
    # known_ids is None on entries created before CONF_KNOWN_CLOUD_IDS existed:
    # they never recorded exclusions, so everything unknown reads as new. The
    # user unchecks once and it sticks from then on.
    assert default_selection(["a"], None, ["a", "b"]) == ["a", "b"]


def test_default_selection_preserves_catalogue_order():
    assert default_selection(["b"], ["a", "b"], ["a", "b", "c"]) == ["b", "c"]


def test_default_selection_keeps_vanished_but_configured_device():
    # A stored device absent from fresh discovery is still in the catalogue and
    # must stay pre-checked, or a flaky cloud response silently removes it.
    assert default_selection(["a", "b"], ["a", "b"], ["a", "b"]) == ["a", "b"]


# --- next_known_ids --------------------------------------------------------

def test_next_known_ids_is_monotonic_union():
    assert next_known_ids(["a"], ["b"], ["c"]) == ["a", "b", "c"]


def test_next_known_ids_from_legacy_none():
    assert next_known_ids(None, ["a"], ["a", "b"]) == ["a", "b"]


def test_next_known_ids_never_shrinks():
    # A device dropped from both the entry and the cloud stays known, so
    # re-appearing later doesn't read as brand new and resurrect itself.
    assert next_known_ids(["a", "b"], [], ["c"]) == ["a", "b", "c"]
