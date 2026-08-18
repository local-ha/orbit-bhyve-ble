"""Reconfigure flow: re-discover devices without clobbering the user's choices.

entry.data["devices"] is a frozen snapshot — async_setup_entry never re-queries
the cloud, and re-running the config flow with the same email aborts on the
unique_id. So a device bought after setup was unreachable without deleting the
entry. These tests pin the flow that fixes it.

config_flow.py imports Home Assistant at module level, so this module is skipped
in the HA-less `tests` job and exercised by `tests-ha`. The flow handler is
driven DIRECTLY rather than through the flow manager: async_show_form and
async_abort are pure dict builders, so a fake hass plus a hand-set context is
enough — and it keeps the asyncio.run()-in-a-sync-test style used elsewhere in
this suite (see test_gen1_flow_lifecycle.py) instead of requiring pytest-asyncio.
"""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("homeassistant")

from orbit_bhyve import config_flow as cf  # noqa: E402
from orbit_bhyve.cloud import CloudAuthError, CloudConnectionError  # noqa: E402
from orbit_bhyve.const import (  # noqa: E402
    CONF_DEVICES,
    CONF_EMAIL,
    CONF_INCLUDE,
    CONF_KNOWN_CLOUD_IDS,
    CONF_PASSWORD,
)

KEY = "0123456789abcdef0123456789abcdef"


def _rec(cloud_id="a", **over):
    rec = {
        "cloud_id": cloud_id,
        "name": f"Valve {cloud_id}",
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


class _FakeEntry:
    def __init__(self, data):
        self.entry_id = "entry-1"
        self.data = data


class _FakeConfigEntries:
    """Records what the flow does to the entry."""

    def __init__(self, entry):
        self._entry = entry
        self.updated: list[dict] = []
        self.reloaded: list[str] = []

    def async_get_entry(self, entry_id):
        return self._entry if entry_id == self._entry.entry_id else None

    def async_update_entry(self, entry, data=None, **_kw):
        entry.data = data
        self.updated.append(data)

    async def async_reload(self, entry_id):
        self.reloaded.append(entry_id)


class _FakeHass:
    def __init__(self, entry):
        self.config_entries = _FakeConfigEntries(entry)


class _FakeCloud:
    """Stands in for OrbitCloudClient. `results` is consumed per discover()."""

    def __init__(self, results):
        self._results = list(results)

    async def discover(self, email, password):
        outcome = self._results.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _flow(monkeypatch, entry, results, source="reconfigure"):
    monkeypatch.setattr(cf, "async_get_clientsession", lambda hass: None)
    cloud = _FakeCloud(results)
    monkeypatch.setattr(cf, "OrbitCloudClient", lambda session: cloud)
    flow = cf.BHyveConfigFlow()
    flow.hass = _FakeHass(entry)
    flow.context = {"source": source, "entry_id": entry.entry_id}
    flow.flow_id = "test-flow"
    flow.handler = "orbit_bhyve"
    return flow


def _entry(devices, known=None, email="a@b.c", password="pw"):
    data = {CONF_EMAIL: email, CONF_PASSWORD: password, CONF_DEVICES: devices}
    if known is not None:
        data[CONF_KNOWN_CLOUD_IDS] = known
    return _FakeEntry(data)


def _defaults(result):
    """Pull the pre-checked cloud_ids out of a rendered picker form."""
    for key in result["data_schema"].schema:
        if key == CONF_INCLUDE:
            return list(key.default())
    raise AssertionError("no include key in schema")


def _labels(result):
    for key, validator in result["data_schema"].schema.items():
        if key == CONF_INCLUDE:
            return [o["label"] for o in validator.config["options"]]
    raise AssertionError("no include key in schema")


# --- picker defaults -------------------------------------------------------

def test_reconfigure_prechecks_new_device(monkeypatch):
    # The reported bug: a device bought after setup never showed up.
    entry = _entry([_rec("a")], known=["a"])
    flow = _flow(monkeypatch, entry, [[_rec("a"), _rec("b")]])
    result = asyncio.run(flow.async_step_reconfigure())
    assert result["type"] == "form"
    assert result["step_id"] == "reconfigure_devices"
    assert _defaults(result) == ["a", "b"]


def test_previously_excluded_device_stays_unchecked(monkeypatch):
    entry = _entry([_rec("a")], known=["a", "b"])
    flow = _flow(monkeypatch, entry, [[_rec("a"), _rec("b")]])
    result = asyncio.run(flow.async_step_reconfigure())
    assert _defaults(result) == ["a"]

    asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a"]}))
    assert [r["cloud_id"] for r in entry.data[CONF_DEVICES]] == ["a"]


def test_legacy_entry_without_known_ids_prechecks_all(monkeypatch):
    # Entries created before CONF_KNOWN_CLOUD_IDS existed never recorded what
    # was excluded, so everything unknown reads as new — once.
    entry = _entry([_rec("a")])
    flow = _flow(monkeypatch, entry, [[_rec("a"), _rec("b")]])
    result = asyncio.run(flow.async_step_reconfigure())
    assert _defaults(result) == ["a", "b"]

    asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a"]}))
    assert entry.data[CONF_KNOWN_CLOUD_IDS] == ["a", "b"]


def test_exclusions_stick_after_the_first_reconfigure(monkeypatch):
    entry = _entry([_rec("a")])
    flow = _flow(monkeypatch, entry, [[_rec("a"), _rec("b")]])
    asyncio.run(flow.async_step_reconfigure())
    asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a"]}))

    flow2 = _flow(monkeypatch, entry, [[_rec("a"), _rec("b")]])
    result = asyncio.run(flow2.async_step_reconfigure())
    assert _defaults(result) == ["a"]


# --- submit path -----------------------------------------------------------

def test_reconfigure_submit_updates_entry_and_aborts(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    flow = _flow(monkeypatch, entry, [[_rec("a"), _rec("b")]])
    asyncio.run(flow.async_step_reconfigure())
    result = asyncio.run(
        flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a", "b"]})
    )
    assert result["type"] == "abort"
    assert result["reason"] == "reconfigure_successful"
    assert [r["cloud_id"] for r in entry.data[CONF_DEVICES]] == ["a", "b"]
    assert flow.hass.config_entries.reloaded == ["entry-1"]


def test_empty_selection_reshows_form_with_error(monkeypatch):
    # vol.Required accepts [] on a multi-select, and an empty device list makes
    # async_setup_entry return False — the entry would brick silently.
    entry = _entry([_rec("a")], known=["a"])
    flow = _flow(monkeypatch, entry, [[_rec("a")]])
    asyncio.run(flow.async_step_reconfigure())
    result = asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: []}))
    assert result["type"] == "form"
    assert result["errors"] == {"base": "no_devices_selected"}
    assert flow.hass.config_entries.updated == []


def test_merge_preserves_hub_mesh_device_id_through_flow(monkeypatch):
    # End-to-end guard: a partial cloud response returning None must not drop
    # HT25 to the 0x0000 placeholder and start silently eating START frames.
    entry = _entry([_rec("a")], known=["a"])
    stale = _rec("a", hub_mesh_device_id=None, network_key=None, name="Renamed")
    flow = _flow(monkeypatch, entry, [[stale]])
    asyncio.run(flow.async_step_reconfigure())
    asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a"]}))
    kept = entry.data[CONF_DEVICES][0]
    assert kept["hub_mesh_device_id"] == 0xEB42
    assert kept["network_key"] == KEY
    assert kept["name"] == "Renamed"


# --- credentials -----------------------------------------------------------

def test_auth_failure_falls_back_to_password_prompt(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    flow = _flow(monkeypatch, entry, [CloudAuthError("nope")])
    result = asyncio.run(flow.async_step_reconfigure())
    assert result["type"] == "form"
    assert result["step_id"] == "reconfigure_auth"


def test_password_prompt_success_reaches_picker_and_persists_password(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    flow = _flow(monkeypatch, entry, [CloudAuthError("nope"), [_rec("a")]])
    asyncio.run(flow.async_step_reconfigure())
    result = asyncio.run(flow.async_step_reconfigure_auth({CONF_PASSWORD: "new-pw"}))
    assert result["step_id"] == "reconfigure_devices"

    asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a"]}))
    assert entry.data[CONF_PASSWORD] == "new-pw"


def test_password_prompt_shows_inline_error_on_second_failure(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    flow = _flow(monkeypatch, entry, [CloudAuthError("a"), CloudAuthError("b")])
    asyncio.run(flow.async_step_reconfigure())
    result = asyncio.run(flow.async_step_reconfigure_auth({CONF_PASSWORD: "wrong"}))
    assert result["step_id"] == "reconfigure_auth"
    assert result["errors"] == {"base": "invalid_auth"}


def test_missing_credentials_go_straight_to_password_prompt(monkeypatch):
    entry = _entry([_rec("a")], known=["a"], password="")
    flow = _flow(monkeypatch, entry, [[_rec("a")]])
    result = asyncio.run(flow.async_step_reconfigure())
    assert result["step_id"] == "reconfigure_auth"


def test_connection_failure_aborts_without_touching_entry(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    flow = _flow(monkeypatch, entry, [CloudConnectionError("down")])
    result = asyncio.run(flow.async_step_reconfigure())
    assert result["type"] == "abort"
    assert result["reason"] == "cannot_connect"
    assert flow.hass.config_entries.updated == []
    assert flow.hass.config_entries.reloaded == []


# --- devices the cloud no longer returns -----------------------------------

def test_disappeared_device_is_listed_and_prechecked(monkeypatch):
    entry = _entry([_rec("a"), _rec("b")], known=["a", "b"])
    flow = _flow(monkeypatch, entry, [[_rec("a")]])
    result = asyncio.run(flow.async_step_reconfigure())
    assert "b" in _defaults(result)
    assert any("no longer on the Orbit account" in lb for lb in _labels(result))


def test_disappeared_device_record_survives_verbatim(monkeypatch):
    gone = _rec("b", network_key=KEY, mesh_device_id=0x1234)
    entry = _entry([_rec("a"), gone], known=["a", "b"])
    flow = _flow(monkeypatch, entry, [[_rec("a")]])
    asyncio.run(flow.async_step_reconfigure())
    asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a", "b"]}))
    kept = next(r for r in entry.data[CONF_DEVICES] if r["cloud_id"] == "b")
    assert kept == gone


def test_unchecking_disappeared_device_removes_it(monkeypatch):
    entry = _entry([_rec("a"), _rec("b")], known=["a", "b"])
    flow = _flow(monkeypatch, entry, [[_rec("a")]])
    asyncio.run(flow.async_step_reconfigure())
    asyncio.run(flow.async_step_reconfigure_devices({CONF_INCLUDE: ["a"]}))
    assert [r["cloud_id"] for r in entry.data[CONF_DEVICES]] == ["a"]


# --- initial setup must be unchanged ---------------------------------------

def test_initial_setup_still_creates_entry(monkeypatch):
    entry = _entry([])
    flow = _flow(monkeypatch, entry, [[_rec("a"), _rec("b")]], source="user")
    flow._email = "a@b.c"
    flow._password = "pw"
    flow._discovered = [_rec("a"), _rec("b")]
    result = asyncio.run(flow.async_step_pick_devices({CONF_INCLUDE: ["a"]}))
    assert result["type"] == "create_entry"
    assert [r["cloud_id"] for r in result["data"][CONF_DEVICES]] == ["a"]
    # Both offered ids are recorded, so "b" reads as excluded — not new — next time.
    assert result["data"][CONF_KNOWN_CLOUD_IDS] == ["a", "b"]
    assert result["options"]


def test_initial_setup_rejects_empty_selection(monkeypatch):
    entry = _entry([])
    flow = _flow(monkeypatch, entry, [[_rec("a")]], source="user")
    flow._discovered = [_rec("a")]
    result = asyncio.run(flow.async_step_pick_devices({CONF_INCLUDE: []}))
    assert result["type"] == "form"
    assert result["errors"] == {"base": "no_devices_selected"}
