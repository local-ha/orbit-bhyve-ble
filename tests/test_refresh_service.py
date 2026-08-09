"""refresh_devices merges instead of clobbering.

The old handler wrote data={**entry.data, "devices": discovered} — the full
discovery result — so every excluded device came back and a partial cloud
response overwrote working network keys with None. Same HA-guard and
direct-drive style as test_config_flow.py.
"""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("homeassistant")

from homeassistant.exceptions import HomeAssistantError  # noqa: E402

from orbit_bhyve import refresh as rf  # noqa: E402
from orbit_bhyve.cloud import CloudAuthError, CloudConnectionError  # noqa: E402
from orbit_bhyve.const import (  # noqa: E402
    CONF_DEVICES,
    CONF_EMAIL,
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
        self.reauth_started = 0

    def async_start_reauth(self, hass):
        self.reauth_started += 1


class _FakeConfigEntries:
    def __init__(self):
        self.updated: list[dict] = []
        self.reloaded: list[str] = []

    def async_update_entry(self, entry, data=None, **_kw):
        entry.data = data
        self.updated.append(data)

    async def async_reload(self, entry_id):
        self.reloaded.append(entry_id)


class _FakeHass:
    def __init__(self):
        self.config_entries = _FakeConfigEntries()


def _setup(monkeypatch, outcome):
    monkeypatch.setattr(rf, "async_get_clientsession", lambda hass: None)

    class _Cloud:
        async def discover(self, email, password):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    monkeypatch.setattr(rf, "OrbitCloudClient", lambda session: _Cloud())
    return _FakeHass()


def _entry(devices, known=None, email="a@b.c", password="pw"):
    data = {CONF_EMAIL: email, CONF_PASSWORD: password, CONF_DEVICES: devices}
    if known is not None:
        data[CONF_KNOWN_CLOUD_IDS] = known
    return _FakeEntry(data)


def _ids(entry):
    return [r["cloud_id"] for r in entry.data[CONF_DEVICES]]


def test_refresh_merges_instead_of_clobbering(monkeypatch):
    # The old behaviour resurrected "b" here.
    entry = _entry([_rec("a")], known=["a", "b"])
    hass = _setup(monkeypatch, [_rec("a"), _rec("b")])
    assert asyncio.run(rf.async_refresh_entry(hass, entry)) is True
    assert _ids(entry) == ["a"]


def test_refresh_adds_never_seen_device(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    hass = _setup(monkeypatch, [_rec("a"), _rec("c")])
    asyncio.run(rf.async_refresh_entry(hass, entry))
    assert _ids(entry) == ["a", "c"]
    assert hass.config_entries.reloaded == ["entry-1"]


def test_refresh_preserves_sticky_fields(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    hass = _setup(
        monkeypatch, [_rec("a", network_key=None, hub_mesh_device_id=None)]
    )
    asyncio.run(rf.async_refresh_entry(hass, entry))
    kept = entry.data[CONF_DEVICES][0]
    assert kept["network_key"] == KEY
    assert kept["hub_mesh_device_id"] == 0xEB42


def test_refresh_keeps_vanished_device(monkeypatch):
    gone = _rec("b")
    entry = _entry([_rec("a"), gone], known=["a", "b"])
    hass = _setup(monkeypatch, [_rec("a")])
    asyncio.run(rf.async_refresh_entry(hass, entry))
    assert _ids(entry) == ["a", "b"]
    assert entry.data[CONF_DEVICES][1] == gone


def test_refresh_records_known_ids_on_legacy_entry(monkeypatch):
    entry = _entry([_rec("a")])
    hass = _setup(monkeypatch, [_rec("a"), _rec("b")])
    asyncio.run(rf.async_refresh_entry(hass, entry))
    # Legacy entry has no exclusion record, so "b" reads as new and is added —
    # but from now on the choice is recorded.
    assert _ids(entry) == ["a", "b"]
    assert entry.data[CONF_KNOWN_CLOUD_IDS] == ["a", "b"]


def test_auth_error_starts_reauth_and_raises(monkeypatch):
    # ConfigEntryAuthFailed does nothing from a service handler, so the flow
    # has to be started by hand.
    entry = _entry([_rec("a")], known=["a"])
    hass = _setup(monkeypatch, CloudAuthError("bad password"))
    with pytest.raises(HomeAssistantError):
        asyncio.run(rf.async_refresh_entry(hass, entry))
    assert entry.reauth_started == 1
    assert hass.config_entries.updated == []


def test_connection_error_raises_and_leaves_entry_alone(monkeypatch):
    entry = _entry([_rec("a")], known=["a"])
    hass = _setup(monkeypatch, CloudConnectionError("down"))
    with pytest.raises(HomeAssistantError):
        asyncio.run(rf.async_refresh_entry(hass, entry))
    assert hass.config_entries.updated == []
    assert hass.config_entries.reloaded == []


def test_entry_without_credentials_is_skipped(monkeypatch):
    entry = _entry([_rec("a")], known=["a"], password="")
    hass = _setup(monkeypatch, [_rec("a")])
    assert asyncio.run(rf.async_refresh_entry(hass, entry)) is False
    assert hass.config_entries.updated == []
