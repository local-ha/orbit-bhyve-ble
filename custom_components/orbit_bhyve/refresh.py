"""Non-destructive cloud re-discovery, behind the refresh_devices service.

Lives outside __init__.py on purpose: tests/conftest.py shims `orbit_bhyve` as an
empty namespace package so the HA-heavy __init__ never executes, which means
anything importable by the test suite has to be its own module.
"""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .cloud import CloudAuthError, CloudConnectionError, OrbitCloudClient
from .const import CONF_DEVICES, CONF_EMAIL, CONF_KNOWN_CLOUD_IDS, CONF_PASSWORD
from .merge import default_selection, merge_device_lists, next_known_ids

_LOGGER = logging.getLogger(__name__)


async def async_refresh_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Re-query the cloud and MERGE into entry.data[CONF_DEVICES], then reload.

    Same semantics as the reconfigure picker with its defaults accepted:
    currently-kept devices stay, never-seen-before devices are added,
    previously-excluded devices stay excluded, devices the cloud no longer
    returns are kept, and a blank fresh value never clobbers a good stored
    network key or mesh id (see merge.STICKY_FIELDS).

    Returns False if the entry has no usable credentials.
    """
    email = entry.data.get(CONF_EMAIL)
    password = entry.data.get(CONF_PASSWORD)
    if not (email and password):
        return False

    client = OrbitCloudClient(async_get_clientsession(hass))
    try:
        discovered = await client.discover(email, password)
    except CloudAuthError as err:
        _LOGGER.error("Refresh: auth failed for %s: %s", email, err)
        # ConfigEntryAuthFailed is only honoured inside async_setup_entry and
        # coordinator updates; raised from a service handler it just produces a
        # traceback and no reauth card, so start the flow explicitly.
        entry.async_start_reauth(hass)
        raise HomeAssistantError(
            f"Orbit cloud rejected the saved credentials for {email}"
        ) from err
    except CloudConnectionError as err:
        raise HomeAssistantError(f"Orbit cloud unreachable: {err}") from err

    stored = list(entry.data.get(CONF_DEVICES, []))
    stored_ids = [r["cloud_id"] for r in stored]
    discovered_ids = {r["cloud_id"] for r in discovered}
    known = entry.data.get(CONF_KNOWN_CLOUD_IDS)
    catalogue_ids = [r["cloud_id"] for r in discovered] + [
        cid for cid in stored_ids if cid not in discovered_ids
    ]
    selected = set(default_selection(stored_ids, known, catalogue_ids))

    hass.config_entries.async_update_entry(
        entry,
        data={
            **entry.data,
            CONF_DEVICES: merge_device_lists(stored, discovered, selected),
            CONF_KNOWN_CLOUD_IDS: next_known_ids(known, stored_ids, catalogue_ids),
        },
    )
    await hass.config_entries.async_reload(entry.entry_id)
    return True
