"""Device-class dispatch + structure tests.

Verifies resolve_device_class() routes each hardware/firmware/type to the right
class — in particular that Gen2 HT25G2 valves (which share the "HT25" prefix
with the older mesh hose timers) land on the protobuf class, not the mesh one —
and that the consolidated protobuf family keeps its expected shape. No hardware
or Home Assistant required.
"""
from __future__ import annotations

import pytest

from orbit_bhyve.devices import (
    BHyveHT25Device,
    BHyveHT25Fw0085Device,
    BHyveHT25G2Device,
    BHyveHT34ADevice,
    BHyveHubDevice,
    UnsupportedModel,
    resolve_device_class,
)
from orbit_bhyve.devices.base import _mv_to_pct
from orbit_bhyve.devices.protobuf import BHyveProtobufDevice


@pytest.mark.parametrize(
    "hardware,firmware,type_,expected",
    [
        ("", "", "bridge", BHyveHubDevice),               # hub wins on type
        ("HT34A-0001", "0107", "", BHyveHT34ADevice),     # XD 4-port
        ("HT25G2-0001", "0111", "", BHyveHT25G2Device),   # Gen2 by suffix
        ("HT25-0001", "0111", "", BHyveHT25G2Device),       # Gen2 by fw0111
        ("HT25-0001", "0085", "", BHyveHT25Fw0085Device),   # mesh fw0085 (upstream subclass)
        ("HT25-0001", "0041", "", BHyveHT25Device),         # mesh base (fw0041)
    ],
)
def test_resolve_routes(hardware, firmware, type_, expected):
    assert resolve_device_class(hardware=hardware, firmware=firmware, type_=type_) is expected


def test_resolve_unknown_raises():
    with pytest.raises(UnsupportedModel):
        resolve_device_class(hardware="ZZ99", firmware="0001", type_="")


def test_protobuf_family_subclassing():
    assert issubclass(BHyveHT34ADevice, BHyveProtobufDevice)
    assert issubclass(BHyveHT25G2Device, BHyveProtobufDevice)


@pytest.mark.parametrize(
    "cls,label",
    [(BHyveHT34ADevice, "HT34A"), (BHyveHT25G2Device, "HT25G2")],
)
def test_protobuf_family_attrs(cls, label):
    assert cls.log_label == label
    assert cls.frame_magic == 0x11
    assert cls.trailer_const == 0x11


@pytest.mark.parametrize(
    "mv,pct",
    [
        (2400, 0),     # curve floor
        (3000, 100),   # curve ceiling
        (2700, 50),    # midpoint
        (2000, 0),     # below floor clamps
        (3500, 100),   # above ceiling clamps
    ],
)
def test_mv_to_pct(mv, pct):
    assert _mv_to_pct(mv) == pct
