"""HT34A-0001 (4-port XD timer) device class.

Ported from upstream `wxfield/Orbit_B-Hyve_4Port_Controller` and
community-verified against firmware 0107 (2026-06): zone start/stop
actuate over BLE via Home Assistant, both through an ESPHome Bluetooth
proxy and a direct adapter. Cipher math is shared with the HT25 family.

The protocol logic (framing, cipher, timerMode start/stop, confirm-and-retry,
protobuf RX status decode) lives in `protobuf.BHyveProtobufDevice`; this class
only carries the model's log label. Station addressing comes from
`self.stations` (4 here).
"""
from __future__ import annotations

from .protobuf import BHyveProtobufDevice


class BHyveHT34ADevice(BHyveProtobufDevice):
    """4-port XD timer. Ported from upstream; verified on fw0107 over BLE."""

    log_label = "HT34A"
