#!/usr/bin/env python3
"""
B-Hyve BLE ↔ MQTT Bridge

Subscribes to MQTT topics for valve control commands and relays them
to the B-Hyve sprinkler via Bluetooth Low Energy.

MQTT Topics:
    bhyve/zone/1/set    → "ON" or "OFF" (or JSON {"state":"ON","duration":300})
    bhyve/zone/2/set    → same
    bhyve/zone/3/set    → same
    bhyve/zone/4/set    → same
    bhyve/all/set       → "OFF" (stop all)

    bhyve/zone/1/state  ← publishes "ON" / "OFF" (retained)
    bhyve/zone/2/state  ← same
    bhyve/zone/3/state  ← same
    bhyve/zone/4/state  ← same
    bhyve/status        ← "online" / "offline" (retained, LWT)

Home Assistant MQTT Switch config (add to configuration.yaml):

    mqtt:
      switch:
        - name: "B-Hyve Zone 1"
          unique_id: bhyve_zone_1
          command_topic: "bhyve/zone/1/set"
          state_topic: "bhyve/zone/1/state"
          icon: mdi:sprinkler-variant
        - name: "B-Hyve Zone 2"
          unique_id: bhyve_zone_2
          command_topic: "bhyve/zone/2/set"
          state_topic: "bhyve/zone/2/state"
          icon: mdi:sprinkler-variant
        - name: "B-Hyve Zone 3"
          unique_id: bhyve_zone_3
          command_topic: "bhyve/zone/3/set"
          state_topic: "bhyve/zone/3/state"
          icon: mdi:sprinkler-variant
        - name: "B-Hyve Zone 4"
          unique_id: bhyve_zone_4
          command_topic: "bhyve/zone/4/set"
          state_topic: "bhyve/zone/4/state"
          icon: mdi:sprinkler-variant

Requirements: pip install paho-mqtt bleak cryptography

⚠️  WARNING: Do NOT update your B-Hyve device firmware!
"""

import asyncio
import json
import logging
import os
import struct
import sys
import time
import threading

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ─── Configuration ───────────────────────────────────────────────────────

MQTT_BROKER = os.environ.get("MQTT_BROKER", "<mqtt_broker>")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "admin")
MQTT_PASS = os.environ.get("MQTT_PASS", "<your_mqtt_password>")
MQTT_TOPIC_BASE = os.environ.get("MQTT_TOPIC", "bhyve")

BHYVE_MAC = os.environ.get("BHYVE_MAC", "XX:XX:XX:XX:XX:XX")
BHYVE_KEY = os.environ.get("BHYVE_KEY", "<YOUR_NETWORK_KEY_HEX>")
DEFAULT_DURATION = int(os.environ.get("BHYVE_DURATION", "600"))
NUM_ZONES = int(os.environ.get("BHYVE_ZONES", "4"))
BLE_ADAPTER = os.environ.get("BLE_ADAPTER", "hci1")  # Use hci1 to avoid conflict with HA on hci0

# GATT UUIDs
AES_CHAR = "00006c71-fe32-4f58-8b78-98e42b2c047f"
WRITE_CHAR = "00006c72-fe32-4f58-8b78-98e42b2c047f"
READ_CHAR = "00006c73-fe32-4f58-8b78-98e42b2c047f"
MSG_HEADER = bytes([0xAA, 0x77, 0x5A, 0x0F])

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("bhyve-mqtt")

# ─── BLE Crypto ──────────────────────────────────────────────────────────

def crc16_ccitt(data, init=0):
    crc = init
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def pb_varint(val):
    r = bytearray()
    while val > 0x7F:
        r.append((val & 0x7F) | 0x80)
        val >>= 7
    r.append(val & 0x7F)
    return bytes(r)


def pb_field_varint(f, v):
    return pb_varint((f << 3) | 0) + pb_varint(v)


def pb_field_bytes(f, d):
    return pb_varint((f << 3) | 2) + pb_varint(len(d)) + d


def build_start_protobuf(station_id, duration_sec):
    station_info = pb_field_varint(1, station_id) + pb_field_varint(2, duration_sec)
    manual_params = pb_field_bytes(3, station_info)
    timer_mode = pb_field_varint(1, 2) + pb_field_bytes(2, manual_params)
    return pb_field_bytes(14, timer_mode)


def build_stop_protobuf():
    return bytes.fromhex("720408021200")


# ─── BLE Command Execution ──────────────────────────────────────────────

def compute_trailer(plaintext):
    """Compute the 2-byte frame trailer checksum.
    Formula: uint16_LE(sum(plaintext_bytes) + 0x11 + len(plaintext))
    """
    total = sum(plaintext) + 0x11 + len(plaintext)
    return struct.pack("<H", total & 0xFFFF)


async def send_ble_command(mac, key_hex, protobuf):
    from bleak import BleakClient

    key = bytes.fromhex(key_hex)

    async with BleakClient(mac, timeout=15.0) as client:
        try:
            await client._backend._acquire_mtu()
        except Exception:
            pass  # MTU negotiation optional

        # Init AES session
        init_tx = bytearray(os.urandom(20))
        init_tx[11] = 0x00
        init_tx = bytes(init_tx)
        await client.write_gatt_char(AES_CHAR, init_tx)
        rx = await client.read_gatt_char(AES_CHAR)

        iv = rx[:4] + init_tx[4:12]
        counter = struct.unpack("<I", init_tx[12:16])[0]

        # Build message
        payload_len = len(protobuf) + 2
        msg = MSG_HEADER + bytes([payload_len, 0x00]) + protobuf
        crc = struct.pack("<H", crc16_ccitt(msg, 0))
        plaintext = msg + crc

        # Encrypt
        ct = bytearray()
        for offset in range(0, len(plaintext), 16):
            chunk = plaintext[offset:offset + 16]
            block = iv + struct.pack("<I", counter)
            ks = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)
            ct.extend(b ^ k for b, k in zip(chunk, ks[:len(chunk)]))
            counter = (counter + 1) % 0xFFFFFFFF

        trailer = compute_trailer(plaintext)
        frame = bytes([0x11, len(ct)]) + bytes(ct) + trailer
        await client.write_gatt_char(WRITE_CHAR, frame, response=False)
        await asyncio.sleep(2)

        return True


def run_ble_command(mac, key, protobuf):
    """Run BLE command in a new event loop (thread-safe)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(send_ble_command(mac, key, protobuf))
    finally:
        loop.close()


# ─── Zone State Tracking ─────────────────────────────────────────────────

zone_states = {}
zone_timers = {}


def set_zone_state(client, zone, state):
    zone_states[zone] = state
    topic = f"{MQTT_TOPIC_BASE}/zone/{zone}/state"
    client.publish(topic, state, retain=True)
    log.info("Zone %d → %s", zone, state)


def schedule_auto_off(client, zone, duration):
    """Schedule automatic OFF after duration."""
    if zone in zone_timers and zone_timers[zone]:
        zone_timers[zone].cancel()

    def auto_off():
        log.info("Zone %d auto-off after %ds", zone, duration)
        set_zone_state(client, zone, "OFF")

    timer = threading.Timer(duration, auto_off)
    timer.daemon = True
    timer.start()
    zone_timers[zone] = timer


# ─── MQTT Callbacks ──────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        log.info("MQTT connected to %s:%d", MQTT_BROKER, MQTT_PORT)
        client.publish(f"{MQTT_TOPIC_BASE}/status", "online", retain=True)

        # Subscribe to command topics
        for z in range(1, NUM_ZONES + 1):
            topic = f"{MQTT_TOPIC_BASE}/zone/{z}/set"
            client.subscribe(topic)
            log.info("Subscribed: %s", topic)

        client.subscribe(f"{MQTT_TOPIC_BASE}/all/set")

        # Publish initial states
        for z in range(1, NUM_ZONES + 1):
            set_zone_state(client, z, "OFF")
    else:
        log.error("MQTT connection failed: rc=%d", rc)


def on_message(client, userdata, msg):
    topic = msg.topic
    payload = msg.payload.decode("utf-8", errors="ignore").strip()
    log.info("MQTT ← %s: %s", topic, payload)

    # Parse zone from topic
    if "/all/set" in topic:
        handle_stop_all(client)
        return

    try:
        parts = topic.split("/")
        zone = int(parts[parts.index("zone") + 1])
    except (ValueError, IndexError):
        log.error("Invalid topic: %s", topic)
        return

    if zone < 1 or zone > NUM_ZONES:
        log.error("Zone %d out of range", zone)
        return

    # Parse payload
    duration = DEFAULT_DURATION
    if payload.startswith("{"):
        try:
            data = json.loads(payload)
            payload = data.get("state", payload)
            duration = data.get("duration", DEFAULT_DURATION)
        except json.JSONDecodeError:
            pass

    if payload.upper() == "ON":
        handle_zone_on(client, zone, duration)
    elif payload.upper() == "OFF":
        handle_zone_off(client, zone)
    else:
        log.warning("Unknown payload: %s", payload)


def handle_zone_on(client, zone, duration):
    log.info("Turning ON zone %d for %ds...", zone, duration)
    set_zone_state(client, zone, "ON")  # publish immediately for responsive UI
    try:
        protobuf = build_start_protobuf(zone - 1, duration)
        run_ble_command(BHYVE_MAC, BHYVE_KEY, protobuf)
        schedule_auto_off(client, zone, duration)
    except Exception as e:
        log.error("BLE command failed: %s", e)
        set_zone_state(client, zone, "OFF")  # revert on failure


def handle_zone_off(client, zone):
    log.info("Turning OFF zone %d...", zone)
    set_zone_state(client, zone, "OFF")  # publish immediately for responsive UI
    try:
        protobuf = build_stop_protobuf()
        run_ble_command(BHYVE_MAC, BHYVE_KEY, protobuf)
        if zone in zone_timers and zone_timers[zone]:
            zone_timers[zone].cancel()
    except Exception as e:
        log.error("BLE command failed: %s", e)


def handle_stop_all(client):
    log.info("Stopping ALL zones...")
    try:
        protobuf = build_stop_protobuf()
        run_ble_command(BHYVE_MAC, BHYVE_KEY, protobuf)
        for z in range(1, NUM_ZONES + 1):
            set_zone_state(client, z, "OFF")
            if z in zone_timers and zone_timers[z]:
                zone_timers[z].cancel()
    except Exception as e:
        log.error("BLE command failed: %s", e)


# ─── Main ────────────────────────────────────────────────────────────────

def main():
    log.info("B-Hyve MQTT Bridge starting...")
    log.info("  MQTT:  %s:%d", MQTT_BROKER, MQTT_PORT)
    log.info("  BLE:   %s", BHYVE_MAC)
    log.info("  Zones: %d", NUM_ZONES)
    log.info("  Duration: %ds default", DEFAULT_DURATION)

    client = mqtt.Client(
        client_id="bhyve-ble-bridge",
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    )
    client.username_pw_set(MQTT_USER, MQTT_PASS)
    client.will_set(f"{MQTT_TOPIC_BASE}/status", "offline", retain=True)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    log.info("MQTT bridge running. Press Ctrl+C to stop.")

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        client.publish(f"{MQTT_TOPIC_BASE}/status", "offline", retain=True)
        client.disconnect()


if __name__ == "__main__":
    main()
