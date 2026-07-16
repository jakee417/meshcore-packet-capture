#!/usr/bin/env python3
"""Tests for the payload-decode export (GRP_TXT decryption + per-broker toggle)."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.config_loader import flatten_config_to_env_dict
from meshcore_packet_capture.packet_capture import (
    PacketCapture,
    _RotatingPacketLog,
    _parse_size,
)
from meshcore_packet_capture.payload_decode import (
    DEFAULT_PUBLIC_CHANNEL_KEY,
    ChannelKeyStore,
    channel_hash_for_key,
    decode_payload,
    derive_hashtag_key,
)

# Known GRP_TXT vector from michaelhart/meshcore-decoder tests.
BOT_KEY_HEX = "eb50a1bcb3e4e5d7bf69a57c9dada211"
GRP_RAW = "1540cab3b15626481a5ba64247ab25766e410b026e0678a32da9f0c3946fae5b714cab170f"


def test_runtime_metadata_declares_crypto_backend():
    repo_root = Path(__file__).resolve().parents[2]
    metadata = tomllib.loads((repo_root / "pyproject.toml").read_text())

    assert any(
        dependency.lower().startswith("cryptography")
        for dependency in metadata["project"]["dependencies"]
    )


def test_decoder_decrypts_known_vector():
    payload = bytes.fromhex(GRP_RAW[4:])  # after header + path
    store = ChannelKeyStore()
    store.add_secret(bytes.fromhex(BOT_KEY_HEX), "#bot")
    result = decode_payload(5, payload, store)
    assert result["decrypted"] is True
    assert result["sender"] == "Howl 👾"
    assert result["text"] == "prefix 0101"


def test_decoder_rejects_message_with_invalid_mac():
    payload = bytearray.fromhex(GRP_RAW[4:])
    payload[1] ^= 0xFF
    store = ChannelKeyStore()
    store.add_secret(bytes.fromhex(BOT_KEY_HEX), "#bot")

    result = decode_payload(5, bytes(payload), store)

    assert result["decrypted"] is False
    assert result["channel_hash"] == "ca"


def test_decoder_does_not_try_invalid_channel_keys():
    payload = bytes.fromhex(GRP_RAW[4:])
    store = ChannelKeyStore()
    store.add_secret(b"too short", "invalid")

    result = decode_payload(5, payload, store)

    assert len(store) == 0
    assert result["decrypted"] is False


def test_decoder_parses_advert_location_and_name():
    public_key = bytes(range(32))
    timestamp = 1_720_000_000
    signature = bytes([0xA5]) * 64
    flags = 0x80 | 0x10 | 0x01  # name + lat/lon + companion
    latitude = 47_606_200
    longitude = -122_332_100
    payload = (
        public_key
        + timestamp.to_bytes(4, "little")
        + signature
        + bytes([flags])
        + latitude.to_bytes(4, "little", signed=True)
        + longitude.to_bytes(4, "little", signed=True)
        + b"Seattle Node\x00"
    )

    result = decode_payload(4, payload)

    assert result["advert_parse_ok"] is True
    assert result["public_key"] == public_key.hex()
    assert result["advert_time"] == timestamp
    assert result["mode"] == "Companion"
    assert result["lat"] == 47.6062
    assert result["lon"] == -122.3321
    assert result["name"] == "Seattle Node"


def test_decoder_reports_short_advert_payload():
    result = decode_payload(4, b"short")

    assert result == {
        "kind": "ADVERT",
        "advert_parse_ok": False,
        "advert_error": "payload_too_short_header",
    }


def test_default_public_key_is_fixed_constant():
    assert DEFAULT_PUBLIC_CHANNEL_KEY != derive_hashtag_key("public")
    assert channel_hash_for_key(DEFAULT_PUBLIC_CHANNEL_KEY) == "11"


def test_format_packet_data_attaches_decoded(monkeypatch):
    monkeypatch.setenv("PACKETCAPTURE_DECODE_PAYLOADS", "true")
    monkeypatch.setenv("PACKETCAPTURE_DECODE_CHANNEL_KEYS", f"bot={BOT_KEY_HEX}")
    monkeypatch.setenv("PACKETCAPTURE_DECODE_INCLUDE_PUBLIC", "false")

    capture = PacketCapture(enable_mqtt=False)
    packet = capture.format_packet_data(GRP_RAW)
    assert "decoded" in packet
    assert packet["decoded"]["text"] == "prefix 0101"
    # Header fields are not restated inside decoded (no redundancy with top level)
    assert "type_label" not in packet["decoded"]
    assert "route_label" not in packet["decoded"]


def test_no_decoded_when_disabled(monkeypatch):
    monkeypatch.setenv("PACKETCAPTURE_DECODE_PAYLOADS", "false")
    capture = PacketCapture(enable_mqtt=False)
    packet = capture.format_packet_data(GRP_RAW)
    assert "decoded" not in packet


def test_broker_wants_decoded_per_broker(monkeypatch):
    monkeypatch.setenv("PACKETCAPTURE_INCLUDE_DECODED", "true")
    monkeypatch.setenv("PACKETCAPTURE_MQTT2_INCLUDE_DECODED", "false")
    capture = PacketCapture(enable_mqtt=False)
    assert capture._broker_wants_decoded(1) is True   # inherits global default
    assert capture._broker_wants_decoded(2) is False  # per-broker override


def test_include_decoded_defaults_off(monkeypatch):
    # Nothing configured -> global default off; brokers inherit unless they opt in.
    monkeypatch.setenv("PACKETCAPTURE_MQTT2_INCLUDE_DECODED", "true")
    capture = PacketCapture(enable_mqtt=False)
    assert capture.include_decoded is False
    assert capture._broker_wants_decoded(1) is False  # inherits global default (off)
    assert capture._broker_wants_decoded(2) is True   # explicit opt-in


def test_safe_publish_strips_decoded_per_broker(monkeypatch):
    monkeypatch.setattr(pc_mod.mqtt, "MQTT_ERR_SUCCESS", 0, raising=False)
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_INCLUDE_DECODED", "false")
    monkeypatch.setenv("PACKETCAPTURE_MQTT2_INCLUDE_DECODED", "true")
    capture = PacketCapture(enable_mqtt=True)
    capture.mqtt_connected = True

    class FakeClient:
        def __init__(self):
            self.published = []

        def is_connected(self):
            return True

        def publish(self, topic, payload, **kwargs):
            self.published.append((topic, json.loads(payload), kwargs))
            return SimpleNamespace(rc=0)

    stripped_client = FakeClient()
    decoded_client = FakeClient()
    capture.mqtt_clients = [
        {"client": stripped_client, "broker_num": 1, "label": "stripped"},
        {"client": decoded_client, "broker_num": 2, "label": "decoded"},
    ]
    packet = {"raw": "AA", "decoded": {"kind": "GRP_TXT", "text": "secret"}}

    metrics = capture.safe_publish(
        "meshcore/test",
        json.dumps(packet),
        decoded_dict=packet,
    )

    assert metrics == {"attempted": 2, "succeeded": 2}
    assert stripped_client.published[0][1] == {"raw": "AA"}
    assert decoded_client.published[0][1] == packet


def test_packet_log_without_rotation_truncates_existing_file(tmp_path):
    output = tmp_path / "packets.jsonl"
    output.write_text("old packet\n")

    packet_log = _RotatingPacketLog(output, rotation="off")
    packet_log.write_line("new packet")
    packet_log.close()

    assert output.read_text() == "new packet\n"


def test_packet_log_rotates_by_size(tmp_path):
    output = tmp_path / "packets.jsonl"
    packet_log = _RotatingPacketLog(output, rotation="size", max_bytes=20, backup_count=2)

    packet_log.write_line("first packet")
    packet_log.write_line("second packet")
    packet_log.close()

    assert output.read_text() == "second packet\n"
    assert (tmp_path / "packets.jsonl.1").read_text() == "first packet\n"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("50MB", 50 * 1024**2), ("1.5G", int(1.5 * 1024**3)), ("bad", 0)],
)
def test_parse_log_size(value, expected):
    assert _parse_size(value) == expected


def test_config_flatten_maps_decode_and_rotation_keys():
    cfg = {
        "capture": {
            "decode_payloads": True,
            "decode_hashtag_channels": ["bot", "weather"],
            "log_rotation": "size",
            "log_max_bytes": "10M",
        },
        "broker": [
            {"enabled": True, "name": "full", "server": "a"},
            {"enabled": True, "name": "raw", "server": "b", "include_decoded": False},
        ],
    }
    env = flatten_config_to_env_dict(cfg)
    assert env["PACKETCAPTURE_DECODE_PAYLOADS"] == "true"
    assert env["PACKETCAPTURE_DECODE_HASHTAG_CHANNELS"] == "bot,weather"
    assert env["PACKETCAPTURE_LOG_ROTATION"] == "size"
    assert env["PACKETCAPTURE_MQTT2_INCLUDE_DECODED"] == "false"
