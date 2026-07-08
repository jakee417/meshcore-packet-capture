#!/usr/bin/env python3
"""Tests for the payload-decode export (GRP_TXT decryption + per-broker toggle)."""

from __future__ import annotations

import pytest

from meshcore_packet_capture.config_loader import flatten_config_to_env_dict
from meshcore_packet_capture.packet_capture import PacketCapture
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


def test_decoder_decrypts_known_vector():
    payload = bytes.fromhex(GRP_RAW[4:])  # after header + path
    store = ChannelKeyStore()
    store.add_secret(bytes.fromhex(BOT_KEY_HEX), "#bot")
    result = decode_payload(5, payload, store)
    assert result["decrypted"] is True
    assert result["sender"] == "Howl 👾"
    assert result["text"] == "prefix 0101"


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
