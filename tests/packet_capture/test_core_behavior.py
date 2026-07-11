"""Core packet-capture behavior tests (parsing + retry/shutdown state)."""
from __future__ import annotations

import asyncio
import json
import types

import pytest

from meshcore_packet_capture import packet_capture as pc_mod
from meshcore_packet_capture.enums import PayloadType
from meshcore_packet_capture.packet_capture import PacketCapture


@pytest.fixture
def capture() -> PacketCapture:
    return PacketCapture(enable_mqtt=False)


def test_retry_delay_uses_backoff_and_jitter(monkeypatch: pytest.MonkeyPatch, capture: PacketCapture) -> None:
    capture.connection_retry_delay = 2
    capture.connection_retry_backoff_multiplier = 2.0
    capture.connection_retry_delay_max = 100
    capture.connection_retry_jitter = True

    # delay for attempt=3 => 2 * 2^(3-1) = 8 ; with jitter 1.25 => 10
    monkeypatch.setattr("random.uniform", lambda _a, _b: 1.25)
    assert capture.calculate_connection_retry_delay(3) == 10


def test_track_consecutive_failure_triggers_service_exit(capture: PacketCapture) -> None:
    capture.max_consecutive_failures = 2
    capture.max_service_failures = 1
    capture.service_failure_window = 3600

    assert capture.track_consecutive_failure("connection") is False
    assert capture.should_exit is False
    assert capture.track_consecutive_failure("connection") is True
    assert capture.should_exit is True


def test_ble_grace_period_allows_then_fails(capture: PacketCapture) -> None:
    capture.connection_type = "ble"
    capture.health_check_grace_period = 2
    capture.health_check_failure_count = 0
    capture.meshcore = types.SimpleNamespace(is_connected=True)

    assert capture._check_ble_grace_period("timed out") is True
    assert capture._check_ble_grace_period("timed out") is True
    assert capture._check_ble_grace_period("timed out") is False


@pytest.mark.asyncio
async def test_wait_with_shutdown_event_returns_true(capture: PacketCapture) -> None:
    capture.shutdown_event = asyncio.Event()
    capture.shutdown_event.set()
    assert await capture.wait_with_shutdown(0.01) is True


def test_decode_unknown_packet_version_returns_none(capture: PacketCapture) -> None:
    # header version bits set to 1 (unknown), payload type ADVERT, route FLOOD
    header = ((1 & 0x03) << 6) | ((PayloadType.ADVERT.value & 0x0F) << 2) | 0
    # one-byte path (path_len=1), one-byte path data, then advert-sized payload bytes
    raw_hex = bytes([header, 0x01, 0xAA]) .hex()
    assert capture.decode_and_publish_message(raw_hex) is None


def test_decode_path_length_overflow_returns_none(capture: PacketCapture) -> None:
    # Version 0, payload type ADVERT, route FLOOD
    header = ((0 & 0x03) << 6) | ((PayloadType.ADVERT.value & 0x0F) << 2) | 0
    # claim 10 hops with 1 byte/hop, but only provide 1 byte
    raw_hex = bytes([header, 0x0A, 0xAA]).hex()
    assert capture.decode_and_publish_message(raw_hex) is None


def test_resolve_topic_template_replaces_token_placeholder(monkeypatch: pytest.MonkeyPatch, capture: PacketCapture) -> None:
    capture.global_iata = "sea"
    capture.device_public_key = "ABCDEF"
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_TOKEN", "tok123")
    topic = capture.resolve_topic_template("meshrank/uplink/{TOKEN}/{PUBLIC_KEY}/packets", broker_num=1)
    assert topic == "meshrank/uplink/tok123/ABCDEF/packets"


def test_get_topic_broker_can_disable_decoded(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_DECODED", "off")
    assert capture.get_topic("decoded", broker_num=1) is None


def test_get_topic_global_disable_blocks_default(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    monkeypatch.setenv("PACKETCAPTURE_TOPIC_DECODED", "disabled")
    assert capture.get_topic("decoded", broker_num=2) is None


def test_get_topic_command_default(capture: PacketCapture) -> None:
    assert capture.get_topic("command", broker_num=1) == "meshcore/command/+"


@pytest.mark.asyncio
async def test_refresh_stats_fetches_packet_stats(monkeypatch: pytest.MonkeyPatch, capture: PacketCapture) -> None:
    event_type = types.SimpleNamespace(
        ERROR="error",
        STATS_CORE="stats_core",
        STATS_RADIO="stats_radio",
        STATS_PACKETS="stats_packets",
    )
    monkeypatch.setattr(pc_mod, "EventType", event_type)

    async def _core():
        return types.SimpleNamespace(type=event_type.STATS_CORE, payload={"uptime": 10})

    async def _radio():
        return types.SimpleNamespace(type=event_type.STATS_RADIO, payload={"airtime": 20})

    async def _packets():
        return types.SimpleNamespace(
            type=event_type.STATS_PACKETS,
            payload={
                "recv": 1234,
                "sent": 567,
                "flood_tx": 400,
                "direct_tx": 167,
                "flood_rx": 900,
                "direct_rx": 334,
                "recv_errors": 12,
            },
        )

    async def _retry(command, *_args, **_kwargs):
        return await command()

    capture.meshcore = types.SimpleNamespace(
        is_connected=True,
        commands=types.SimpleNamespace(
            get_stats_core=_core,
            get_stats_radio=_radio,
            get_stats_packets=_packets,
        ),
    )
    capture.retryable_device_command = _retry

    stats = await capture.refresh_stats(force=True)

    assert stats["packets_received"] == 1234
    assert stats["packets_sent"] == 567
    assert stats["recv"] == 1234
    assert stats["sent"] == 567
    assert stats["flood_tx"] == 400
    assert stats["direct_rx"] == 334
    assert stats["recv_errors"] == 12


@pytest.mark.asyncio
async def test_publish_status_includes_packet_stats_aliases(capture: PacketCapture) -> None:
    published: list[dict] = []

    async def _firmware():
        return {"model": "companion", "version": "1.2.3"}

    async def _refresh_stats(force=False):
        return {
            "recv": 1234,
            "sent": 567,
            "packets_received": 1234,
            "packets_sent": 567,
        }

    def _publish(_topic, payload, **_kwargs):
        published.append(json.loads(payload))
        return {"attempted": 1, "succeeded": 1}

    capture.get_firmware_info = _firmware
    capture.refresh_stats = _refresh_stats
    capture.safe_publish = _publish
    capture.mqtt_connected = True
    capture.device_name = "node"
    capture.device_public_key = "abc"
    capture.radio_info = {"region": "US"}

    await capture.publish_status("online")

    assert published
    assert published[0]["stats"]["packets_received"] == 1234
    assert published[0]["stats"]["packets_sent"] == 567


@pytest.mark.asyncio
async def test_handle_decoded_message_event_publishes_decoded_payload(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str, str | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.device_name = "node"
    capture.device_public_key = "abc123"

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload, kwargs.get("topic_type")))
        return {"attempted": 1, "succeeded": 1}

    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
        },
    )

    await capture.handle_decoded_message_event(event)

    assert published
    assert published[0][2] == "decoded"
    payload_json = json.loads(published[0][1])
    assert payload_json["type"] == "DECODED_MESSAGE"
    assert payload_json["direction"] == "direct"
    assert payload_json["message"] == "hello world"
    assert payload_json["from"] == "node-a"


@pytest.mark.asyncio
async def test_handle_decoded_message_event_includes_payload_signal(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str, str | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload, kwargs.get("topic_type")))
        return {"attempted": 1, "succeeded": 1}

    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
            "snr": 12.5,
            "rssi": -87,
        },
    )

    await capture.handle_decoded_message_event(event)

    payload_json = json.loads(published[0][1])
    assert payload_json["snr"] == 12.5
    assert payload_json["rssi"] == -87.0


@pytest.mark.asyncio
async def test_handle_decoded_message_event_does_not_use_rf_cache_signal(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str, str | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True
    capture.rf_data_cache = {
        "old": {"snr": 1.0, "rssi": -100, "timestamp": 1.0},
        "recent": {"snr": 7.25, "rssi": -72, "timestamp": 10.0},
    }

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload, kwargs.get("topic_type")))
        return {"attempted": 1, "succeeded": 1}

    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
        },
    )

    original_time = pc_mod.time.time
    try:
        pc_mod.time.time = lambda: 12.0
        await capture.handle_decoded_message_event(event)
    finally:
        pc_mod.time.time = original_time

    payload_json = json.loads(published[0][1])
    assert "snr" not in payload_json
    assert "rssi" not in payload_json


@pytest.mark.asyncio
async def test_handle_decoded_message_event_reads_metadata_signal(
    capture: PacketCapture,
) -> None:
    published: list[tuple[str | None, str, str | None]] = []

    capture.enable_mqtt = True
    capture.mqtt_connected = True

    def _publish(topic, payload, **kwargs):
        published.append((topic, payload, kwargs.get("topic_type")))
        return {"attempted": 1, "succeeded": 1}

    capture.safe_publish = _publish

    event = types.SimpleNamespace(
        type="CONTACT_MSG_RECV",
        payload={
            "type": "PRIV",
            "text": "hello world",
            "from": "node-a",
            "pubkey_prefix": "a1b2c3",
            "msg_id": "msg-1",
            "metadata": {
                "signal": {
                    "SNR": 3.14,
                    "RSSI": -91,
                }
            },
        },
    )

    await capture.handle_decoded_message_event(event)

    payload_json = json.loads(published[0][1])
    assert payload_json["snr"] == 3.14
    assert payload_json["rssi"] == -91.0


@pytest.mark.asyncio
async def test_setup_event_handlers_subscribes_message_events(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    subscribed: list[tuple[str, object]] = []

    event_type = types.SimpleNamespace(
        RX_LOG_DATA="RX_LOG_DATA",
        RAW_DATA="RAW_DATA",
        STATUS_RESPONSE="STATUS_RESPONSE",
        CONTACT_MSG_RECV="CONTACT_MSG_RECV",
        CHANNEL_MSG_RECV="CHANNEL_MSG_RECV",
        DISCONNECTED="DISCONNECTED",
    )
    monkeypatch.setattr(pc_mod, "EventType", event_type)

    capture.meshcore = types.SimpleNamespace(
        subscribe=lambda event_name, handler: subscribed.append((event_name, handler)),
        dispatcher=types.SimpleNamespace(subscriptions=[]),
        unsubscribe=lambda _subscription: None,
    )

    await capture.setup_event_handlers()

    subscribed_names = {name for name, _handler in subscribed}
    assert "CONTACT_MSG_RECV" in subscribed_names
    assert "CHANNEL_MSG_RECV" in subscribed_names


def test_on_mqtt_connect_subscribes_command_topic(
    monkeypatch: pytest.MonkeyPatch, capture: PacketCapture
) -> None:
    class _Client:
        def __init__(self):
            self.subscribed = []

        def subscribe(self, topic, qos=0):
            self.subscribed.append((topic, qos))
            return (0, 1)

    monkeypatch.setenv("PACKETCAPTURE_MQTT1_QOS", "1")
    monkeypatch.setenv("PACKETCAPTURE_MQTT1_TOPIC_COMMAND", "local/mesh/command/+")
    client = _Client()

    capture.on_mqtt_connect(client, {"name": "local", "broker_num": 1}, None, 0)

    assert client.subscribed == [("local/mesh/command/+", 1)]


@pytest.mark.asyncio
async def test_process_mqtt_command_send_msg_executes_meshcore_command(
    capture: PacketCapture,
) -> None:
    calls: list[tuple[str, str]] = []

    async def _send_msg(destination, message):
        calls.append((destination, message))
        return types.SimpleNamespace(type="OK", payload={})

    async def _retry(command_func, _command_name, **_kwargs):
        return await command_func()

    capture.meshcore = types.SimpleNamespace(
        is_connected=True,
        commands=types.SimpleNamespace(send_msg=_send_msg),
    )
    capture.retryable_device_command = _retry

    await capture._process_mqtt_command(
        "send_msg",
        {
            "destination": "cccccdbvtubkcjdjueurlflrfkcgirjlufjrdjjugldg",
            "message": "hello",
        },
        broker_num=1,
    )

    assert calls == [("cccccdbvtubkcjdjueurlflrfkcgirjlufjrdjjugldg", "hello")]
