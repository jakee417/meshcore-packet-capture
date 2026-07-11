"""Helpers for MQTT command subscription and command execution."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional

import paho.mqtt.client as mqtt
from meshcore import EventType


def subscribe_command_topic(capture: Any, client: Any, broker_num: Optional[int]) -> None:
    """Subscribe an MQTT client to its configured command topic when available."""
    if broker_num is None:
        return

    command_topic = capture.get_topic("command", broker_num)
    if not command_topic:
        return

    qos = capture.get_env_int(f"MQTT{broker_num}_QOS", 0)
    result = client.subscribe(command_topic, qos=qos)
    if isinstance(result, tuple):
        subscribe_rc = result[0]
    else:
        subscribe_rc = result

    mqtt_ok = getattr(mqtt, "MQTT_ERR_SUCCESS", 0)
    if subscribe_rc == mqtt_ok:
        capture.logger.info(
            f"Subscribed to command topic on {capture.get_broker_label(broker_num)}: {command_topic}"
        )
    else:
        capture.logger.warning(
            f"Failed to subscribe command topic on {capture.get_broker_label(broker_num)}: {command_topic}"
        )


def handle_mqtt_message(capture: Any, userdata: Any, msg: Any) -> None:
    """Parse inbound MQTT command payload and dispatch async command execution."""
    broker_num = userdata.get("broker_num", None) if userdata else None
    broker_label = capture.get_broker_label(broker_num) if broker_num else "unknown"

    try:
        payload_text = msg.payload.decode("utf-8") if msg.payload else "{}"
        payload_data: Dict[str, Any] = json.loads(payload_text) if payload_text else {}
        if not isinstance(payload_data, dict):
            capture.logger.warning(
                f"Ignoring non-object command payload from {broker_label} on {msg.topic}"
            )
            return
    except Exception as e:
        capture.logger.warning(
            f"Invalid JSON payload on {msg.topic} from {broker_label}: {e}"
        )
        return

    topic_command_type = msg.topic.split("/")[-1] if msg.topic else ""
    command_type = payload_data.get("command_type") or topic_command_type
    if not command_type or command_type in {"command", "+"}:
        capture.logger.warning(
            f"Ignoring command message without command type from {broker_label} on {msg.topic}"
        )
        return

    if capture._event_loop is None:
        capture.logger.warning("Event loop unavailable; cannot process MQTT command")
        return

    future = asyncio.run_coroutine_threadsafe(
        process_mqtt_command(capture, command_type, payload_data, broker_num),
        capture._event_loop,
    )

    def _done_callback(done_future: Any) -> None:
        try:
            done_future.result()
        except Exception as exc:
            capture.logger.error(f"Error processing MQTT command '{command_type}': {exc}")

    future.add_done_callback(_done_callback)


async def process_mqtt_command(
    capture: Any,
    command_type: str,
    payload_data: Dict[str, Any],
    broker_num: Optional[int],
) -> None:
    """Execute supported MeshCore commands from MQTT command payloads."""
    broker_label = capture.get_broker_label(broker_num) if broker_num else "unknown"
    command = command_type.strip().lower()

    if not capture._ensure_connected(f"mqtt command '{command}'", "warning"):
        return

    async def _run_command(
        command_name: str,
        command_func: Any,
        timeout: float = 10.0,
        on_success: Any = None,
    ) -> bool:
        retries = capture.default_retry_limit
        result = await capture.retryable_device_command(
            command_func,
            command_name,
            timeout=timeout,
            max_retries=retries,
            retry_delay=0.2,
        )
        if result is None:
            capture.logger.warning(
                f"MQTT command '{command_name}' failed on {broker_label}: no response"
            )
            return False
        if hasattr(result, "type") and result.type == EventType.ERROR:
            capture.logger.warning(
                f"MQTT command '{command_name}' failed on {broker_label}: {result.payload}"
            )
            return False
        if on_success is not None:
            success_message = on_success(result)
            if success_message:
                capture.logger.info(success_message)
        else:
            capture.logger.info(f"MQTT command '{command_name}' succeeded on {broker_label}")
        return True

    if command == "send_msg":
        destination = payload_data.get("destination")
        message = payload_data.get("message")
        if not destination or not isinstance(destination, str):
            capture.logger.warning("send_msg requires string 'destination'")
            return
        if not message or not isinstance(message, str):
            capture.logger.warning("send_msg requires string 'message'")
            return

        async def _send_msg_command() -> Any:
            result = await capture.meshcore.commands.send_msg(destination, message)
            return result

        await _run_command(
            "send_msg",
            _send_msg_command,
            on_success=lambda result: f"📤 Sent direct message (to={destination}): {message}",
        )
        return

    if command == "send_chan_msg":
        channel = payload_data.get("channel")
        message = payload_data.get("message")
        if channel is None:
            capture.logger.warning("send_chan_msg requires 'channel'")
            return
        try:
            channel_idx = int(channel)
        except (TypeError, ValueError):
            capture.logger.warning("send_chan_msg requires numeric 'channel'")
            return
        if not message or not isinstance(message, str):
            capture.logger.warning("send_chan_msg requires string 'message'")
            return
        await _run_command(
            "send_chan_msg",
            lambda: capture.meshcore.commands.send_chan_msg(channel_idx, message),
            on_success=lambda result: f"📤 Sent channel message (channel={channel_idx}): {message}",
        )
        return

    capture.logger.warning(f"Unknown MQTT command '{command}' from {broker_label}")
