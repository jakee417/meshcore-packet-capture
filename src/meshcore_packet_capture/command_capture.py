"""Helpers for MQTT command subscription and command execution with security hardening.

Security model addressing PR #37 feedback:
- Per-broker only activation (no global TOPIC_COMMAND fallback)
- Explicit opt-in gate MQTT{n}_COMMANDS_ENABLED
- Topic verification via topic_matches_sub
- Retain drop + timestamp freshness + nonce deduplication (replay protection)
- Per-broker rate limiting (token bucket)
- Command type derived from topic, not payload (prevents ACL bypass via + wildcard)
- Log sanitization (newline injection)
- Optional HMAC shared-secret verification (moves trust boundary off broker)
"""

from __future__ import annotations

import asyncio
import collections
import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional, Tuple

import paho.mqtt.client as mqtt
from meshcore import EventType

# ---------------------------------------------------------------------------
# Configuration defaults (overridable via env)
# ---------------------------------------------------------------------------
DEFAULT_COMMAND_MAX_AGE = 300  # seconds, 5 min replay window
DEFAULT_COMMAND_FUTURE_SKEW = 60  # allow 60s clock skew in future
DEFAULT_COMMAND_MAX_RATE = 10  # commands per window
DEFAULT_COMMAND_RATE_WINDOW = 60  # seconds
DEFAULT_NONCE_CACHE_TTL = 600  # keep nonces for 10 min

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_log_sanitize_re = re.compile(r"[\r\n]+")
_non_printable_re = re.compile(r"[\x00-\x1f\x7f]+")


def _sanitize_log_field(value: Any, max_len: int = 120) -> str:
    """Sanitize a field interpolated into logs - strip newlines/control chars, truncate."""
    if not isinstance(value, str):
        value = str(value)
    # Replace newlines with space, strip control chars
    cleaned = _log_sanitize_re.sub(" ", value)
    cleaned = _non_printable_re.sub("", cleaned)
    cleaned = cleaned.strip()
    if len(cleaned) > max_len:
        return cleaned[: max_len - 3] + "..."
    return cleaned


def _topic_matches(subscription: str, topic: str) -> bool:
    """Check if topic matches subscription with +/# wildcards. Uses paho's helper if available."""
    # Prefer paho's implementation for exact MQTT spec compliance
    try:
        # paho.mqtt.client.topic_matches_sub is the canonical helper
        return mqtt.topic_matches_sub(subscription, topic)  # type: ignore[attr-defined]
    except AttributeError:
        pass
    try:
        # Older paho versions expose it in client module differently
        from paho.mqtt.client import topic_matches_sub

        return topic_matches_sub(subscription, topic)
    except Exception:
        pass

    # Fallback minimal implementation: + = single level, # = rest
    # This is not fully spec compliant but covers + case used here
    sub_parts = subscription.split("/")
    topic_parts = topic.split("/")
    i = 0
    while i < len(sub_parts):
        s = sub_parts[i]
        if s == "#":
            return True
        if i >= len(topic_parts):
            return False
        if s == "+":
            # matches any single level, but must not be empty unless topic has empty?
            pass
        elif s != topic_parts[i]:
            return False
        i += 1
    return i == len(topic_parts)


def _is_commands_enabled(capture: Any, broker_num: Optional[int]) -> bool:
    if broker_num is None:
        return False
    return capture.get_env_bool(f"MQTT{broker_num}_COMMANDS_ENABLED", False)


def _get_per_broker_command_topic_raw(capture: Any, broker_num: Optional[int]) -> Optional[str]:
    """Only per-broker topic, no global fallback - returns raw env value or None."""
    if broker_num is None:
        return None
    # raw=True returns None if unset, "" if explicitly set to empty (opt-out)
    raw = capture.get_env(f"MQTT{broker_num}_TOPIC_COMMAND", raw=True)
    return raw


def _get_configured_command_topic(capture: Any, broker_num: Optional[int]) -> Optional[str]:
    """Resolved command topic for this broker (per-broker only, empty disables)."""
    if broker_num is None:
        return None
    raw = _get_per_broker_command_topic_raw(capture, broker_num)
    if raw is None:
        return None
    if raw == "":
        return None  # explicit opt-out
    # Use the same resolution logic as get_topic for templates, but only per-broker
    # get_topic already implements per-broker-only for COMMAND after our fix
    return capture.get_topic("command", broker_num)


def _get_hmac_key(capture: Any, broker_num: Optional[int]) -> Optional[str]:
    if broker_num is None:
        return None
    key = capture.get_env(f"MQTT{broker_num}_COMMAND_HMAC_KEY", "")
    if not key:
        # Also allow global fallback for HMAC key? Keep per-broker only for security
        # but check global as well for convenience
        key = capture.get_env("COMMAND_HMAC_KEY", "")
    return key if key else None


def _parse_timestamp(value: Any) -> Optional[float]:
    """Parse timestamp from payload: epoch int/float or ISO8601 string."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        # Try epoch as string
        try:
            return float(value)
        except ValueError:
            pass
        # Try ISO8601
        try:
            # Handle Z suffix
            iso = value.replace("Z", "+00:00") if value.endswith("Z") else value
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return None
    return None


def _verify_timestamp(capture: Any, payload_data: Dict[str, Any], broker_num: Optional[int]) -> Tuple[bool, str]:
    max_age = capture.get_env_int(f"MQTT{broker_num}_COMMAND_MAX_AGE", DEFAULT_COMMAND_MAX_AGE) if broker_num else DEFAULT_COMMAND_MAX_AGE
    future_skew = DEFAULT_COMMAND_FUTURE_SKEW

    ts_raw = payload_data.get("timestamp") or payload_data.get("ts")
    if ts_raw is None:
        return False, "missing timestamp (required for replay protection)"

    ts = _parse_timestamp(ts_raw)
    if ts is None:
        return False, f"unparseable timestamp: {_sanitize_log_field(ts_raw)}"

    now = time.time()
    age = now - ts
    if age > max_age:
        return False, f"stale timestamp, age {age:.1f}s > max {max_age}s"
    if age < -future_skew:
        return False, f"timestamp from future, skew { -age:.1f}s > max {future_skew}s"

    return True, ""


def _ensure_security_state(capture: Any) -> None:
    """Lazily initialize per-capture security tracking structures."""
    if not hasattr(capture, "_command_seen_nonces"):
        capture._command_seen_nonces = {}  # broker_num -> {nonce: expiry}
    if not hasattr(capture, "_command_rate_buckets"):
        capture._command_rate_buckets = {}  # broker_num -> deque[timestamps]


def _get_command_execution_lock(capture: Any, broker_num: Optional[int]) -> asyncio.Lock:
    """Return a per-broker async lock so MQTT commands execute sequentially."""
    if not hasattr(capture, "_command_execution_locks"):
        capture._command_execution_locks = {}
    lock = capture._command_execution_locks.get(broker_num)
    if lock is None:
        lock = asyncio.Lock()
        capture._command_execution_locks[broker_num] = lock
    return lock


def _cleanup_expired_nonces(capture: Any, broker_num: Optional[int], now: float) -> None:
    _ensure_security_state(capture)
    if broker_num not in capture._command_seen_nonces:
        return
    nonce_map = capture._command_seen_nonces[broker_num]
    expired = [n for n, exp in nonce_map.items() if exp < now]
    for n in expired:
        del nonce_map[n]


def _check_and_record_nonce(capture: Any, broker_num: Optional[int], nonce: Any) -> Tuple[bool, str]:
    if nonce is None:
        # Nonce is recommended but not strictly required if timestamp+HMAC present; require for full replay protection
        return True, ""
    if not isinstance(nonce, str):
        nonce = str(nonce)
    # Sanitize nonce for storage but keep original for HMAC (HMAC uses original value)
    nonce_key = nonce.strip()
    if not nonce_key:
        return True, ""
    if len(nonce_key) > 128:
        return False, "nonce too long"

    _ensure_security_state(capture)
    now = time.time()
    _cleanup_expired_nonces(capture, broker_num, now)

    bucket = capture._command_seen_nonces.setdefault(broker_num, {})
    if nonce_key in bucket:
        return False, f"duplicate nonce: {_sanitize_log_field(nonce_key, 40)}"
    bucket[nonce_key] = now + DEFAULT_NONCE_CACHE_TTL
    return True, ""


def _check_rate_limit(capture: Any, broker_num: Optional[int]) -> Tuple[bool, str]:
    _ensure_security_state(capture)
    now = time.time()
    window = capture.get_env_int(f"MQTT{broker_num}_COMMAND_RATE_WINDOW", DEFAULT_COMMAND_RATE_WINDOW) if broker_num else DEFAULT_COMMAND_RATE_WINDOW
    max_rate = capture.get_env_int(f"MQTT{broker_num}_COMMAND_MAX_RATE", DEFAULT_COMMAND_MAX_RATE) if broker_num else DEFAULT_COMMAND_MAX_RATE

    bucket: Deque[float] = capture._command_rate_buckets.setdefault(broker_num, collections.deque())

    # Purge outside window
    while bucket and bucket[0] < now - window:
        bucket.popleft()

    if len(bucket) >= max_rate:
        return False, f"rate limit exceeded: {len(bucket)} commands in last {window}s (max {max_rate})"

    return True, ""


def _record_rate_limit(capture: Any, broker_num: Optional[int]) -> None:
    _ensure_security_state(capture)
    bucket = capture._command_rate_buckets.setdefault(broker_num, collections.deque())
    bucket.append(time.time())


def _compute_hmac_signature(key: str, command_type: str, timestamp: Any, nonce: Any, payload_core: Dict[str, Any]) -> str:
    """
    Compute HMAC-SHA256 over canonical representation.
    payload_core should be the command-relevant fields excluding hmac/signature itself.
    """
    # Canonical: command_type.timestamp.nonce.json(sorted core)
    # Ensure deterministic JSON: sort keys, compact separators
    core_json = json.dumps(payload_core, sort_keys=True, separators=(",", ":"))
    ts_str = str(timestamp) if timestamp is not None else ""
    nonce_str = str(nonce) if nonce is not None else ""
    message = f"{command_type}.{ts_str}.{nonce_str}.{core_json}"
    sig = hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return sig


def _verify_hmac(capture: Any, broker_num: Optional[int], command_type: str, payload_data: Dict[str, Any]) -> Tuple[bool, str]:
    key = _get_hmac_key(capture, broker_num)
    if not key:
        # No HMAC configured -> transport-only trust. Log warning at handler level.
        return True, "no HMAC key configured, using transport-only trust"

    # Expect hmac or signature field
    provided = payload_data.get("hmac") or payload_data.get("signature")
    if not provided or not isinstance(provided, str):
        return False, "missing hmac/signature (required when COMMAND_HMAC_KEY is set)"

    # Extract core fields for verification (exclude hmac/signature itself)
    core = {k: v for k, v in payload_data.items() if k not in ("hmac", "signature")}

    timestamp = payload_data.get("timestamp") or payload_data.get("ts")
    nonce = payload_data.get("nonce") or payload_data.get("id") or payload_data.get("msg_id")

    expected = _compute_hmac_signature(key, command_type, timestamp, nonce, core)

    # Use constant-time compare
    if not hmac.compare_digest(expected, provided):
        return False, "HMAC verification failed"

    return True, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def subscribe_command_topic(capture: Any, client: Any, broker_num: Optional[int]) -> None:
    """Subscribe an MQTT client to its configured command topic when explicitly enabled."""
    if broker_num is None:
        return

    # Explicit opt-in gate - prevents accidental enablement via topic alone
    if not _is_commands_enabled(capture, broker_num):
        if capture.debug:
            capture.logger.debug(
                f"Command ingress not enabled for {capture.get_broker_label(broker_num)} "
                f"(set PACKETCAPTURE_MQTT{broker_num}_COMMANDS_ENABLED=true to enable)"
            )
        return

    command_topic = _get_configured_command_topic(capture, broker_num)
    if not command_topic:
        capture.logger.warning(
            f"Command ingress enabled for {capture.get_broker_label(broker_num)} "
            f"but no topic configured (set PACKETCAPTURE_MQTT{broker_num}_TOPIC_COMMAND)"
        )
        return

    # Warn if no HMAC key - transport-only trust
    if not _get_hmac_key(capture, broker_num):
        capture.logger.warning(
            f"Command ingress enabled on {capture.get_broker_label(broker_num)} "
            f"without HMAC (PACKETCAPTURE_MQTT{broker_num}_COMMAND_HMAC_KEY). "
            f"Trust is broker ACLs only. Set HMAC key for cryptographic auth."
        )

    qos = capture.get_env_int(f"MQTT{broker_num}_QOS", 0)
    result = client.subscribe(command_topic, qos=qos)
    if isinstance(result, tuple):
        subscribe_rc = result[0]
    else:
        subscribe_rc = result

    mqtt_ok = getattr(mqtt, "MQTT_ERR_SUCCESS", 0)
    if subscribe_rc == mqtt_ok:
        capture.logger.info(
            f"Subscribed to command topic on {capture.get_broker_label(broker_num)}: "
            f"{_sanitize_log_field(command_topic, 200)} (enabled gate + per-broker topic)"
        )
    else:
        capture.logger.warning(
            f"Failed to subscribe command topic on {capture.get_broker_label(broker_num)}: "
            f"{_sanitize_log_field(command_topic, 200)} rc={subscribe_rc}"
        )


def handle_mqtt_message(capture: Any, userdata: Any, msg: Any) -> None:
    """Parse inbound MQTT command payload and dispatch async command execution with hardening."""
    broker_num = userdata.get("broker_num", None) if userdata else None
    broker_label = capture.get_broker_label(broker_num) if broker_num else "unknown"

    # --- Replay protection: drop retained ---
    if getattr(msg, "retain", False):
        capture.logger.warning(
            f"Dropping retained command message from {broker_label} on {_sanitize_log_field(msg.topic)} (retain not allowed)"
        )
        return

    # --- Explicit enable gate ---
    if not _is_commands_enabled(capture, broker_num):
        capture.logger.warning(
            f"Ignoring command message on {broker_label} - command ingress not enabled for this broker "
            f"(topic={_sanitize_log_field(msg.topic)})"
        )
        return

    # --- Verify broker has command topic configured ---
    configured_topic = _get_configured_command_topic(capture, broker_num)
    if not configured_topic:
        capture.logger.warning(
            f"Ignoring command message on {broker_label} - no command topic configured for this broker "
            f"(incoming={_sanitize_log_field(msg.topic)})"
        )
        return

    # --- Verify inbound topic matches configured subscription ---
    try:
        if not _topic_matches(configured_topic, msg.topic):
            capture.logger.warning(
                f"Ignoring command message on {broker_label} - topic mismatch: "
                f"got {_sanitize_log_field(msg.topic)} expected {_sanitize_log_field(configured_topic)}"
            )
            return
    except Exception as e:
        capture.logger.warning(f"Topic match check failed for {broker_label}: {e}")
        return

    # --- Parse JSON ---
    try:
        payload_text = msg.payload.decode("utf-8") if msg.payload else "{}"
        payload_data: Dict[str, Any] = json.loads(payload_text) if payload_text else {}
        if not isinstance(payload_data, dict):
            capture.logger.warning(
                f"Ignoring non-object command payload from {broker_label} on {_sanitize_log_field(msg.topic)}"
            )
            return
    except Exception as e:
        capture.logger.warning(
            f"Invalid JSON payload on {_sanitize_log_field(msg.topic)} from {broker_label}: {_sanitize_log_field(e, 200)}"
        )
        return

    # --- Command type must come from topic, not payload (prevents ACL bypass via + wildcard) ---
    topic_command_type = msg.topic.split("/")[-1] if msg.topic else ""
    if not topic_command_type or topic_command_type in {"command", "+"}:
        capture.logger.warning(
            f"Ignoring command message without concrete command type in topic from {broker_label} on {_sanitize_log_field(msg.topic)}"
        )
        return

    payload_cmd_override = payload_data.get("command_type")
    if payload_cmd_override and str(payload_cmd_override).strip().lower() != topic_command_type.strip().lower():
        capture.logger.warning(
            f"Ignoring command message from {broker_label} - payload command_type "
            f"'{_sanitize_log_field(payload_cmd_override)}' does not match topic command "
            f"'{_sanitize_log_field(topic_command_type)}' (override not allowed)"
        )
        return

    command_type = topic_command_type.strip().lower()

    # --- Timestamp freshness (replay protection) ---
    ok, reason = _verify_timestamp(capture, payload_data, broker_num)
    if not ok:
        capture.logger.warning(
            f"Dropping command '{_sanitize_log_field(command_type)}' from {broker_label} - {reason}"
        )
        return

    # --- Nonce deduplication ---
    nonce_val = payload_data.get("nonce") or payload_data.get("id") or payload_data.get("msg_id")
    ok, reason = _check_and_record_nonce(capture, broker_num, nonce_val)
    if not ok:
        capture.logger.warning(
            f"Dropping duplicate/reused command '{_sanitize_log_field(command_type)}' from {broker_label} - {reason}"
        )
        return

    # --- HMAC verification (moves trust boundary off broker) ---
    ok, hmac_msg = _verify_hmac(capture, broker_num, command_type, payload_data)
    if not ok:
        capture.logger.warning(
            f"Dropping command '{_sanitize_log_field(command_type)}' from {broker_label} - {hmac_msg}"
        )
        # Clean up nonce on HMAC failure so retry with correct HMAC can succeed? Keep it to prevent brute force replay.
        return
    if "no HMAC key" in hmac_msg:
        # Log once per broker that we are in transport-only trust mode
        if not hasattr(capture, "_command_hmac_warned"):
            capture._command_hmac_warned = set()
        if broker_num not in capture._command_hmac_warned:
            capture.logger.warning(
                f"Command ingress on {broker_label} using transport-only trust (no HMAC). "
                f"Set PACKETCAPTURE_MQTT{broker_num}_COMMAND_HMAC_KEY for cryptographic authentication."
            )
            capture._command_hmac_warned.add(broker_num)

    # --- Rate limiting ---
    ok, reason = _check_rate_limit(capture, broker_num)
    if not ok:
        capture.logger.warning(
            f"Dropping command '{_sanitize_log_field(command_type)}' from {broker_label} - {reason}"
        )
        return

    if capture._event_loop is None:
        capture.logger.warning("Event loop unavailable; cannot process MQTT command")
        return

    # Record rate limit *before* dispatch to prevent burst queueing
    _record_rate_limit(capture, broker_num)

    future = asyncio.run_coroutine_threadsafe(
        process_mqtt_command(capture, command_type, payload_data, broker_num),
        capture._event_loop,
    )

    def _done_callback(done_future: Any) -> None:
        try:
            done_future.result()
        except Exception as exc:
            capture.logger.error(f"Error processing MQTT command '{_sanitize_log_field(command_type)}': {_sanitize_log_field(exc, 300)}")

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
    lock = _get_command_execution_lock(capture, broker_num)

    async with lock:
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
                    f"MQTT command '{_sanitize_log_field(command_name)}' failed on {broker_label}: no response"
                )
                return False
            if hasattr(result, "type") and result.type == EventType.ERROR:
                capture.logger.warning(
                    f"MQTT command '{_sanitize_log_field(command_name)}' failed on {broker_label}: {_sanitize_log_field(result.payload, 200)}"
                )
                return False
            if on_success is not None:
                try:
                    success_message = on_success(result)
                    if success_message:
                        capture.logger.info(success_message)
                except Exception as e:
                    capture.logger.warning(f"Success callback failed for {command_name}: {e}")
            else:
                capture.logger.info(
                    f"MQTT command '{_sanitize_log_field(command_name)}' succeeded on {broker_label}"
                )
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

            # Basic validation and sanitization for log injection
            dest_clean = _sanitize_log_field(destination, 80)
            msg_clean = _sanitize_log_field(message, 200)

            async def _send_msg_command() -> Any:
                result = await capture.meshcore.commands.send_msg(destination, message)
                return result

            await _run_command(
                "send_msg",
                _send_msg_command,
                on_success=lambda result: f"📤 Sent direct message (to={dest_clean}): {msg_clean}",
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

            msg_clean = _sanitize_log_field(message, 200)

            await _run_command(
                "send_chan_msg",
                lambda: capture.meshcore.commands.send_chan_msg(channel_idx, message),
                on_success=lambda result: f"📤 Sent channel message (channel={channel_idx}): {msg_clean}",
            )
            return

        capture.logger.warning(
            f"Unknown MQTT command '{_sanitize_log_field(command)}' from {broker_label}"
        )
