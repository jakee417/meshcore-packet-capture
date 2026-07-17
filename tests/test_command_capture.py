from __future__ import annotations

import asyncio
import logging
import time
from types import SimpleNamespace

from meshcore_packet_capture.command_capture import process_mqtt_command


class _FakeCommands:
    def __init__(self, events: list[tuple[str, float]]) -> None:
        self._events = events

    async def send_msg(self, destination: str, message: str) -> SimpleNamespace:
        self._events.append((f"start:{message}", time.monotonic()))
        await asyncio.sleep(0.02)
        self._events.append((f"end:{message}", time.monotonic()))
        return SimpleNamespace(type=None, payload=None)


class _FakeCapture:
    def __init__(self, events: list[tuple[str, float]]) -> None:
        self.logger = logging.getLogger("test-command-capture")
        self.meshcore = SimpleNamespace(commands=_FakeCommands(events))
        self.default_retry_limit = 0

    def get_broker_label(self, broker_num: int | None) -> str:
        return f"broker-{broker_num}"

    def _ensure_connected(self, context: str, level: str) -> bool:
        return True

    async def retryable_device_command(
        self,
        command_func,
        command_name: str,
        timeout: float,
        max_retries: int,
        retry_delay: float,
    ) -> SimpleNamespace:
        return await command_func()


def test_process_mqtt_command_serializes_per_broker() -> None:
    events: list[tuple[str, float]] = []
    capture = _FakeCapture(events)

    async def runner() -> None:
        await asyncio.gather(
            process_mqtt_command(
                capture,
                "send_msg",
                {"destination": "alice", "message": "first"},
                1,
            ),
            process_mqtt_command(
                capture,
                "send_msg",
                {"destination": "alice", "message": "second"},
                1,
            ),
        )

    asyncio.run(runner())

    starts = {label: ts for label, ts in events if label.startswith("start:")}
    ends = {label: ts for label, ts in events if label.startswith("end:")}
    assert starts["start:second"] >= ends["end:first"]