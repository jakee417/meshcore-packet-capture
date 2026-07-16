"""Tests for per-broker owner email configuration."""
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from installer import config as cfg


def _seed_user_toml(config_dir: Path) -> Path:
    config_d = config_dir / "config.d"
    config_d.mkdir(parents=True, exist_ok=True)
    dest = cfg.user_config_path(config_dir)
    cfg.write_user_toml_base(
        str(dest), "SEA", "agessaman/x", "main",
        {"type": "serial", "serial_device": "/dev/ttyUSB0"},
    )
    return dest


def _write_token_preset(config_d: Path, filename: str, name: str, server: str) -> None:
    (config_d / filename).write_text(
        f'''[[broker]]
name = "{name}"
enabled = true
server = "{server}"
port = 443
transport = "websockets"

[broker.tls]
enabled = true

[broker.auth]
method = "token"
audience = "{server}"
'''
    )


def _broker_emails(path: Path) -> dict[str, str]:
    data = tomllib.loads(path.read_text())
    emails: dict[str, str] = {}
    for broker in data.get("broker", []):
        auth = broker.get("auth") or {}
        if broker.get("name") and auth.get("email"):
            emails[str(broker["name"])] = str(auth["email"])
    return emails


def test_rewrite_token_owner_overrides_distinct_emails(tmp_path: Path):
    config_dir = tmp_path / "etc"
    dest = _seed_user_toml(config_dir)
    owner = "A" * 64

    cfg._rewrite_token_owner_overrides_toml(str(dest), ["meshmapper"], owner, "mesh@example.com")
    cfg._rewrite_token_owner_overrides_toml(str(dest), ["waev"], owner, "waev@example.com")

    assert _broker_emails(dest) == {
        "meshmapper": "mesh@example.com",
        "waev": "waev@example.com",
    }


def test_configure_token_preset_overrides_per_broker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    config_dir = tmp_path / "etc"
    dest = _seed_user_toml(config_dir)
    config_d = config_dir / "config.d"
    _write_token_preset(config_d, "10-meshmapper.toml", "meshmapper", "mqtt.meshmapper.net")
    _write_token_preset(config_d, "10-waev.toml", "waev", "mqtt.waev.app")

    owner_keys = iter(["A" * 64, "A" * 64])
    emails = iter(["mesh@example.com", "waev@example.com"])

    def _yes_no(prompt: str, default: str = "n") -> bool:
        if "same owner public key and email for all" in prompt:
            return False
        return default == "y"

    monkeypatch.setattr(cfg, "prompt_yes_no", _yes_no)
    monkeypatch.setattr(cfg, "prompt_input", lambda prompt, default="": "2" if "Choose" in prompt else default)
    monkeypatch.setattr(cfg, "prompt_owner_pubkey", lambda existing="": next(owner_keys))
    monkeypatch.setattr(cfg, "prompt_owner_email", lambda existing="": next(emails))

    cfg._configure_token_preset_overrides(str(config_dir))

    assert _broker_emails(dest) == {
        "meshmapper": "mesh@example.com",
        "waev": "waev@example.com",
    }


def test_update_owner_info_routes_to_safe_config_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    config_dir = tmp_path / "etc"
    dest = _seed_user_toml(config_dir)
    owner = "A" * 64
    cfg._rewrite_token_owner_overrides_toml(
        str(dest), ["meshmapper", "waev"], owner, "mesh@example.com"
    )
    cfg._rewrite_token_owner_overrides_toml(str(dest), ["waev"], owner, "waev@example.com")
    before = _broker_emails(dest)

    calls: list[str] = []

    def _preset_overrides(config_dir_arg: str) -> None:
        calls.append("preset")

    def _user_overrides(config_dir_arg: str, broker_names: list[str]) -> None:
        calls.append("user")

    preset = tmp_path / "10-meshmapper.toml"
    monkeypatch.setattr(cfg, "token_preset_brokers", lambda _d: {preset: ["meshmapper"]})
    monkeypatch.setattr(cfg, "_user_token_broker_names", lambda _d: ["custom-token"])
    monkeypatch.setattr(cfg, "_configure_token_preset_overrides", _preset_overrides)
    monkeypatch.setattr(cfg, "_configure_user_token_owner_overrides", _user_overrides)

    cfg.update_owner_info(str(config_dir))

    assert calls == ["preset", "user"]
    assert _broker_emails(dest) == before


def test_update_owner_info_decline_preserves_distinct_emails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    config_dir = tmp_path / "etc"
    dest = _seed_user_toml(config_dir)
    config_d = config_dir / "config.d"
    _write_token_preset(config_d, "10-meshmapper.toml", "meshmapper", "mqtt.meshmapper.net")
    _write_token_preset(config_d, "10-waev.toml", "waev", "mqtt.waev.app")

    owner = "A" * 64
    cfg._rewrite_token_owner_overrides_toml(str(dest), ["meshmapper"], owner, "mesh@example.com")
    cfg._rewrite_token_owner_overrides_toml(str(dest), ["waev"], owner, "waev@example.com")
    before = _broker_emails(dest)

    monkeypatch.setattr(
        cfg,
        "prompt_yes_no",
        lambda prompt, default="n": False if "Update owner info" in prompt else default == "y",
    )

    cfg.update_owner_info(str(config_dir))

    assert _broker_emails(dest) == before
