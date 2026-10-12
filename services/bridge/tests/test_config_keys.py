"""Criterion 6 and story 9.3: configuration by environment only; the key file is the one
thing on disk, owner-only, never overwritten, deleted by unlink."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from support import make_key

from parley_bridge import keys, server
from parley_bridge.config import (
    DEFAULT_HISTORY_LIMIT,
    DEFAULT_KEY_PATH,
    DEFAULT_PINGPONG_LIMIT,
    DEFAULT_RELAY_URL,
    ConfigError,
    settings_from_env,
)


def test_settings_come_from_the_environment_with_the_record_defaults() -> None:
    settings = settings_from_env({})
    assert settings.relay_url == DEFAULT_RELAY_URL
    assert settings.key_path == DEFAULT_KEY_PATH
    assert settings.wake_command == ()
    assert settings.challenge_payload == "auto" and settings.transport == "auto"
    assert settings.pingpong_limit == DEFAULT_PINGPONG_LIMIT == 6
    assert settings.history_limit == DEFAULT_HISTORY_LIMIT == 20
    assert settings.text_only is True and settings.secret_guard is True
    custom = settings_from_env(
        {
            "PARLEY_RELAY_URL": "https://relay.example/",
            "PARLEY_BRIDGE_KEY_PATH": "C:/keys/k.json" if sys.platform == "win32" else "/k/k.json",
            "PARLEY_BRIDGE_WAKE_COMMAND": "python -c 'print(1)'",
            "PARLEY_BRIDGE_CHALLENGE_PAYLOAD": "bare",
            "PARLEY_BRIDGE_TRANSPORT": "poll",
            "PARLEY_BRIDGE_PINGPONG_LIMIT": "0",
            "PARLEY_BRIDGE_HISTORY_LIMIT": "5",
            "PARLEY_BRIDGE_TEXT_ONLY": "0",
            "PARLEY_BRIDGE_SECRET_GUARD": "off",
        }
    )
    assert custom.relay_url == "https://relay.example"
    assert custom.websocket_url == "wss://relay.example/connect"
    assert custom.wake_command == ("python", "-c", "print(1)")
    assert custom.challenge_payload == "bare" and custom.transport == "poll"
    assert custom.pingpong_limit == 0 and custom.history_limit == 5
    assert custom.text_only is False and custom.secret_guard is False
    assert "relay.example" not in repr(custom)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PARLEY_RELAY_URL", "relay.example"),
        ("PARLEY_RELAY_URL", "http://relay.example"),
        ("PARLEY_RELAY_URL", "http://10.0.0.7:8000"),
        ("PARLEY_RELAY_URL", "http://127.evil.example"),
        ("PARLEY_RELAY_URL", "http://127.0.0.1.evil.example:8000"),
        ("PARLEY_RELAY_URL", "http://localhost.evil.example"),
        ("PARLEY_BRIDGE_CHALLENGE_PAYLOAD", "signed"),
        ("PARLEY_BRIDGE_TRANSPORT", "carrier-pigeon"),
        ("PARLEY_BRIDGE_PINGPONG_LIMIT", "many"),
        ("PARLEY_BRIDGE_HISTORY_LIMIT", "0"),
        ("PARLEY_BRIDGE_TEXT_ONLY", "maybe"),
        ("PARLEY_BRIDGE_WAKE_COMMAND", "python -c 'unterminated"),
    ],
)
def test_a_bad_setting_names_the_variable_and_never_its_value(name: str, value: str) -> None:
    with pytest.raises(ConfigError) as caught:
        settings_from_env({name: value})
    assert name in str(caught.value) and value not in str(caught.value)


def test_plain_http_is_accepted_for_loopback_only() -> None:
    for url in (
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://127.5.5.5:8000",
        "http://[::1]:8000",
    ):
        assert settings_from_env({"PARLEY_RELAY_URL": url}).relay_url == url
    assert settings_from_env({"PARLEY_RELAY_URL": "https://relay.example"}).websocket_url == (
        "wss://relay.example/connect"
    )


def test_an_existing_parent_directory_keeps_its_permissions(tmp_path: Path) -> None:
    """Security item 7: only a directory the bridge created is restricted."""
    parent = tmp_path / "shared"
    parent.mkdir()
    if sys.platform != "win32":
        parent.chmod(0o755)
    keys.save(parent / "bridge-key.json", make_key("device-9"))
    if sys.platform != "win32":
        assert parent.stat().st_mode & 0o777 == 0o755
        assert (parent / "bridge-key.json").stat().st_mode & 0o777 == 0o600
    made = tmp_path / "made" / "by" / "bridge"
    keys.save(made / "bridge-key.json", make_key("device-10"))
    if sys.platform != "win32":
        assert made.stat().st_mode & 0o777 == 0o700


def test_key_file_round_trip_owner_only_and_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "deep" / "bridge-key.json"
    key = make_key("device-7")
    keys.save(path, key)
    loaded = keys.load(path)
    assert loaded.device_id == "device-7"
    assert loaded.private_key == key.private_key and loaded.relay_url == key.relay_url
    assert "private" not in repr(loaded).lower() or "PrivateKey" not in repr(loaded)
    assert key.private_key.to_base64url() not in repr(loaded)
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700
    with pytest.raises(keys.KeyFileError, match="unlink"):
        keys.save(path, make_key("device-8"))
    assert keys.load(path).device_id == "device-7"
    assert keys.delete(path) is True and not path.exists()
    assert keys.delete(path) is False


def test_a_damaged_key_file_is_refused_without_showing_its_content(tmp_path: Path) -> None:
    path = tmp_path / "k.json"
    with pytest.raises(keys.KeyFileError, match="not paired"):
        keys.load(path)
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(keys.KeyFileError, match="not JSON"):
        keys.load(path)
    path.write_text(json.dumps({"format_version": 1, "device_id": "d"}), encoding="utf-8")
    with pytest.raises(keys.KeyFileError, match="missing"):
        keys.load(path)
    path.write_text(
        json.dumps({"format_version": 1, "device_id": "d", "private_key": "!!", "relay_url": "u"}),
        encoding="utf-8",
    )
    with pytest.raises(keys.KeyFileError) as caught:
        keys.load(path)
    assert "!!" not in str(caught.value)


def test_unlink_and_status_commands_act_on_the_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "bridge-key.json"
    monkeypatch.setenv("PARLEY_BRIDGE_KEY_PATH", str(path))
    with pytest.raises(SystemExit) as exit_status:
        server.main(["status"])
    assert exit_status.value.code == 1
    assert "Not paired" in capsys.readouterr().out
    keys.save(path, make_key("device-3"))
    with pytest.raises(SystemExit) as exit_status:
        server.main(["status"])
    assert exit_status.value.code == 0
    assert "device-3" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_status:
        server.main(["unlink"])
    assert exit_status.value.code == 0 and not path.exists()
    assert "unlinked" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exit_status:
        server.main(["run"])
    assert exit_status.value.code == 1  # not paired: the server does not start
