"""The bridge's settings, read from the environment only (criterion 6).

There is no configuration file. Everything the bridge needs is one of these variables:

- ``PARLEY_RELAY_URL``: the relay's origin, ``https://relay.example``. It is the only
  network destination the bridge ever talks to (story 9.4). Default
  ``http://127.0.0.1:8000`` for a local relay. Plain ``http://`` is accepted for a
  loopback host only (``localhost``, ``127.0.0.1``, ``::1``); every other relay must be
  ``https://`` (6b: all traffic over TLS).
- ``PARLEY_BRIDGE_KEY_PATH``: the file that holds the device's private key once paired
  (story 9.3). Default ``~/.parley/bridge-key.json``. Nothing else is stored on disk.
- ``PARLEY_BRIDGE_WAKE_COMMAND``: a command run once per wake-up frame (story 9.2),
  split like a shell would but run without one. Unset means no command.
- ``PARLEY_BRIDGE_CHALLENGE_PAYLOAD``: ``auto`` (default), ``domain`` or ``bare``; see
  :mod:`parley_bridge.connection` for the two payloads and the transition.
- ``PARLEY_BRIDGE_TRANSPORT``: ``auto`` (default: WebSocket, long-poll when the upgrade
  is refused), ``websocket`` or ``poll``.
- ``PARLEY_BRIDGE_PINGPONG_LIMIT``: the courtesy loop guard from c2chat, 6 by default,
  ``0`` disables. The relay's bounce limit is the control (product rule 3).
- ``PARLEY_BRIDGE_HISTORY_LIMIT``: messages ``check_inbox`` returns at most, 20 by default.
- ``PARLEY_BRIDGE_TEXT_ONLY``: ``1`` (default) refuses links and attachments in text to
  another owner (story 4.14); ``0`` turns the default off.
- ``PARLEY_BRIDGE_SECRET_GUARD``: ``1`` (default) refuses outgoing text that looks like a
  key (story 9.7); ``0`` turns the default off. A default, never a guarantee.

Nothing here logs; a value is never put in an error message.
"""

from __future__ import annotations

import ipaddress
import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ENV_RELAY_URL = "PARLEY_RELAY_URL"
ENV_KEY_PATH = "PARLEY_BRIDGE_KEY_PATH"
ENV_WAKE_COMMAND = "PARLEY_BRIDGE_WAKE_COMMAND"
ENV_CHALLENGE_PAYLOAD = "PARLEY_BRIDGE_CHALLENGE_PAYLOAD"
ENV_TRANSPORT = "PARLEY_BRIDGE_TRANSPORT"
ENV_PINGPONG_LIMIT = "PARLEY_BRIDGE_PINGPONG_LIMIT"
ENV_HISTORY_LIMIT = "PARLEY_BRIDGE_HISTORY_LIMIT"
ENV_TEXT_ONLY = "PARLEY_BRIDGE_TEXT_ONLY"
ENV_KEY_GUARD = "PARLEY_BRIDGE_SECRET_GUARD"

DEFAULT_RELAY_URL = "http://127.0.0.1:8000"
DEFAULT_KEY_PATH = Path.home() / ".parley" / "bridge-key.json"
DEFAULT_PINGPONG_LIMIT = 6
DEFAULT_HISTORY_LIMIT = 20

CHALLENGE_PAYLOADS = ("auto", "domain", "bare")
TRANSPORTS = ("auto", "websocket", "poll")


class ConfigError(ValueError):
    """A setting has a shape the bridge cannot use. The message names the variable only."""


@dataclass(frozen=True, slots=True)
class Settings:
    relay_url: str
    key_path: Path
    wake_command: tuple[str, ...]
    challenge_payload: str = "auto"
    transport: str = "auto"
    pingpong_limit: int = DEFAULT_PINGPONG_LIMIT
    history_limit: int = DEFAULT_HISTORY_LIMIT
    text_only: bool = True
    secret_guard: bool = True

    def __repr__(self) -> str:
        return f"Settings(transport={self.transport!r}, challenge={self.challenge_payload!r})"

    @property
    def websocket_url(self) -> str:
        """``WS /connect`` on the relay: ``http`` becomes ``ws``, ``https`` becomes ``wss``."""
        base = self.relay_url
        if base.startswith("https://"):
            base = "wss://" + base[len("https://") :]
        elif base.startswith("http://"):
            base = "ws://" + base[len("http://") :]
        return base + "/connect"


def settings_from_env(environ: os._Environ[str] | dict[str, str] | None = None) -> Settings:
    """Read the settings; ``environ`` defaults to the process environment."""
    env = os.environ if environ is None else environ
    relay_url = env.get(ENV_RELAY_URL, DEFAULT_RELAY_URL).strip().rstrip("/")
    if not relay_url.startswith(("http://", "https://")):
        raise ConfigError(f"{ENV_RELAY_URL} must start with http:// or https://")
    if relay_url.startswith("http://") and not _is_loopback(relay_url):
        raise ConfigError(f"{ENV_RELAY_URL} must be https:// unless the relay is on this machine")
    raw_path = env.get(ENV_KEY_PATH, "").strip()
    key_path = Path(raw_path).expanduser() if raw_path else DEFAULT_KEY_PATH
    raw_command = env.get(ENV_WAKE_COMMAND, "").strip()
    try:
        wake_command = tuple(shlex.split(raw_command)) if raw_command else ()
    except ValueError as error:
        raise ConfigError(f"{ENV_WAKE_COMMAND} is not a well-formed command line") from error
    challenge = _choice(env, ENV_CHALLENGE_PAYLOAD, CHALLENGE_PAYLOADS)
    transport = _choice(env, ENV_TRANSPORT, TRANSPORTS)
    return Settings(
        relay_url=relay_url,
        key_path=key_path,
        wake_command=wake_command,
        challenge_payload=challenge,
        transport=transport,
        pingpong_limit=_count(env, ENV_PINGPONG_LIMIT, DEFAULT_PINGPONG_LIMIT, minimum=0),
        history_limit=_count(env, ENV_HISTORY_LIMIT, DEFAULT_HISTORY_LIMIT, minimum=1),
        text_only=_flag(env, ENV_TEXT_ONLY, True),
        secret_guard=_flag(env, ENV_KEY_GUARD, True),
    )


def _is_loopback(url: str) -> bool:
    """``localhost`` or a loopback IP address; a name that merely starts with ``127.`` is
    not one (``127.evil.example`` is a host name)."""
    host = urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _choice(env: os._Environ[str] | dict[str, str], name: str, allowed: tuple[str, ...]) -> str:
    value = env.get(name, allowed[0]).strip().lower() or allowed[0]
    if value not in allowed:
        raise ConfigError(f"{name} must be one of: " + ", ".join(allowed))
    return value


def _count(env: os._Environ[str] | dict[str, str], name: str, default: int, *, minimum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ConfigError(f"{name} must be a whole number") from error
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


def _flag(env: os._Environ[str] | dict[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be 1 or 0")
