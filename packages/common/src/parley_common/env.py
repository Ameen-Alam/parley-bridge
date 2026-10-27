"""The one reader of ``PARLEY_`` configuration (T-0047).

Every service reads its settings through these functions, so the rules live in one
place (founder's deploy findings of 13 October, items 1a, 1c and 1d; deploy runbook
section 3):

- A blank value means unset. Compose's ``env_file`` hands an empty ``NAME=`` line to the
  container as an empty string, and ``.env.example`` leaves every optional variable
  empty, so an empty or all-whitespace value reads exactly like a missing one and the
  default applies.
- A value is stripped of surrounding whitespace before it is used.
- A value the reader cannot parse is refused with :class:`ConfigError`, whose message
  names the variable and the rule and never the value, its characters or its length
  (product rule 1: a secret is never printed). The parse error is never chained, so a
  traceback cannot carry the value either.
- A flag (:func:`env_flag`) is on only for an explicit ``true``, ``1`` or ``yes`` in any
  case; anything else, blank included, is off.
- The relay's signing key (:func:`env_signing_key`) is 43 base64url characters, the
  canonical spelling of a 32-byte Ed25519 seed, and nothing else: a trailing comment
  that Docker Compose kept inside the value is refused like any wrong length.

Each function takes an optional ``environ`` mapping for tests; by default it reads
:data:`os.environ` at the moment of the call.
"""

from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping

from parley_common import signing

TRUE_VALUES: frozenset[str] = frozenset({"true", "1", "yes"})
"""The only values that turn a flag on, compared case-insensitively."""
SIGNING_KEY_LENGTH = 43
"""Base64url characters in an Ed25519 private key (a 32-byte seed, unpadded)."""
_SIGNING_KEY_SHAPE = re.compile(r"[A-Za-z0-9_-]{43}")
_WHOLE_NUMBER = re.compile(r"[+-]?[0-9]+")


class ConfigError(ValueError):
    """A configuration value the service cannot use. The message names the variable and
    the rule only, never the value."""


def _environ(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def env_text(
    name: str, default: str | None = None, *, environ: Mapping[str, str] | None = None
) -> str | None:
    """The stripped value of ``name``, or ``default`` when it is unset or blank."""
    raw = _environ(environ).get(name)
    if raw is None:
        return default
    value = raw.strip()
    return value if value else default


def env_int(
    name: str,
    default: int,
    *,
    minimum: int = 1,
    environ: Mapping[str, str] | None = None,
) -> int:
    """A whole number of at least ``minimum``, or ``default`` when unset or blank."""
    value = env_text(name, environ=environ)
    if value is None:
        return default
    if _WHOLE_NUMBER.fullmatch(value) is None or int(value) < minimum:
        raise ConfigError(f"{name} must be a whole number of at least {minimum}")
    return int(value)


def env_seconds(
    name: str,
    default: float,
    *,
    maximum: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> float:
    """A finite number of seconds greater than zero, brought down to ``maximum`` when one
    is given; ``default`` when unset or blank."""
    value = env_text(name, environ=environ)
    if value is None:
        return default
    try:
        seconds = float(value)
    except ValueError:
        seconds = math.nan
    if not math.isfinite(seconds) or seconds <= 0:
        raise ConfigError(f"{name} must be a finite number of seconds greater than zero")
    return seconds if maximum is None else min(seconds, maximum)


def env_flag(name: str, *, environ: Mapping[str, str] | None = None) -> bool:
    """True only for an explicit ``true``, ``1`` or ``yes`` (any case); else False."""
    value = env_text(name, environ=environ)
    return value is not None and value.lower() in TRUE_VALUES


def env_list(name: str, *, environ: Mapping[str, str] | None = None) -> frozenset[str]:
    """A comma-separated list as a set of its non-blank, stripped items; empty when
    unset or blank."""
    value = env_text(name, environ=environ)
    if value is None:
        return frozenset()
    return frozenset(part.strip() for part in value.split(",") if part.strip())


def env_signing_key(
    name: str, *, environ: Mapping[str, str] | None = None
) -> signing.PrivateKey | None:
    """The Ed25519 private key in ``name``, or None when it is unset or blank (the caller
    decides whether a missing key may start the service). Anything but 43 canonical
    base64url characters is refused naming the variable and the rule."""
    value = env_text(name, environ=environ)
    if value is None:
        return None
    rule = (
        f"{name} must be an Ed25519 private key: exactly {SIGNING_KEY_LENGTH} base64url "
        "characters (A-Z, a-z, 0-9, - and _) with nothing before or after them, on a "
        "line of its own"
    )
    if _SIGNING_KEY_SHAPE.fullmatch(value) is None:
        raise ConfigError(rule)
    try:
        return signing.PrivateKey.from_base64url(value)
    except (signing.SigningError, ValueError):
        raise ConfigError(rule) from None


__all__ = [
    "SIGNING_KEY_LENGTH",
    "TRUE_VALUES",
    "ConfigError",
    "env_flag",
    "env_int",
    "env_list",
    "env_seconds",
    "env_signing_key",
    "env_text",
]
