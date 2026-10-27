"""Tests for parley_common.env, the one reader of PARLEY_ configuration (T-0047).

Every value here is made up. The key values are built from fixed bytes so the checks
on what an error may say are the same on every run; no assertion message carries a
value.
"""

from __future__ import annotations

import traceback

import pytest

from parley_common import signing
from parley_common.env import (
    SIGNING_KEY_LENGTH,
    ConfigError,
    env_flag,
    env_int,
    env_list,
    env_seconds,
    env_signing_key,
    env_text,
)

NAME = "PARLEY_EXAMPLE_SETTING"
KEY_NAME = "PARLEY_RELAY_SIGNING_KEY"
GOOD_KEY = signing.PrivateKey(bytes(range(32))).to_base64url()


def _windows(value: str, size: int = 4) -> set[str]:
    return {value[i : i + size] for i in range(len(value) - size + 1)}


def _says_nothing_of(error: BaseException, value: str) -> bool:
    """True when neither the message nor the whole printed traceback (chained causes
    included) carries the value or any four characters of it in a row."""
    printed = "".join(traceback.format_exception(error))
    return all(window not in printed for window in _windows(value))


@pytest.mark.parametrize("raw", [None, "", " ", "\t", "  \n"])
def test_blank_or_missing_reads_as_unset_for_every_reader(raw: str | None) -> None:
    """Criterion 1: a blank value means unset; the default applies everywhere."""
    environ = {} if raw is None else {NAME: raw, KEY_NAME: raw}
    assert env_text(NAME, environ=environ) is None
    assert env_text(NAME, "fallback", environ=environ) == "fallback"
    assert env_int(NAME, 7, environ=environ) == 7
    assert env_seconds(NAME, 2.5, environ=environ) == 2.5
    assert env_flag(NAME, environ=environ) is False
    assert env_list(NAME, environ=environ) == frozenset()
    assert env_signing_key(KEY_NAME, environ=environ) is None


def test_values_are_stripped_and_parsed() -> None:
    environ = {
        "PARLEY_A": "  some-text  ",
        "PARLEY_B": " 42 ",
        "PARLEY_C": "1.5",
        "PARLEY_D": " one, two ,, three ",
        "PARLEY_E": "7200",
    }
    assert env_text("PARLEY_A", environ=environ) == "some-text"
    assert env_int("PARLEY_B", 1, environ=environ) == 42
    assert env_seconds("PARLEY_C", 9.0, environ=environ) == 1.5
    assert env_list("PARLEY_D", environ=environ) == frozenset({"one", "two", "three"})
    assert env_seconds("PARLEY_E", 1.0, maximum=3600.0, environ=environ) == 3600.0
    assert env_int("PARLEY_B", 1, minimum=42, environ=environ) == 42


@pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", "YES", "Yes", " yes "])
def test_a_flag_is_on_for_an_explicit_true(value: str) -> None:
    """Criterion 4: true, 1 or yes, in any case."""
    assert env_flag(NAME, environ={NAME: value}) is True


@pytest.mark.parametrize(
    "value", ["", "0", "false", "no", "off", "on", "y", "t", "2", "truee", "yes # dev", "1.0"]
)
def test_a_flag_is_off_for_anything_else(value: str) -> None:
    """Criterion 4: anything but an explicit true is off, blank included."""
    assert env_flag(NAME, environ={NAME: value}) is False


@pytest.mark.parametrize("value", ["abc", "1.5", "0", "-3", "12 # comment", "1e3", "٣", "0x10"])
def test_an_unparsable_whole_number_is_refused_naming_the_variable(value: str) -> None:
    """Criterion 3: refused with the variable's name and the rule, never the value."""
    with pytest.raises(ConfigError) as caught:
        env_int(NAME, 5, environ={NAME: value})
    message = str(caught.value)
    assert message == f"{NAME} must be a whole number of at least 1"
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("value", ["abc", "nan", "inf", "-inf", "0", "-1", "30 # half a minute"])
def test_an_unparsable_number_of_seconds_is_refused_naming_the_variable(value: str) -> None:
    """Criterion 3 for the seconds variables."""
    with pytest.raises(ConfigError) as caught:
        env_seconds(NAME, 5.0, environ={NAME: value})
    assert str(caught.value) == f"{NAME} must be a finite number of seconds greater than zero"
    assert caught.value.__cause__ is None


def test_a_valid_signing_key_is_read() -> None:
    key = env_signing_key(KEY_NAME, environ={KEY_NAME: f"  {GOOD_KEY}  "})
    assert key is not None and key.to_base64url() == GOOD_KEY
    assert len(GOOD_KEY) == SIGNING_KEY_LENGTH


BAD_KEYS = {
    "one character short": GOOD_KEY[:-1],
    "one character long": GOOD_KEY + "A",
    "padded": GOOD_KEY + "=",
    "standard base64 alphabet": "+" + GOOD_KEY[1:],
    "slash": GOOD_KEY[:20] + "/" + GOOD_KEY[21:],
    "trailing comment": GOOD_KEY + " # 77",
    "trailing text": GOOD_KEY + "xyz",
    "quoted": f'"{GOOD_KEY}"',
    "not canonical": GOOD_KEY[:-1] + "9",
    "a public key's hex": "ab" * 32,
}


@pytest.mark.parametrize("label", sorted(BAD_KEYS))
def test_a_bad_signing_key_is_refused_naming_the_variable_and_never_the_value(label: str) -> None:
    """Criterion 2: wrong length, not base64url or trailing text is refused with the
    variable's name and the rule (43 characters); neither the message nor the printed
    traceback carries the value."""
    value = BAD_KEYS[label]
    with pytest.raises(ConfigError) as caught:
        env_signing_key(KEY_NAME, environ={KEY_NAME: value})
    message = str(caught.value)
    assert KEY_NAME in message and f"exactly {SIGNING_KEY_LENGTH} base64url" in message
    error = caught.value
    assert error.__cause__ is None and (error.__context__ is None or error.__suppress_context__)
    quiet = _says_nothing_of(caught.value, value)
    assert quiet, label
