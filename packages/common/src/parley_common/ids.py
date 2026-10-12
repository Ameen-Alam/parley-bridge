"""Request IDs: 128-bit, URL-safe, time-sortable, ULID-style.

A request ID is 26 characters of Crockford base32: a 48-bit millisecond
timestamp from :mod:`parley_common.clock` followed by 80 random bits. IDs made
in the same millisecond are monotonic (the random part is incremented), so
string order is creation order within one process. :func:`parse` returns the
embedded timestamp as an aware UTC datetime.

Nothing here logs or prints, and no ID appears in an exception message.
"""

from __future__ import annotations

import secrets
import threading
from datetime import UTC, datetime

from parley_common import clock

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ID_LENGTH = 26
_TIME_BITS = 48
_RANDOM_BITS = 80
_MAX_RANDOM = (1 << _RANDOM_BITS) - 1
_MAX_TIME = (1 << _TIME_BITS) - 1
_DECODE = {char: index for index, char in enumerate(ALPHABET)}
# Crockford decoding tolerates the usual confusable letters on input.
_DECODE.update({"O": 0, "I": 1, "L": 1})


class InvalidRequestIdError(ValueError):
    """The text is not a request ID. The message never carries the text."""


class _Generator:
    """Monotonic ULID state for one process, guarded by a lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_random = 0

    def next_id(self) -> str:
        ms = _epoch_ms(clock.utc_now())
        with self._lock:
            if ms <= self._last_ms:
                # Same millisecond, or a clock that stepped back: stay sortable
                # by continuing from the previous value.
                ms = self._last_ms
                random_part = self._last_random + 1
                if random_part > _MAX_RANDOM:
                    raise OverflowError("request ID random part exhausted in this millisecond")
            else:
                random_part = secrets.randbits(_RANDOM_BITS)
            self._last_ms = ms
            self._last_random = random_part
        return _encode((ms << _RANDOM_BITS) | random_part)


_generator = _Generator()


def new_request_id() -> str:
    """Return a fresh request ID, later in string order than any made before it here."""
    return _generator.next_id()


def parse(request_id: str) -> datetime:
    """Return the UTC timestamp embedded in ``request_id``.

    Raises :class:`InvalidRequestIdError` when the text is not a well-formed ID.
    """
    if not isinstance(request_id, str) or len(request_id) != ID_LENGTH:
        raise InvalidRequestIdError("request ID must be 26 characters")
    value = 0
    for char in request_id.upper():
        digit = _DECODE.get(char)
        if digit is None:
            raise InvalidRequestIdError("request ID contains a character outside Crockford base32")
        value = (value << 5) | digit
    if value >> (_TIME_BITS + _RANDOM_BITS):
        raise InvalidRequestIdError("request ID is out of range")
    ms = value >> _RANDOM_BITS
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


def _epoch_ms(moment: datetime) -> int:
    if moment.tzinfo is None:
        raise ValueError("naive datetime: every time in Parley is timezone-aware UTC")
    ms = int(moment.timestamp() * 1000)
    if not 0 <= ms <= _MAX_TIME:
        raise ValueError("timestamp outside the 48-bit millisecond range")
    return ms


def _encode(value: int) -> str:
    chars = []
    for _ in range(ID_LENGTH):
        chars.append(ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))
