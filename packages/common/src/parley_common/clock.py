"""The one clock.

Every service reads time from here, so tests can see one format everywhere
and no naive datetime slips in. The relay's clock is the only clock that
counts for limits (sign-off minutes, Item 4: "The service's clock is the only
clock").
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# Exactly the shape to_iso writes; strptime alone would accept a three-digit year.
_ISO_SHAPE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def utc_now() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(UTC)


def to_iso(moment: datetime) -> str:
    """Format an aware datetime as ISO 8601 in UTC with a trailing Z, second precision."""
    if moment.tzinfo is None:
        raise ValueError("naive datetime: every time in Parley is timezone-aware UTC")
    m = moment.astimezone(UTC)
    # Not strftime: glibc's %Y does not zero-pad years below 1000, and stored
    # times are compared as text, so every field must be fixed width.
    return f"{m.year:04d}-{m.month:02d}-{m.day:02d}T{m.hour:02d}:{m.minute:02d}:{m.second:02d}Z"


def from_iso(text: str) -> datetime:
    """Parse the format produced by :func:`to_iso` back into an aware UTC datetime."""
    if not _ISO_SHAPE.match(text):
        raise ValueError("time text must be exactly YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(text, ISO_FORMAT).replace(tzinfo=UTC)


def now_iso() -> str:
    """Shorthand for ``to_iso(utc_now())``."""
    return to_iso(utc_now())
