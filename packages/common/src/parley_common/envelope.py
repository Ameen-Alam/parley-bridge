"""The message envelope every relay module and the bridge share.

An :class:`Envelope` is a frozen dataclass with three groups of fields:

- **Sender fields**, set by the assistant's bridge: ``request_id`` (see
  :mod:`parley_common.ids`), ``thread_id``, ``to`` (recipient IDs), ``body``
  (opaque text, untrusted, never shown in a repr or an error) and ``sent_at``.
- **The five reserved fields** of ruling 5 and the seven additions, item 1:
  ``kind`` (``chat`` is the only kind the test uses), ``commit_id``,
  ``expiry``, ``business_address`` and ``format_version`` (``1``). The
  business track is parked; the fields are reserved so the format does not
  change later.
- **Relay-set identity fields**: ``owner``, ``sent_by`` and
  ``permission_ref``. A sender cannot set them. :meth:`Envelope.from_sender`
  leaves them empty, :meth:`Envelope.from_json` refuses a document that
  carries them unless the relay says the document is its own
  (``trusted=True``), and :meth:`Envelope.stamped_by_relay` is the only way
  to fill them.

On the wire the envelope is a JSON object described by :data:`ENVELOPE_SCHEMA`.
``sent_at`` and ``expiry`` are ISO 8601 UTC strings in the one format of
:mod:`parley_common.clock`; in Python they are aware UTC datetimes at second
precision. The envelope is plain text in the test; encryption between devices
is the queue's concern (T-0006), not this module's.

Nothing here logs or prints. Error messages name fields, never values.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import InitVar, dataclass, field, fields, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from parley_common import clock, ids

FORMAT_VERSION = 1

SENDER_FIELDS = ("request_id", "thread_id", "to", "body", "sent_at")
RESERVED_FIELDS = ("kind", "commit_id", "expiry", "business_address", "format_version")
RELAY_SET_FIELDS = ("owner", "sent_by", "permission_ref")

# A private token: only this module's relay-stamping paths hold it, so a relay
# field can be filled only through stamped_by_relay() or from_json(trusted=True).
_RELAY_STAMP = object()


class Kind(StrEnum):
    """The reserved ``kind`` field. Only ``chat`` is used in the test."""

    CHAT = "chat"
    QUOTE = "quote"
    APPROVAL = "approval"
    RECEIPT = "receipt"


class EnvelopeError(ValueError):
    """Base class: the envelope is not acceptable. Messages name fields, not values."""


class MalformedEnvelopeError(EnvelopeError):
    """The document is not JSON, not an object, or a field has the wrong shape."""


class RelaySetFieldError(EnvelopeError):
    """A sender tried to set a field only the relay may set."""


class UnsupportedFormatVersionError(EnvelopeError):
    """The envelope's ``format_version`` is not one this code understands."""


class AlreadyStampedError(EnvelopeError):
    """The relay tried to stamp an envelope it had already stamped."""


REQUEST_ID_PATTERN = "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
_REQUEST_ID = re.compile(REQUEST_ID_PATTERN)

_STRING_OR_NULL: dict[str, Any] = {"type": ["string", "null"]}
_ISO_UTC: dict[str, Any] = {
    "type": "string",
    "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
}

ENVELOPE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://parley.invalid/schemas/envelope-v1.json",
    "title": "Parley message envelope, format version 1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "request_id",
        "thread_id",
        "to",
        "body",
        "sent_at",
        "kind",
        "commit_id",
        "expiry",
        "business_address",
        "format_version",
    ],
    "properties": {
        "request_id": {
            "type": "string",
            "pattern": REQUEST_ID_PATTERN,
            "description": "ULID-style request ID, 26 characters of Crockford base32.",
        },
        "thread_id": {"type": "string", "minLength": 1},
        "to": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string", "minLength": 1},
            "description": "Recipient IDs.",
        },
        "body": {"type": "string", "description": "Opaque text. Untrusted data."},
        "sent_at": _ISO_UTC,
        "kind": {"type": "string", "enum": [kind.value for kind in Kind]},
        "commit_id": _STRING_OR_NULL,
        "expiry": {"anyOf": [_ISO_UTC, {"type": "null"}]},
        "business_address": _STRING_OR_NULL,
        "format_version": {"type": "integer", "const": FORMAT_VERSION},
        "owner": {"type": "string", "description": "Relay-set. Rejected from a sender."},
        "sent_by": {"type": "string", "description": "Relay-set. Rejected from a sender."},
        "permission_ref": {
            "type": "string",
            "description": "Relay-set. Rejected from a sender.",
        },
    },
}


@dataclass(frozen=True, slots=True)
class Envelope:
    """One message on the relay. Build it with :meth:`from_sender` or :meth:`from_json`."""

    request_id: str
    thread_id: str
    to: tuple[str, ...]
    body: str = field(repr=False)
    sent_at: datetime
    kind: Kind = Kind.CHAT
    commit_id: str | None = None
    expiry: datetime | None = None
    business_address: str | None = None
    format_version: int = FORMAT_VERSION
    owner: str | None = None
    sent_by: str | None = None
    permission_ref: str | None = None
    _stamp: InitVar[object | None] = None

    def __post_init__(self, _stamp: object | None) -> None:
        if self.is_stamped and _stamp is not _RELAY_STAMP:
            raise RelaySetFieldError(
                "only the relay sets owner, sent_by and permission_ref; use stamped_by_relay"
            )
        _check_request_id(self.request_id)
        _check_text("thread_id", self.thread_id)
        object.__setattr__(self, "to", _check_recipients(self.to))
        if not isinstance(self.body, str):
            raise MalformedEnvelopeError("body must be a string")
        object.__setattr__(self, "sent_at", _check_moment("sent_at", self.sent_at))
        object.__setattr__(self, "kind", _check_kind(self.kind))
        _check_optional_text("commit_id", self.commit_id)
        if self.expiry is not None:
            object.__setattr__(self, "expiry", _check_moment("expiry", self.expiry))
        _check_optional_text("business_address", self.business_address)
        if type(self.format_version) is not int or self.format_version != FORMAT_VERSION:
            raise UnsupportedFormatVersionError("format_version must be the integer 1")
        for name in RELAY_SET_FIELDS:
            _check_optional_text(name, getattr(self, name))

    # ------------------------------------------------------------ building

    @classmethod
    def from_sender(
        cls,
        *,
        to: tuple[str, ...] | list[str],
        body: str,
        thread_id: str | None = None,
        request_id: str | None = None,
        sent_at: datetime | None = None,
        kind: Kind | str = Kind.CHAT,
        commit_id: str | None = None,
        expiry: datetime | None = None,
        business_address: str | None = None,
    ) -> Envelope:
        """Build the envelope a sender is allowed to build: relay-set fields stay empty.

        ``request_id`` defaults to a fresh ID, ``thread_id`` to that ID (a first
        message starts its own thread) and ``sent_at`` to the clock's now.
        """
        request_id = ids.new_request_id() if request_id is None else request_id
        return cls(
            request_id=request_id,
            thread_id=request_id if thread_id is None else thread_id,
            to=_check_recipients(to),
            body=body,
            sent_at=clock.utc_now() if sent_at is None else sent_at,
            kind=_check_kind(kind),
            commit_id=commit_id,
            expiry=expiry,
            business_address=business_address,
        )

    def stamped_by_relay(self, owner: str, sent_by: str, permission_ref: str) -> Envelope:
        """Return a copy with the relay-set identity fields filled. The relay's door only."""
        if self.is_stamped:
            raise AlreadyStampedError("envelope is already stamped by the relay")
        for name, value in (
            ("owner", owner),
            ("sent_by", sent_by),
            ("permission_ref", permission_ref),
        ):
            _check_text(name, value)
        return replace(
            self,
            owner=owner,
            sent_by=sent_by,
            permission_ref=permission_ref,
            _stamp=_RELAY_STAMP,
        )

    @property
    def is_stamped(self) -> bool:
        """True once the relay has set ``owner``, ``sent_by`` and ``permission_ref``."""
        return any(getattr(self, name) is not None for name in RELAY_SET_FIELDS)

    # ------------------------------------------------------------ JSON

    @staticmethod
    def json_schema() -> dict[str, Any]:
        """The JSON Schema (draft 2020-12) of the wire format, as a fresh copy."""
        return copy.deepcopy(ENVELOPE_SCHEMA)

    def to_dict(self) -> dict[str, Any]:
        """The wire form as a dict. Relay-set fields appear only once stamped."""
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "thread_id": self.thread_id,
            "to": list(self.to),
            "body": self.body,
            "sent_at": clock.to_iso(self.sent_at),
            "kind": self.kind.value,
            "commit_id": self.commit_id,
            "expiry": None if self.expiry is None else clock.to_iso(self.expiry),
            "business_address": self.business_address,
            "format_version": self.format_version,
        }
        if self.is_stamped:
            for name in RELAY_SET_FIELDS:
                data[name] = getattr(self, name)
        return data

    def to_json(self) -> str:
        """The wire form: compact JSON with sorted keys, so that signing is stable."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, trusted: bool = False) -> Envelope:
        """Build from the wire form. See :meth:`from_json`."""
        if not isinstance(data, dict):
            raise MalformedEnvelopeError("envelope must be a JSON object")
        if not trusted:
            present = [name for name in RELAY_SET_FIELDS if name in data]
            if present:
                raise RelaySetFieldError("a sender may not set relay fields: " + ", ".join(present))
        known = set(ENVELOPE_SCHEMA["properties"])
        if set(data) - known:
            raise MalformedEnvelopeError("envelope carries a field outside the schema")
        missing = [name for name in ENVELOPE_SCHEMA["required"] if name not in data]
        if missing:
            raise MalformedEnvelopeError("envelope is missing: " + ", ".join(missing))
        if trusted:
            stamped = [name for name in RELAY_SET_FIELDS if data.get(name) is not None]
            if stamped and len(stamped) != len(RELAY_SET_FIELDS):
                raise MalformedEnvelopeError(
                    "a stamped envelope carries all of owner, sent_by and permission_ref"
                )
        to = data["to"]
        if not isinstance(to, list):
            raise MalformedEnvelopeError("to must be a list of recipient IDs")
        return cls(
            request_id=data["request_id"],
            thread_id=data["thread_id"],
            to=tuple(to),
            body=data["body"],
            sent_at=_parse_moment("sent_at", data["sent_at"]),
            kind=data["kind"],
            commit_id=data["commit_id"],
            expiry=_parse_optional_moment("expiry", data["expiry"]),
            business_address=data["business_address"],
            format_version=data["format_version"],
            owner=data.get("owner"),
            sent_by=data.get("sent_by"),
            permission_ref=data.get("permission_ref"),
            _stamp=_RELAY_STAMP if trusted else None,
        )

    @classmethod
    def from_json(cls, text: str | bytes, *, trusted: bool = False) -> Envelope:
        """Parse the wire form.

        With the default ``trusted=False`` the document is from a sender: any
        relay-set field in it raises :class:`RelaySetFieldError`. The relay
        passes ``trusted=True`` only for documents it wrote itself, such as
        its own queue.
        """
        try:
            data = json.loads(text)
        except (ValueError, TypeError) as error:
            raise MalformedEnvelopeError("envelope is not valid JSON") from error
        return cls.from_dict(data, trusted=trusted)


# ---------------------------------------------------------------- checks


def _check_request_id(value: object) -> None:
    if not isinstance(value, str):
        raise MalformedEnvelopeError("request_id must be a string")
    # The canonical uppercase spelling only, so one ID has one string form.
    if not _REQUEST_ID.fullmatch(value):
        raise MalformedEnvelopeError("request_id is not a request ID in canonical form")
    try:
        ids.parse(value)
    except ids.InvalidRequestIdError as error:
        raise MalformedEnvelopeError("request_id is not a request ID") from error


def _check_text(name: str, value: object) -> None:
    if not isinstance(value, str) or not value:
        raise MalformedEnvelopeError(f"{name} must be a non-empty string")


def _check_optional_text(name: str, value: object) -> None:
    if value is not None:
        _check_text(name, value)


def _check_recipients(value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, list | tuple):
        raise MalformedEnvelopeError("to must be a list of recipient IDs")
    recipients = tuple(value)
    if not recipients:
        raise MalformedEnvelopeError("to must name at least one recipient")
    for item in recipients:
        _check_text("to", item)
    return recipients


def _check_moment(name: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise MalformedEnvelopeError(f"{name} must be an aware datetime")
    return value.astimezone(UTC).replace(microsecond=0)


def _check_kind(value: object) -> Kind:
    if isinstance(value, Kind):
        return value
    if isinstance(value, str):
        try:
            return Kind(value)
        except ValueError:
            pass
    raise MalformedEnvelopeError("kind must be one of chat, quote, approval, receipt")


def _parse_moment(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise MalformedEnvelopeError(f"{name} must be an ISO 8601 UTC string")
    try:
        return clock.from_iso(value)
    except ValueError as error:
        raise MalformedEnvelopeError(f"{name} must be an ISO 8601 UTC string") from error


def _parse_optional_moment(name: str, value: object) -> datetime | None:
    return None if value is None else _parse_moment(name, value)


FIELD_NAMES: tuple[str, ...] = tuple(f.name for f in fields(Envelope))
