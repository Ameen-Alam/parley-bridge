"""T-0001 criteria 1, 2, 6 and 7: the envelope, its wire form, and who may set what."""

import dataclasses
import json
import logging
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from parley_common import clock, envelope, ids
from parley_common.envelope import Envelope, Kind

BODY = "hostile body text that must never leak"
MOMENT = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
PACKAGE = Path(envelope.__file__).parent


def sender_envelope(**overrides: object) -> Envelope:
    kwargs: dict[str, object] = {"to": ["recipient-a"], "body": BODY, "sent_at": MOMENT}
    kwargs.update(overrides)
    return Envelope.from_sender(**kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------- criterion 1


def test_envelope_is_a_frozen_dataclass_with_the_three_field_groups() -> None:
    assert dataclasses.is_dataclass(Envelope)
    names = tuple(f.name for f in dataclasses.fields(Envelope))
    assert names == envelope.SENDER_FIELDS + envelope.RESERVED_FIELDS + envelope.RELAY_SET_FIELDS
    env = sender_envelope()
    with pytest.raises(dataclasses.FrozenInstanceError):
        env.body = "changed"  # type: ignore[misc]


def test_from_sender_fills_defaults_from_the_clock_and_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(clock, "utc_now", lambda: MOMENT.replace(microsecond=250_000))
    env = Envelope.from_sender(to=["recipient-a", "recipient-b"], body=BODY)
    ids.parse(env.request_id)
    assert env.thread_id == env.request_id, "a first message starts its own thread"
    assert env.to == ("recipient-a", "recipient-b")
    assert env.sent_at == MOMENT, "second precision, the clock's wire format"
    assert env.kind is Kind.CHAT
    assert env.commit_id is None
    assert env.expiry is None
    assert env.business_address is None
    assert env.format_version == 1
    assert (env.owner, env.sent_by, env.permission_ref) == (None, None, None)
    assert not env.is_stamped


def test_kind_is_the_four_reserved_values_and_chat_is_default() -> None:
    assert [k.value for k in Kind] == ["chat", "quote", "approval", "receipt"]
    assert sender_envelope(kind="quote").kind is Kind.QUOTE
    with pytest.raises(envelope.MalformedEnvelopeError):
        sender_envelope(kind="invoice")


def test_json_round_trip_keeps_every_field() -> None:
    env = sender_envelope(
        thread_id="thread-1",
        kind=Kind.QUOTE,
        commit_id="commit-1",
        expiry=MOMENT + timedelta(days=1),
        business_address="shop.example",
    )
    text = env.to_json()
    assert Envelope.from_json(text) == env
    assert Envelope.from_json(text.encode("utf-8")) == env


def test_to_json_is_compact_sorted_and_matches_the_schema_shape() -> None:
    env = sender_envelope()
    data = json.loads(env.to_json())
    assert list(data) == sorted(data)
    assert set(data) == set(envelope.SENDER_FIELDS + envelope.RESERVED_FIELDS)
    assert data["format_version"] == 1
    assert data["kind"] == "chat"
    assert data["to"] == ["recipient-a"]
    assert "\n" not in env.to_json()


def test_json_schema_is_a_valid_document_that_names_every_field() -> None:
    schema = Envelope.json_schema()
    json.dumps(schema)
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == set(envelope.FIELD_NAMES)
    assert set(schema["required"]) == set(envelope.SENDER_FIELDS + envelope.RESERVED_FIELDS)
    assert schema["properties"]["format_version"]["const"] == 1
    assert schema["properties"]["kind"]["enum"] == ["chat", "quote", "approval", "receipt"]
    schema["properties"].clear()
    assert Envelope.json_schema()["properties"], "json_schema returns a copy"


def test_from_dict_requires_exactly_what_the_schema_requires() -> None:
    """An outside validator and the relay must agree on what a valid envelope is."""
    data = sender_envelope().to_dict()
    assert set(data) == set(Envelope.json_schema()["required"])
    for name in data:
        with pytest.raises(envelope.MalformedEnvelopeError) as info:
            Envelope.from_dict({k: v for k, v in data.items() if k != name})
        assert name in str(info.value)


def test_request_id_must_be_canonical_uppercase() -> None:
    env = sender_envelope()
    lower = env.request_id.lower()
    ids.parse(lower)  # ids.parse tolerates it; the envelope does not
    with pytest.raises(envelope.MalformedEnvelopeError):
        sender_envelope(request_id=lower)
    assert sender_envelope(request_id=env.request_id).request_id == env.request_id


def test_trusted_document_with_a_partial_stamp_is_malformed() -> None:
    data = sender_envelope().to_dict()
    data["owner"] = "owner-1"
    with pytest.raises(envelope.MalformedEnvelopeError):
        Envelope.from_json(json.dumps(data), trusted=True)
    data.update(sent_by="device-1", permission_ref="perm-1")
    assert Envelope.from_json(json.dumps(data), trusted=True).is_stamped
    for name in envelope.RELAY_SET_FIELDS:
        data[name] = None
    assert not Envelope.from_json(json.dumps(data), trusted=True).is_stamped


def test_wire_values_match_the_schema_patterns() -> None:
    schema = Envelope.json_schema()["properties"]
    data = sender_envelope(expiry=MOMENT).to_dict()
    assert re.fullmatch(schema["request_id"]["pattern"], data["request_id"])
    assert re.fullmatch(schema["sent_at"]["pattern"], data["sent_at"])
    assert re.fullmatch(schema["expiry"]["anyOf"][0]["pattern"], data["expiry"])


@pytest.mark.parametrize(
    "overrides",
    [
        {"to": []},
        {"to": [""]},
        {"to": "recipient-a"},
        {"to": [5]},
        {"body": 5},
        {"thread_id": ""},
        {"request_id": "not-an-id"},
        {"commit_id": ""},
        {"business_address": 7},
    ],
)
def test_bad_sender_fields_are_refused(overrides: dict[str, object]) -> None:
    with pytest.raises(envelope.MalformedEnvelopeError):
        sender_envelope(**overrides)


def test_format_version_must_be_the_integer_one() -> None:
    env = sender_envelope()
    for bad in (2, 0, "1", 1.0, True):
        with pytest.raises(envelope.UnsupportedFormatVersionError):
            Envelope(**{**_as_kwargs(env), "format_version": bad})
    with pytest.raises(envelope.UnsupportedFormatVersionError):
        Envelope.from_json(json.dumps({**env.to_dict(), "format_version": 2}))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("format_version"),
        lambda d: d.pop("to"),
        lambda d: d.pop("body"),
        lambda d: d.pop("kind"),
        lambda d: d.pop("commit_id"),
        lambda d: d.pop("expiry"),
        lambda d: d.pop("business_address"),
        lambda d: d.update(request_id=d["request_id"].lower()),
        lambda d: d.update(request_id="0I" + d["request_id"][2:]),
        lambda d: d.update(extra="x"),
        lambda d: d.update(sent_at="2026-10-11 10:00:00"),
        lambda d: d.update(sent_at="2026-10-11T10:00:00+03:00"),
        lambda d: d.update(expiry="soon"),
        lambda d: d.update(to="recipient-a"),
        lambda d: d.update(kind="invoice"),
    ],
)
def test_bad_wire_documents_are_refused(mutate: object) -> None:
    data = sender_envelope().to_dict()
    mutate(data)  # type: ignore[operator]
    with pytest.raises(envelope.EnvelopeError):
        Envelope.from_json(json.dumps(data))


@pytest.mark.parametrize("text", ["", "not json", "[]", "null", '"x"', "{"])
def test_non_object_documents_are_malformed(text: str) -> None:
    with pytest.raises(envelope.MalformedEnvelopeError):
        Envelope.from_json(text)


# ---------------------------------------------------------------- criterion 2


def test_stamped_by_relay_is_the_only_way_to_fill_relay_fields() -> None:
    env = sender_envelope()
    stamped = env.stamped_by_relay(owner="owner-1", sent_by="device-1", permission_ref="perm-1")
    assert stamped.is_stamped
    assert (stamped.owner, stamped.sent_by, stamped.permission_ref) == (
        "owner-1",
        "device-1",
        "perm-1",
    )
    assert not env.is_stamped, "the original is untouched"
    assert dataclasses.replace(stamped, owner=None, sent_by=None, permission_ref=None) == env
    with pytest.raises(envelope.RelaySetFieldError):
        Envelope(**{**_as_kwargs(env), "owner": "owner-1"})
    with pytest.raises(envelope.RelaySetFieldError):
        dataclasses.replace(env, sent_by="device-1")


def test_stamping_twice_is_refused_and_stamps_must_be_complete() -> None:
    stamped = sender_envelope().stamped_by_relay("owner-1", "device-1", "perm-1")
    with pytest.raises(envelope.AlreadyStampedError):
        stamped.stamped_by_relay("owner-2", "device-2", "perm-2")
    with pytest.raises(envelope.MalformedEnvelopeError):
        sender_envelope().stamped_by_relay("owner-1", "", "perm-1")


@pytest.mark.parametrize("name", envelope.RELAY_SET_FIELDS)
def test_sender_document_carrying_a_relay_field_is_rejected(name: str) -> None:
    data = sender_envelope().to_dict()
    data[name] = "forged"
    with pytest.raises(envelope.RelaySetFieldError) as info:
        Envelope.from_json(json.dumps(data))
    assert name in str(info.value)
    assert "forged" not in str(info.value)


def test_sender_document_with_a_null_relay_field_is_still_rejected() -> None:
    data = sender_envelope().to_dict()
    data["owner"] = None
    with pytest.raises(envelope.RelaySetFieldError):
        Envelope.from_json(json.dumps(data))


def test_relay_reads_its_own_stamped_documents_with_trusted() -> None:
    stamped = sender_envelope().stamped_by_relay("owner-1", "device-1", "perm-1")
    text = stamped.to_json()
    data = json.loads(text)
    assert {data["owner"], data["sent_by"], data["permission_ref"]} == {
        "owner-1",
        "device-1",
        "perm-1",
    }
    with pytest.raises(envelope.RelaySetFieldError):
        Envelope.from_json(text)
    assert Envelope.from_json(text, trusted=True) == stamped


# ---------------------------------------------------------------- criterion 6


def test_repr_and_str_never_contain_the_body() -> None:
    env = sender_envelope()
    stamped = env.stamped_by_relay("owner-1", "device-1", "perm-1")
    for shown in (repr(env), str(env), repr(stamped), str(stamped)):
        assert BODY not in shown
        assert "body" not in shown
        assert env.request_id in shown


def test_errors_never_contain_the_body() -> None:
    data = sender_envelope().to_dict()
    data["owner"] = "forged"
    with pytest.raises(envelope.RelaySetFieldError) as relay_error:
        Envelope.from_json(json.dumps(data))
    assert BODY not in str(relay_error.value)
    assert BODY not in repr(relay_error.value)
    data = sender_envelope().to_dict()
    data["to"] = []
    with pytest.raises(envelope.MalformedEnvelopeError) as malformed:
        Envelope.from_json(json.dumps(data))
    assert BODY not in str(malformed.value)
    with pytest.raises(envelope.MalformedEnvelopeError) as unknown:
        Envelope.from_json(json.dumps({**sender_envelope().to_dict(), BODY: 1}))
    assert BODY not in str(unknown.value)


def test_nothing_in_the_package_logs_or_prints(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    for source in PACKAGE.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        for forbidden in ("logging", "print(", "sys.stdout", "sys.stderr", "warnings"):
            assert forbidden not in text, (source.name, forbidden)
    with caplog.at_level(logging.DEBUG):
        env = sender_envelope()
        Envelope.from_json(env.to_json())
        env.stamped_by_relay("owner-1", "device-1", "perm-1")
        with pytest.raises(envelope.RelaySetFieldError):
            Envelope.from_json(json.dumps({**env.to_dict(), "owner": "x"}))
    assert caplog.records == []
    out, err = capsys.readouterr()
    assert out == ""
    assert err == ""


# ---------------------------------------------------------------- criterion 7


def test_times_are_utc_aware_and_iso_8601_z_on_the_wire() -> None:
    riyadh = timezone(timedelta(hours=3))
    env = sender_envelope(
        sent_at=datetime(2026, 10, 11, 13, 0, 0, tzinfo=riyadh),
        expiry=datetime(2026, 10, 12, 13, 0, 0, 999_000, tzinfo=riyadh),
    )
    assert env.sent_at.tzinfo is UTC
    assert env.expiry is not None
    assert env.expiry.tzinfo is UTC
    data = env.to_dict()
    assert data["sent_at"] == "2026-10-11T10:00:00Z"
    assert data["expiry"] == "2026-10-12T10:00:00Z"
    assert data["sent_at"] == clock.to_iso(env.sent_at)


def test_naive_times_are_refused() -> None:
    with pytest.raises(envelope.MalformedEnvelopeError):
        sender_envelope(sent_at=datetime(2026, 10, 11, 10, 0, 0))  # noqa: DTZ001
    with pytest.raises(envelope.MalformedEnvelopeError):
        sender_envelope(expiry=datetime(2026, 10, 11, 10, 0, 0))  # noqa: DTZ001


# ---------------------------------------------------------------- helpers


def _as_kwargs(env: Envelope) -> dict[str, Any]:
    return {f.name: getattr(env, f.name) for f in dataclasses.fields(env)}
