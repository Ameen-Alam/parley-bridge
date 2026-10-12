"""T-0001 criterion 5: request IDs are 128-bit, URL-safe, time-sortable and unique."""

from datetime import UTC, datetime

import pytest

from parley_common import clock, ids


def test_id_is_26_crockford_base32_characters() -> None:
    request_id = ids.new_request_id()
    assert len(request_id) == 26
    assert set(request_id) <= set(ids.ALPHABET)
    assert request_id[0] <= "7", "128 bits leave the top bit of the first character clear"


def test_ten_thousand_ids_are_unique() -> None:
    made = {ids.new_request_id() for _ in range(10_000)}
    assert len(made) == 10_000


def test_ids_sort_by_creation_order() -> None:
    made = [ids.new_request_id() for _ in range(1_000)]
    assert made == sorted(made)


def freeze(monkeypatch: pytest.MonkeyPatch, frozen: datetime) -> None:
    """Freeze the clock and start a fresh generator, so earlier tests leave no state."""
    monkeypatch.setattr(clock, "utc_now", lambda: frozen)
    monkeypatch.setattr(ids, "_generator", ids._Generator())


def test_same_millisecond_ids_sort_by_creation_order(monkeypatch: pytest.MonkeyPatch) -> None:
    frozen = datetime(2026, 10, 11, 10, 0, 0, 123_000, tzinfo=UTC)
    freeze(monkeypatch, frozen)
    first = ids.new_request_id()
    second = ids.new_request_id()
    assert first[:10] == second[:10], "same millisecond, same time prefix"
    assert first < second
    assert ids.parse(second) == ids.parse(first)


def test_parse_returns_embedded_utc_timestamp(monkeypatch: pytest.MonkeyPatch) -> None:
    frozen = datetime(2026, 10, 11, 10, 0, 0, 123_000, tzinfo=UTC)
    freeze(monkeypatch, frozen)
    parsed = ids.parse(ids.new_request_id())
    assert parsed.tzinfo is UTC
    assert parsed == frozen


def test_parse_matches_a_known_ulid_vector() -> None:
    # 01ARZ3NDEKTSV4RRFFQ69G5FAV is the ULID README example; its time prefix
    # 01ARZ3NDEK is 1469922850259 ms, 2016-07-30T23:54:10.259Z.
    assert ids.parse("01ARZ3NDEKTSV4RRFFQ69G5FAV") == datetime(
        2016, 7, 30, 23, 54, 10, 259_000, tzinfo=UTC
    )


def test_parse_accepts_lowercase_and_confusable_letters() -> None:
    assert ids.parse("01arz3ndektsv4rrffq69g5fav") == ids.parse("01ARZ3NDEKTSV4RRFFQ69G5FAV")
    assert ids.parse("0IARZ3NDEKTSV4RRFFQ69G5FAV") == ids.parse("01ARZ3NDEKTSV4RRFFQ69G5FAV")


@pytest.mark.parametrize(
    "text",
    ["", "01ARZ3NDEKTSV4RRFFQ69G5FA", "01ARZ3NDEKTSV4RRFFQ69G5FAVX", "01ARZ3NDEKTSV4RRFFQ69G5FAU"],
)
def test_parse_refuses_bad_text_without_echoing_it(text: str) -> None:
    with pytest.raises(ids.InvalidRequestIdError) as info:
        ids.parse(text)
    assert text == "" or text not in str(info.value)


def test_parse_refuses_values_above_128_bits() -> None:
    with pytest.raises(ids.InvalidRequestIdError):
        ids.parse("8" + "Z" * 25)


def test_a_clock_step_back_keeps_ids_sortable(monkeypatch: pytest.MonkeyPatch) -> None:
    later = datetime(2026, 10, 11, 10, 0, 1, tzinfo=UTC)
    earlier = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
    freeze(monkeypatch, later)
    first = ids.new_request_id()
    monkeypatch.setattr(clock, "utc_now", lambda: earlier)
    second = ids.new_request_id()
    assert first < second
    assert ids.parse(second) == later
