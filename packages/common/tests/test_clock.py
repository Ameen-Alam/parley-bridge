from datetime import UTC, datetime, timedelta, timezone

import pytest

from parley_common import clock


def test_utc_now_is_aware_utc() -> None:
    moment = clock.utc_now()
    assert moment.tzinfo is UTC


def test_iso_round_trip_is_utc_with_z() -> None:
    moment = datetime(2026, 10, 11, 10, 0, 0, tzinfo=UTC)
    text = clock.to_iso(moment)
    assert text == "2026-10-11T10:00:00Z"
    assert clock.from_iso(text) == moment


def test_other_zones_are_converted_to_utc() -> None:
    riyadh = timezone(timedelta(hours=3))
    moment = datetime(2026, 10, 11, 13, 0, 0, tzinfo=riyadh)
    assert clock.to_iso(moment) == "2026-10-11T10:00:00Z"


def test_naive_datetime_is_refused() -> None:
    with pytest.raises(ValueError, match="naive"):
        clock.to_iso(datetime(2026, 10, 11, 10, 0, 0))  # noqa: DTZ001


def test_years_below_1000_are_zero_padded_so_text_order_is_time_order() -> None:
    early = datetime(999, 1, 1, tzinfo=UTC)
    text = clock.to_iso(early)
    assert text == "0999-01-01T00:00:00Z"
    assert text < clock.to_iso(datetime(2026, 1, 1, tzinfo=UTC))
    assert clock.from_iso(text) == early


@pytest.mark.parametrize(
    "text",
    ["999-01-01T00:00:00Z", "2026-1-01T00:00:00Z", "2026-01-01T00:00:00", " 2026-01-01T00:00:00Z"],
)
def test_from_iso_rejects_anything_but_the_exact_shape(text: str) -> None:
    with pytest.raises(ValueError, match="exactly"):
        clock.from_iso(text)
