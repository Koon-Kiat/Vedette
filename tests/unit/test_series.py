"""Bar sizes and span limits for the interactive charts."""

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.storage.series import MAX_POINTS, MAX_SPAN, SeriesQueries, choose_step

NOW = datetime(2026, 3, 15, 0, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    ("span", "step"),
    [
        (timedelta(seconds=0), 60),
        (timedelta(minutes=30), 60),
        (timedelta(hours=1), 60),
        (timedelta(hours=6), 300),
        (timedelta(hours=24), 900),
        (timedelta(days=7), 3600),
        (timedelta(days=30), 10800),
        (timedelta(days=31), 21600),
    ],
)
def test_the_bar_size_follows_the_span(span: timedelta, step: int) -> None:
    assert choose_step(span) == step
    assert span.total_seconds() / step <= MAX_POINTS


def test_a_span_ending_in_the_future_ends_now() -> None:
    start, end = SeriesQueries.clamp(NOW - timedelta(hours=1), NOW + timedelta(days=1), NOW)

    assert (start, end) == (NOW - timedelta(hours=1), NOW)


def test_a_span_is_at_most_the_limit() -> None:
    start, end = SeriesQueries.clamp(NOW - timedelta(days=400), NOW, NOW)

    assert end - start == MAX_SPAN


def test_an_empty_or_backwards_span_becomes_one_minute() -> None:
    start, end = SeriesQueries.clamp(NOW, NOW - timedelta(hours=2), NOW)

    assert end - start == timedelta(minutes=1)
