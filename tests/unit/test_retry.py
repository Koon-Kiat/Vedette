from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest

from sentinel.retry import backoff_delay, parse_retry_after


@pytest.mark.parametrize("attempt", range(8))
def test_backoff_stays_between_half_and_the_full_exponential_step(attempt: int) -> None:
    step = min(60.0, 1.0 * 2**attempt)

    low = backoff_delay(attempt, base=1.0, cap=60.0, rng=lambda: 0.0)
    high = backoff_delay(attempt, base=1.0, cap=60.0, rng=lambda: 1.0)

    assert low == step / 2
    assert high == step


def test_backoff_is_capped_for_very_large_attempt_numbers() -> None:
    assert backoff_delay(10_000, base=1.0, cap=60.0, rng=lambda: 1.0) == 60.0


def test_backoff_uses_the_random_source_for_jitter() -> None:
    a = backoff_delay(3, base=1.0, cap=60.0, rng=lambda: 0.25)
    b = backoff_delay(3, base=1.0, cap=60.0, rng=lambda: 0.75)

    assert a == 5.0
    assert b == 7.0


def test_retry_after_in_seconds_is_parsed() -> None:
    assert parse_retry_after("17") == 17.0


def test_retry_after_as_http_date_is_converted_to_seconds_from_now() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    header = format_datetime(now + timedelta(seconds=90), usegmt=True)

    assert parse_retry_after(header, now=now) == 90.0


def test_retry_after_in_the_past_is_zero() -> None:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    header = format_datetime(now - timedelta(seconds=90), usegmt=True)

    assert parse_retry_after(header, now=now) == 0.0


@pytest.mark.parametrize("value", [None, "", "soon", "-5", "nan", "inf"])
def test_missing_or_nonsense_retry_after_is_ignored(value: str | None) -> None:
    assert parse_retry_after(value) is None


def test_retry_after_is_capped_so_a_bad_server_cannot_stall_us_forever() -> None:
    assert parse_retry_after("999999") == 3600.0
