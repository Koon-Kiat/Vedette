import asyncio
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest
from structlog.testing import capture_logs

from vedette.retry import UNEXPECTED_RETRY_SECONDS, backoff_delay, parse_retry_after, run_forever


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


class Sleeps:
    """Records each requested sleep and stops the loop after ``limit`` of them."""

    def __init__(self, limit: int) -> None:
        self.delays: list[float] = []
        self.limit = limit

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)
        if len(self.delays) == self.limit:
            raise asyncio.CancelledError


async def test_run_forever_sleeps_what_each_attempt_returns() -> None:
    delays = iter([0.0, 5.0, 2.5])

    async def attempt() -> float:
        return next(delays)

    sleeps = Sleeps(limit=3)
    with pytest.raises(asyncio.CancelledError):
        await run_forever(attempt, sleep=sleeps, failure="worker_unexpected_error")
    assert sleeps.delays == [0.0, 5.0, 2.5]


async def test_run_forever_logs_an_unexpected_error_and_tries_again_later() -> None:
    calls = 0
    failures: list[str] = []

    async def attempt() -> float:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("database is locked")
        return 7.0

    sleeps = Sleeps(limit=2)
    with capture_logs() as logs, pytest.raises(asyncio.CancelledError):
        await run_forever(
            attempt,
            sleep=sleeps,
            failure="worker_unexpected_error",
            on_failure=lambda: failures.append("told"),
        )
    assert sleeps.delays == [UNEXPECTED_RETRY_SECONDS, 7.0]
    assert failures == ["told"]
    (entry,) = [e for e in logs if e["event"] == "worker_unexpected_error"]
    assert entry["error"] == "RuntimeError" and entry["detail"] == "database is locked"
    assert entry["log_level"] == "error"


async def test_run_forever_waits_retry_in_after_an_error_when_given() -> None:
    async def attempt() -> float:
        raise ValueError("bad row")

    sleeps = Sleeps(limit=2)
    with capture_logs(), pytest.raises(asyncio.CancelledError):
        await run_forever(attempt, sleep=sleeps, failure="digest_unexpected_error", retry_in=60.0)
    assert sleeps.delays == [60.0, 60.0]


async def test_run_forever_lets_cancellation_through() -> None:
    async def attempt() -> float:
        raise asyncio.CancelledError

    sleeps = Sleeps(limit=99)
    with pytest.raises(asyncio.CancelledError):
        await run_forever(attempt, sleep=sleeps, failure="worker_unexpected_error")
    assert sleeps.delays == []
