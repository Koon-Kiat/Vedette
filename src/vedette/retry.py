"""Retry timing helpers: backoff with jitter, Retry-After parsing, and the worker loop."""

import math
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import structlog

MAX_RETRY_AFTER_SECONDS = 3600.0
UNEXPECTED_RETRY_SECONDS = 30.0

_log = structlog.get_logger(__name__)


def backoff_delay(
    attempt: int,
    *,
    base: float = 1.0,
    cap: float = 60.0,
    rng: Callable[[], float] = random.random,
) -> float:
    """Seconds to wait before retry number ``attempt`` (0 for the first retry).

    The step doubles each attempt up to ``cap``. Half of it is fixed and half
    is random ("equal jitter"), so retries spread out but never fire instantly.
    """
    step = min(cap, base * 2.0 ** min(attempt, 32))
    return step / 2 + rng() * step / 2


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Convert a ``Retry-After`` header into seconds to wait.

    Accepts both forms HTTP allows (delay in seconds, or an HTTP date). Returns
    ``None`` when the header is absent or unusable. The result is capped at one
    hour so a faulty server cannot stall the collector indefinitely.
    """
    if value is None or not value.strip():
        return None
    text = value.strip()
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except TypeError, ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - (now or datetime.now(UTC))).total_seconds()
        return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return min(seconds, MAX_RETRY_AFTER_SECONDS)


async def run_forever(
    attempt: Callable[[], Awaitable[float]],
    *,
    sleep: Callable[[float], Awaitable[None]],
    failure: str,
    retry_in: float = UNEXPECTED_RETRY_SECONDS,
    on_failure: Callable[[], None] | None = None,
    log: Any = None,
) -> None:
    """Call ``attempt`` again and again, sleeping the seconds it returns in between.

    Workers run unattended, so an unexpected error does not end one: it is logged
    as ``failure`` with its traceback, ``on_failure`` is called, and the next
    attempt comes ``retry_in`` seconds later. Cancel the task to stop.
    """
    logger = _log if log is None else log
    while True:
        try:
            delay = await attempt()
        except Exception as exc:
            logger.exception(failure, error=type(exc).__name__, detail=str(exc)[:200])
            if on_failure is not None:
                on_failure()
            delay = retry_in
        await sleep(delay)
