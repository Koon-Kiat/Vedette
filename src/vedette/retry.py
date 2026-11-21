"""Retry timing helpers: exponential backoff with jitter, and Retry-After parsing."""

import math
import random
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

MAX_RETRY_AFTER_SECONDS = 3600.0


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
