"""Local-time scheduling: quiet hours and the daily digest time.

All results are timezone-aware UTC datetimes; durations are measured on the
UTC timeline so they stay correct across daylight-saving changes.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

_CLOCK = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")


def parse_clock(text: str) -> time:
    """Parse ``HH:MM`` (24-hour clock).

    Raises:
        ValueError: The text is not a valid time.
    """
    match = _CLOCK.fullmatch(text.strip())
    if match is None:
        raise ValueError(f"not a HH:MM time: {text!r}")
    return time(int(match[1]), int(match[2]))


def _at(day: date, clock: time, tz: ZoneInfo) -> datetime:
    return datetime.combine(day, clock, tzinfo=tz).astimezone(UTC)


@dataclass(frozen=True, slots=True)
class QuietHours:
    """A daily local-time window, possibly wrapping past midnight."""

    start: time
    end: time

    @classmethod
    def parse(cls, text: str) -> QuietHours | None:
        """Parse ``HH:MM-HH:MM``; an empty window (start equals end) gives ``None``.

        Raises:
            ValueError: The text is not two valid times joined by a hyphen.
        """
        first, sep, second = text.strip().partition("-")
        if not sep:
            raise ValueError(f"not a HH:MM-HH:MM range: {text!r}")
        start, end = parse_clock(first), parse_clock(second)
        return None if start == end else cls(start, end)

    def _windows(
        self, first: date, last: date, tz: ZoneInfo
    ) -> Iterator[tuple[datetime, datetime]]:
        """Quiet windows starting on each local day from ``first`` to ``last``."""
        day = first
        while day <= last:
            end_day = day if self.end > self.start else day + timedelta(days=1)
            yield _at(day, self.start, tz), _at(end_day, self.end, tz)
            day += timedelta(days=1)

    def contains(self, moment: datetime, tz: ZoneInfo) -> bool:
        """Whether ``moment`` falls inside quiet hours in time zone ``tz``."""
        local_day = moment.astimezone(tz).date()
        return any(
            begin <= moment < end
            for begin, end in self._windows(local_day - timedelta(days=1), local_day, tz)
        )

    def end_after(self, moment: datetime, tz: ZoneInfo) -> datetime:
        """The first end of quiet hours strictly after ``moment``."""
        local_day = moment.astimezone(tz).date()
        windows = self._windows(local_day - timedelta(days=1), local_day + timedelta(days=1), tz)
        return min(end for _, end in windows if end > moment)

    def overlap(self, start: datetime, end: datetime, tz: ZoneInfo) -> timedelta:
        """How much of ``[start, end)`` lies inside quiet hours."""
        if end <= start:
            return timedelta(0)
        total = timedelta(0)
        first = start.astimezone(tz).date() - timedelta(days=1)
        for begin, finish in self._windows(first, end.astimezone(tz).date(), tz):
            low, high = max(begin, start), min(finish, end)
            if high > low:
                total += high - low
        return total


def next_occurrence(clock: time, after: datetime, tz: ZoneInfo) -> datetime:
    """The first local ``clock`` time strictly after ``after``."""
    day = after.astimezone(tz).date()
    candidate = _at(day, clock, tz)
    return candidate if candidate > after else _at(day + timedelta(days=1), clock, tz)


def latest_occurrence(clock: time, now: datetime, tz: ZoneInfo) -> datetime:
    """The most recent local ``clock`` time at or before ``now``."""
    day = now.astimezone(tz).date()
    candidate = _at(day, clock, tz)
    return candidate if candidate <= now else _at(day - timedelta(days=1), clock, tz)
