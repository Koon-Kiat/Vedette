"""Geometry for the dashboard's SVG drawings: the hourly chart and span bars.

Everything is computed here and rendered as plain SVG elements by a template,
so the pages need no charting script and no inline styles.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from sentinel.storage.dashboard import HourBar

WIDTH = 720
HEIGHT = 220
LEFT = 48
BOTTOM = 24
TOP = 30
GAP = 2
MARKER_HEIGHT = 16
SPAN_WIDTH = 120
SPAN_HEIGHT = 8


@dataclass(frozen=True, slots=True)
class Bar:
    """One hour's stacked bar: allowed below, blocked on top."""

    x: float
    width: float
    allowed_y: float
    allowed_height: float
    blocked_y: float
    blocked_height: float
    label: str | None
    title: str


@dataclass(frozen=True, slots=True)
class Marker:
    """A finding's number placed over the hour it was last seen."""

    x: float
    y: float
    width: float
    label: str
    title: str


@dataclass(frozen=True, slots=True)
class Chart:
    """Everything the template needs to draw the chart."""

    width: int
    height: int
    left: int
    plot_bottom: float
    top: int
    y_max: int
    bars: list[Bar]
    usual_y: float | None
    usual: float | None
    markers: list[Marker]


@dataclass(frozen=True, slots=True)
class Span:
    """When a finding was seen, drawn on its last day's 24-hour axis."""

    width: int
    height: int
    x: float
    length: float
    from_earlier: bool
    title: str


def _nice_max(value: float) -> int:
    """Round up to 1, 2 or 5 times a power of ten, so the axis label reads well."""
    if value <= 0:
        return 1
    magnitude = 1
    while magnitude * 10 <= value:
        magnitude *= 10
    for step in (1, 2, 5, 10):
        if step * magnitude >= value:
            return step * magnitude
    return 10 * magnitude  # pragma: no cover - the loop always returns


def hourly_chart(
    hours: Sequence[HourBar],
    tz: ZoneInfo,
    *,
    usual: float | None = None,
    markers: Sequence[tuple[int, datetime]] = (),
) -> Chart:
    """Lay out stacked bars for each hour, labelled every three hours in local time.

    ``usual`` is the usual number of queries per hour (the 7-day average), drawn
    as a band behind the bars. ``markers`` are finding numbers and the time each
    was last seen; those inside the chart's hours are placed over their hour.
    """
    plot_bottom = HEIGHT - BOTTOM
    plot_height = plot_bottom - TOP
    tallest = max((h.allowed + h.blocked for h in hours), default=0)
    y_max = _nice_max(max(tallest, usual or 0))
    slot = (WIDTH - LEFT) / max(len(hours), 1)
    bars: list[Bar] = []
    tops: list[float] = []
    for index, hour in enumerate(hours):
        local: datetime = hour.start.astimezone(tz)
        allowed_height = plot_height * hour.allowed / y_max
        blocked_height = plot_height * hour.blocked / y_max
        allowed_y = plot_bottom - allowed_height
        tops.append(allowed_y - blocked_height)
        bars.append(
            Bar(
                x=round(LEFT + index * slot + GAP / 2, 1),
                width=round(slot - GAP, 1),
                allowed_y=round(allowed_y, 1),
                allowed_height=round(allowed_height, 1),
                blocked_y=round(allowed_y - blocked_height, 1),
                blocked_height=round(blocked_height, 1),
                label=f"{local:%H}:00" if local.hour % 3 == 0 else None,
                title=(
                    f"{local:%Y-%m-%d %H}:00: {hour.allowed + hour.blocked} queries, "
                    f"{hour.blocked} blocked"
                ),
            )
        )
    placed: list[Marker] = []
    taken: list[tuple[int, float, float]] = []  # (level, left, right) of placed markers
    for number, seen in sorted(markers, key=lambda item: item[1]):
        found = next(
            (
                i
                for i, hour in enumerate(hours)
                if hour.start <= seen < hour.start + timedelta(hours=1)
            ),
            None,
        )
        if found is None:
            continue
        label = f"{number:04d}"  # the notice number, as the findings table prints it
        width = 10.0 + 7.0 * len(label)
        centre = LEFT + found * slot + slot / 2
        x = min(max(centre - width / 2, LEFT), WIDTH - width)
        level = 0
        while any(lv == level and x < right and left < x + width for lv, left, right in taken):
            level += 1
        taken.append((level, x, x + width))
        first = max(int((x - LEFT) // slot), 0)
        last = min(int((x + width - LEFT) // slot), len(tops) - 1)
        top = min(tops[first : last + 1])
        y = max(top - 4 - MARKER_HEIGHT * (level + 1), 2.0)
        placed.append(
            Marker(
                x=round(x, 1),
                y=round(y, 1),
                width=width,
                label=label,
                title=f"Finding {number}, last seen {seen.astimezone(tz):%H:%M}",
            )
        )
    usual_y = None if usual is None else round(plot_bottom - plot_height * usual / y_max, 1)
    return Chart(
        width=WIDTH,
        height=HEIGHT,
        left=LEFT,
        plot_bottom=plot_bottom,
        top=TOP,
        y_max=y_max,
        bars=bars,
        usual_y=usual_y,
        usual=usual,
        markers=placed,
    )


def span(first: datetime, last: datetime, tz: ZoneInfo) -> Span:
    """Place first-to-last seen on the 24 hours of the local day it was last seen."""
    last_local = last.astimezone(tz)
    day_start = datetime.combine(last_local.date(), time(0), tzinfo=tz)
    start = max(first.astimezone(tz), day_start)
    per_hour = SPAN_WIDTH / 24
    x = (start - day_start).total_seconds() / 3600 * per_hour
    end = (last_local - day_start).total_seconds() / 3600 * per_hour
    length = max(end - x, 2.0)
    x = min(x, SPAN_WIDTH - length)
    first_local = first.astimezone(tz)
    return Span(
        width=SPAN_WIDTH,
        height=SPAN_HEIGHT,
        x=round(x, 1),
        length=round(length, 1),
        from_earlier=first_local < day_start,
        title=f"Seen {first_local:%Y-%m-%d %H:%M} to {last_local:%Y-%m-%d %H:%M}",
    )
