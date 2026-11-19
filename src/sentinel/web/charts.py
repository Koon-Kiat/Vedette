"""Geometry for the queries-per-hour chart, drawn as SVG by a template.

The chart is computed here and rendered as plain SVG elements, so the page
needs no charting script at all.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from sentinel.storage.dashboard import HourBar

WIDTH = 720
HEIGHT = 200
LEFT = 48
BOTTOM = 24
TOP = 12
GAP = 2


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
class Chart:
    """Everything the template needs to draw the chart."""

    width: int
    height: int
    left: int
    plot_bottom: float
    top: int
    y_max: int
    bars: list[Bar]


def _nice_max(value: int) -> int:
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


def hourly_chart(hours: Sequence[HourBar], tz: ZoneInfo) -> Chart:
    """Lay out stacked bars for each hour, labelled every three hours in local time."""
    plot_bottom = HEIGHT - BOTTOM
    plot_height = plot_bottom - TOP
    y_max = _nice_max(max((h.allowed + h.blocked for h in hours), default=0))
    slot = (WIDTH - LEFT) / max(len(hours), 1)
    bars: list[Bar] = []
    for index, hour in enumerate(hours):
        local: datetime = hour.start.astimezone(tz)
        allowed_height = plot_height * hour.allowed / y_max
        blocked_height = plot_height * hour.blocked / y_max
        allowed_y = plot_bottom - allowed_height
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
    return Chart(
        width=WIDTH,
        height=HEIGHT,
        left=LEFT,
        plot_bottom=plot_bottom,
        top=TOP,
        y_max=y_max,
        bars=bars,
    )
