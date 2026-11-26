"""Time series and time windows behind the dashboard's interactive charts.

The bucket size follows the span asked for, so zooming into a chart fetches
finer data, from one minute up to one day. A chart asks for as many buckets
as its width suits: 240 at most by default, up to 480 on a wide screen.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from vedette.config import ProfileConfig
from vedette.shared.models import Severity
from vedette.storage.live import LiveEvent, feed_columns, live_event
from vedette.storage.models import events, finding_analysis, findings

STEPS = (60, 300, 900, 1800, 3600, 10800, 21600, 43200, 86400)
MAX_POINTS = 240  # buckets when the chart does not say
MIN_POINTS = 24
POINTS_LIMIT = 480  # the most any chart may ask for
MAX_SPAN = timedelta(days=31)
USUAL_WINDOW = timedelta(days=7)


def choose_step(span: timedelta, points: int = MAX_POINTS) -> int:
    """The smallest bucket, in seconds, that keeps the span within ``points`` buckets."""
    points = min(max(points, MIN_POINTS), POINTS_LIMIT)
    seconds = max(span.total_seconds(), 60)
    return next((step for step in STEPS if seconds / step <= points), STEPS[-1])


@dataclass(frozen=True, slots=True)
class SeriesFinding:
    """A finding placed on the time axis. ``about`` is untrusted text."""

    id: int
    t: int
    priority: str
    rule: str
    about: str
    profile_id: str
    status: str


@dataclass(frozen=True, slots=True)
class SeriesLayer:
    """One profile's allowed and blocked queries per bucket."""

    profile_id: str
    allowed: list[int]
    blocked: list[int]


@dataclass(frozen=True, slots=True)
class Series:
    """Allowed and blocked queries per bucket, and the findings in the span.

    ``allowed`` and ``blocked`` are the totals over the profiles; ``layers``
    splits them per profile, in the order the profiles were given.
    """

    start: int
    end: int
    step: int
    t: list[int]
    allowed: list[int]
    blocked: list[int]
    usual: float | None
    findings: list[SeriesFinding]
    layers: list[SeriesLayer]


@dataclass(frozen=True, slots=True)
class TopDomain:
    """A root looked up in a window. ``root`` is untrusted text."""

    root: str
    queries: int
    blocked: int


@dataclass(frozen=True, slots=True)
class Window:
    """What happened between two moments."""

    start: datetime
    end: datetime
    allowed: int
    blocked: int
    findings: list[SeriesFinding]
    top: list[TopDomain]
    latest: list[LiveEvent]


def _epoch(moment: datetime) -> int:
    return int(moment.timestamp())


class SeriesQueries:
    """Reads for the interactive charts, for the enabled profiles."""

    def __init__(self, engine: AsyncEngine, *, profiles: Sequence[ProfileConfig]) -> None:
        """Query the database behind ``engine``."""
        self._engine = engine
        self._profiles = list(profiles)
        self._ids = [profile.id for profile in profiles]

    @staticmethod
    def clamp(start: datetime, end: datetime, now: datetime) -> tuple[datetime, datetime]:
        """Keep a requested span sensible: not in the future, at most ``MAX_SPAN`` long."""
        end = min(end, now)
        start = max(start, end - MAX_SPAN)
        if start >= end:
            start = end - timedelta(minutes=1)
        return start, end

    async def _findings(self, start: datetime, end: datetime, limit: int) -> list[SeriesFinding]:
        statement = (
            select(
                findings.c.id,
                findings.c.last_ts,
                findings.c.severity,
                finding_analysis.c.priority,
                findings.c.rule_id,
                findings.c.target,
                findings.c.profile_id,
                findings.c.status,
            )
            .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
            .where(
                findings.c.profile_id.in_(self._ids),
                findings.c.last_ts >= start,
                findings.c.last_ts < end,
            )
            .order_by(findings.c.last_ts)
            .limit(limit)
        )
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        out = []
        for row in rows:
            floor = Severity(row.severity)
            raised = Severity(row.priority) if row.priority else floor
            out.append(
                SeriesFinding(
                    id=int(row.id),
                    t=_epoch(row.last_ts),
                    priority=(raised if raised.rank > floor.rank else floor).value,
                    rule=row.rule_id,
                    about=row.target,
                    profile_id=row.profile_id,
                    status=row.status,
                )
            )
        return out

    async def series(self, start: datetime, end: datetime, *, points: int = MAX_POINTS) -> Series:
        """Queries per bucket between ``start`` and ``end`` (UTC), oldest first."""
        step = choose_step(end - start, points)
        first = _epoch(start) // step * step
        last = _epoch(end)
        # "//" is integer division in SQL; "/" is true division and would match no bar.
        seconds = cast(func.strftime("%s", events.c.ts), Integer)
        bucket = (seconds // step * step).label("bucket")
        blocked = func.sum(case((events.c.status == "blocked", 1), else_=0))
        aligned = datetime.fromtimestamp(first, UTC)
        async with self._engine.connect() as connection:
            counts: dict[str, dict[int, tuple[int, int]]] = {pid: {} for pid in self._ids}
            for row in (
                await connection.execute(
                    select(bucket, events.c.profile_id, func.count(), blocked)
                    .where(
                        events.c.profile_id.in_(self._ids),
                        events.c.ts >= aligned,
                        events.c.ts < end,
                    )
                    .group_by(bucket, events.c.profile_id)
                )
            ).all():
                counts[str(row[1])][int(row[0])] = (int(row[2]), int(row[3] or 0))
            week_start = end - USUAL_WINDOW
            week_count, oldest = (
                await connection.execute(
                    select(func.count(), func.min(events.c.ts)).where(
                        events.c.profile_id.in_(self._ids),
                        events.c.ts >= week_start,
                        events.c.ts < end,
                    )
                )
            ).one()
        usual = None
        if week_count and oldest is not None:
            covered = (end - max(oldest, week_start)).total_seconds()
            usual = week_count * step / covered if covered >= step else None
        t = list(range(first, last + 1, step))
        layers = []
        for pid in self._ids:
            pairs = [counts[pid].get(moment, (0, 0)) for moment in t]
            layers.append(
                SeriesLayer(
                    profile_id=pid,
                    allowed=[total - blocked_count for total, blocked_count in pairs],
                    blocked=[blocked_count for _, blocked_count in pairs],
                )
            )
        allowed = [sum(layer.allowed[i] for layer in layers) for i in range(len(t))]
        blocked_counts = [sum(layer.blocked[i] for layer in layers) for i in range(len(t))]
        return Series(
            start=first,
            end=last,
            step=step,
            t=t,
            allowed=allowed,
            blocked=blocked_counts,
            usual=round(usual, 2) if usual is not None else None,
            findings=await self._findings(aligned, end, limit=500),
            layers=layers,
        )

    async def window(self, start: datetime, end: datetime, *, top: int = 10) -> Window:
        """Totals, findings, the most queried roots and the latest queries in a window."""
        blocked = func.sum(case((events.c.status == "blocked", 1), else_=0))
        scope = (
            events.c.profile_id.in_(self._ids),
            events.c.ts >= start,
            events.c.ts < end,
        )
        async with self._engine.connect() as connection:
            total, blocked_total = (
                await connection.execute(select(func.count(), blocked).where(*scope))
            ).one()
            roots = (
                await connection.execute(
                    select(events.c.root, func.count().label("n"), blocked)
                    .where(*scope, events.c.root.is_not(None))
                    .group_by(events.c.root)
                    .order_by(func.count().desc(), events.c.root)
                    .limit(top)
                )
            ).all()
            latest_rows = (
                await connection.execute(
                    feed_columns().where(*scope).order_by(events.c.ts.desc()).limit(40)
                )
            ).all()
        return Window(
            start=start,
            end=end,
            allowed=int(total or 0) - int(blocked_total or 0),
            blocked=int(blocked_total or 0),
            findings=await self._findings(start, end, limit=50),
            top=[TopDomain(str(r[0]), int(r[1]), int(r[2] or 0)) for r in roots],
            latest=[live_event(row) for row in latest_rows],
        )
