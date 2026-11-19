"""Measurements taken from the owner's real, stored history.

Nothing here replays or changes data: it reads what the pipeline already
recorded. Only counts and timings leave this module, never names.
"""

import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel.rules.model import Severity
from sentinel.storage.models import events, finding_analysis, findings, llm_calls, notifications

#: An event that reached the database within this time of happening came from the live stream.
LIVE = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class Timing:
    """Median and 95th percentile of a duration, in seconds, over ``count`` cases."""

    count: int
    p50: float | None
    p95: float | None


@dataclass(frozen=True, slots=True)
class HistoryMetrics:
    """What the stored history says about alerts, speed and model load."""

    days: float
    events: int
    alerts: int
    alerts_marked_benign: int
    event_to_finding: Timing
    finding_to_alert: Timing
    llm_calls_7d: int
    llm_cache_hit_rate: float | None

    @property
    def alerts_per_day(self) -> float | None:
        """High and critical findings per day of stored history."""
        return self.alerts / self.days if self.days >= 1 else None

    @property
    def llm_calls_per_day(self) -> float | None:
        """Model calls per day over the last 7 days (or the history, if shorter)."""
        span = min(self.days, 7.0)
        return self.llm_calls_7d / span if span >= 1 else None


def timing(seconds: Sequence[float]) -> Timing:
    """Summarise durations."""
    values = sorted(seconds)
    if not values:
        return Timing(0, None, None)
    if len(values) == 1:
        return Timing(1, values[0], values[0])
    cuts = statistics.quantiles(values, n=20, method="inclusive")
    return Timing(len(values), cuts[9], cuts[18])


async def history_metrics(
    engine: AsyncEngine, profile_ids: Sequence[str], now: datetime
) -> HistoryMetrics:
    """Read the measurements for the given profiles."""
    ids = list(profile_ids)
    async with engine.connect() as connection:
        first, last, count = (
            await connection.execute(
                select(func.min(events.c.ts), func.max(events.c.ts), func.count()).where(
                    events.c.profile_id.in_(ids)
                )
            )
        ).one()
        days = (
            (last - first).total_seconds() / 86400
            if first is not None and last is not None
            else 0.0
        )

        rows = (
            await connection.execute(
                select(findings.c.severity, finding_analysis.c.priority, findings.c.status)
                .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
                .where(findings.c.profile_id.in_(ids))
            )
        ).all()
        alerts = benign = 0
        for floor, priority, status in rows:
            rank = max(Severity(floor).rank, Severity(priority).rank if priority else 0)
            if rank >= Severity.HIGH.rank:
                alerts += 1
                benign += status == "benign"

        live = (
            await connection.execute(
                select(findings.c.created_at, events.c.ts, events.c.ingested_at)
                .join(events, events.c.event_id == findings.c.event_id)
                .where(findings.c.profile_id.in_(ids))
            )
        ).all()
        to_finding = [
            (created - ts).total_seconds()
            for created, ts, ingested in live
            if ingested - ts <= LIVE and created >= ts
        ]

        alerted = (
            await connection.execute(
                select(notifications.c.created_at, findings.c.created_at)
                .join(findings, findings.c.id == notifications.c.finding_id)
                .where(
                    notifications.c.kind == "alert",
                    # Entries skipped as too old or suppressed by the cooldown were never alerts.
                    notifications.c.status.in_(("pending", "sent", "failed")),
                    findings.c.profile_id.in_(ids),
                )
            )
        ).all()
        to_alert = [
            (queued - created).total_seconds() for queued, created in alerted if queued >= created
        ]

        week = now - timedelta(days=7)
        calls = int(
            (
                await connection.execute(
                    select(func.count())
                    .select_from(llm_calls)
                    .where(llm_calls.c.started_at >= week)
                )
            ).scalar_one()
        )
        sources: dict[str, int] = dict(
            (
                await connection.execute(
                    select(finding_analysis.c.source, func.count())
                    .where(finding_analysis.c.created_at >= week)
                    .group_by(finding_analysis.c.source)
                )
            ).all()
        )
    answered = sources.get("cache", 0) + sources.get("llm", 0)
    return HistoryMetrics(
        days=days,
        events=int(count),
        alerts=alerts,
        alerts_marked_benign=benign,
        event_to_finding=timing(to_finding),
        finding_to_alert=timing(to_alert),
        llm_calls_7d=calls,
        llm_cache_hit_rate=sources.get("cache", 0) / answered if answered else None,
    )
