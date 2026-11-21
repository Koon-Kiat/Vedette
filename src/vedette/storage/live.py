"""Reads behind the dashboard's live feed and live counters.

The feed follows event time, not the order rows were written: it reads a short
recent window on every poll and skips events it has already sent, so two
profiles' collectors writing slightly out of order lose nothing, and history
loaded by a backfill or an import (old timestamps) never floods the feed.
"""

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Select, case, func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from vedette.config import ProfileConfig
from vedette.storage.health import HealthStore
from vedette.storage.models import events, findings

#: How far back each poll looks, to catch events written a little late.
OVERLAP = timedelta(seconds=90)
#: Events older than this when the feed starts are not shown as live.
START_WINDOW = timedelta(minutes=2)
MINUTES = 30


@dataclass(frozen=True, slots=True)
class LiveEvent:
    """One DNS query, as the feed shows it. Every string is untrusted."""

    event_id: str
    ts: datetime
    profile_id: str
    device: str | None
    fqdn: str
    status: str
    reason: str | None


@dataclass(frozen=True, slots=True)
class LiveStats:
    """The live counters."""

    last_minute: int
    blocked_last_minute: int
    per_minute: list[tuple[int, int]]  # (allowed, blocked), oldest minute first, current last
    open_findings: int
    newest_finding_id: int | None
    checks_ok: int
    checks_total: int
    newest_event: datetime | None
    #: Open findings per profile id, every profile of the view listed.
    open_by_profile: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class FeedCursor:
    """Where a feed has got to: the newest time sent and the ids sent recently."""

    since: datetime
    seen: deque[str] = field(default_factory=lambda: deque(maxlen=5000))
    seen_set: set[str] = field(default_factory=set)

    def mark(self, event_id: str) -> None:
        """Remember an event as sent, forgetting the oldest beyond the window."""
        if len(self.seen) == self.seen.maxlen:
            self.seen_set.discard(self.seen[0])
        self.seen.append(event_id)
        self.seen_set.add(event_id)


def _event_columns() -> Select[Any]:
    return select(
        events.c.event_id,
        events.c.ts,
        events.c.profile_id,
        events.c.device_id,
        events.c.device_name,
        events.c.fqdn,
        events.c.status,
        events.c.reasons,
    )


def live_event(row: Any) -> LiveEvent:
    """An events row (with the columns of the live feed) as a feed item."""
    reasons = row.reasons or []
    first = reasons[0] if isinstance(reasons, list) and reasons else None
    reason = (first.get("name") or first.get("id")) if isinstance(first, dict) else None
    return LiveEvent(
        event_id=row.event_id,
        ts=row.ts,
        profile_id=row.profile_id,
        device=row.device_name or row.device_id,
        fqdn=row.fqdn,
        status=row.status,
        reason=str(reason) if reason else None,
    )


class LiveQueries:
    """Recent events and live counters for the enabled profiles."""

    def __init__(self, engine: AsyncEngine, *, profiles: Sequence[ProfileConfig]) -> None:
        """Query the database behind ``engine``."""
        self._engine = engine
        self._ids = [profile.id for profile in profiles]

    @staticmethod
    def _event(row: Any) -> LiveEvent:
        return live_event(row)

    def _select(self) -> Select[Any]:
        return _event_columns().where(events.c.profile_id.in_(self._ids))

    async def recent(self, limit: int) -> list[LiveEvent]:
        """The newest events, newest first."""
        statement = self._select().order_by(events.c.ts.desc()).limit(limit)
        async with self._engine.connect() as connection:
            return [self._event(row) for row in (await connection.execute(statement)).all()]

    def start(self, now: datetime) -> FeedCursor:
        """A cursor that will deliver events from a moment ago onwards."""
        return FeedCursor(since=now - START_WINDOW)

    async def poll(self, cursor: FeedCursor, *, limit: int = 200) -> list[LiveEvent]:
        """Events not sent yet, oldest first. Updates ``cursor``."""
        statement = (
            self._select()
            .where(events.c.ts > cursor.since - OVERLAP)
            .order_by(events.c.ts, events.c.event_id)
            .limit(limit + len(cursor.seen_set))
        )
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        fresh: list[LiveEvent] = []
        for row in rows:
            if row.event_id in cursor.seen_set:
                continue
            item = self._event(row)
            cursor.mark(item.event_id)
            fresh.append(item)
            if item.ts > cursor.since:
                cursor.since = item.ts
            if len(fresh) >= limit:
                break
        return fresh

    async def stats(self, now: datetime) -> LiveStats:
        """Counts for the last minute and the last 30 minutes, and pipeline state."""
        start = (now - timedelta(minutes=MINUTES - 1)).replace(second=0, microsecond=0)
        minute = func.strftime("%Y-%m-%d %H:%M", events.c.ts).label("minute")
        blocked = func.sum(case((events.c.status == "blocked", 1), else_=0))
        async with self._engine.connect() as connection:
            counts = {
                str(row[0]): (int(row[1]), int(row[2] or 0))
                for row in (
                    await connection.execute(
                        select(minute, func.count(), blocked)
                        .where(events.c.profile_id.in_(self._ids), events.c.ts >= start)
                        .group_by(minute)
                    )
                ).all()
            }
            last_minute, blocked_last = (
                await connection.execute(
                    select(func.count(), blocked).where(
                        events.c.profile_id.in_(self._ids),
                        events.c.ts > now - timedelta(minutes=1),
                    )
                )
            ).one()
            by_profile = {pid: 0 for pid in self._ids}
            newest_finding: int | None = None
            for profile_id, count, newest in (
                await connection.execute(
                    select(findings.c.profile_id, func.count(), func.max(findings.c.id))
                    .where(findings.c.profile_id.in_(self._ids), findings.c.status == "open")
                    .group_by(findings.c.profile_id)
                )
            ).all():
                by_profile[str(profile_id)] = int(count)
                if newest is not None and (newest_finding is None or int(newest) > newest_finding):
                    newest_finding = int(newest)
            newest_event = (
                await connection.execute(
                    select(func.max(events.c.ts)).where(events.c.profile_id.in_(self._ids))
                )
            ).scalar_one_or_none()
        per_minute = []
        for index in range(MINUTES):
            key = (start + timedelta(minutes=index)).strftime("%Y-%m-%d %H:%M")
            total, blocked_count = counts.get(key, (0, 0))
            per_minute.append((total - blocked_count, blocked_count))
        checks = await HealthStore(self._engine).read()
        return LiveStats(
            last_minute=int(last_minute or 0),
            blocked_last_minute=int(blocked_last or 0),
            per_minute=per_minute,
            open_findings=sum(by_profile.values()),
            newest_finding_id=newest_finding,
            checks_ok=sum(1 for check in checks if check.ok),
            checks_total=len(checks),
            newest_event=newest_event,
            open_by_profile=by_profile,
        )
