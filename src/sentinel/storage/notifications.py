"""The notification outbox and the digest archive.

Every alert, health message and digest is written here before anything is
sent, together with what happened to it: ``pending`` (waiting to be sent),
``sent``, ``failed`` (gave up), ``skipped`` (deliberately not sent, for
example too old or no channel configured) or ``suppressed`` (within the
cooldown). A restart therefore loses nothing, and an alert is never created
twice for the same finding.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel.llm.schema import Analysis
from sentinel.notify.channels import OutgoingMessage
from sentinel.rules.model import Severity
from sentinel.storage.analysis import AnalysisStore
from sentinel.storage.models import digests, finding_analysis, findings, notifications
from sentinel.storage.store import StoredFinding, finding_from_row

_ALERTING = [Severity.HIGH.value, Severity.CRITICAL.value]


@dataclass(frozen=True, slots=True)
class OutboxItem:
    """One message in the outbox and what has happened to it."""

    id: int
    kind: str
    dedupe_key: str
    finding_id: int | None
    title: str
    body: str
    priority: Severity
    tags: tuple[str, ...]
    status: str
    reason: str | None
    attempts: int
    next_attempt_at: datetime
    created_at: datetime
    sent_at: datetime | None

    @property
    def message(self) -> OutgoingMessage:
        """The message to hand to a channel."""
        return OutgoingMessage(
            title=self.title, body=self.body, priority=self.priority, tags=self.tags
        )


@dataclass(frozen=True, slots=True)
class AlertCandidate:
    """A finding that may need an instant alert, with its analysis if it has one."""

    finding: StoredFinding
    analysis: Analysis | None


@dataclass(frozen=True, slots=True)
class StoredDigest:
    """A digest as generated, kept for the archive."""

    id: int
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    title: str
    body: str
    data: dict[str, Any]
    notification_id: int | None


def _new_id(result: CursorResult[Any]) -> int:
    """Primary key of the row an INSERT just created."""
    key = result.inserted_primary_key
    if key is None:  # pragma: no cover - SQLite always reports it
        raise RuntimeError("the database did not report the new row's id")
    return int(key[0])


def _item(row: Any) -> OutboxItem:
    return OutboxItem(
        id=row.id,
        kind=row.kind,
        dedupe_key=row.dedupe_key,
        finding_id=row.finding_id,
        title=row.title,
        body=row.body,
        priority=Severity(row.priority),
        tags=tuple(row.tags),
        status=row.status,
        reason=row.reason,
        attempts=row.attempts,
        next_attempt_at=row.next_attempt_at,
        created_at=row.created_at,
        sent_at=row.sent_at,
    )


def _row(
    *,
    kind: str,
    key: str,
    message: OutgoingMessage,
    now: datetime,
    finding_id: int | None,
    status: str,
    reason: str | None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "dedupe_key": key[:600],
        "finding_id": finding_id,
        "title": message.title[:300],
        "body": message.body,
        "priority": message.priority.value,
        "tags": list(message.tags),
        "status": status,
        "reason": reason,
        "attempts": 0,
        "next_attempt_at": now,
        "created_at": now,
        "sent_at": None,
    }


class NotificationStore:
    """Reads and writes the outbox and the digest archive."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Use the given database engine (shared with the event store)."""
        self._engine = engine

    # --- deciding what to alert ------------------------------------------------------

    async def alert_candidates(self, *, limit: int = 100) -> list[AlertCandidate]:
        """Findings with an effective priority of high or critical and no outbox entry yet."""
        effective = func.coalesce(finding_analysis.c.priority, findings.c.severity)
        statement = (
            select(findings)
            .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
            .outerjoin(notifications, notifications.c.finding_id == findings.c.id)
            .where(
                notifications.c.id.is_(None),
                or_(findings.c.severity.in_(_ALERTING), effective.in_(_ALERTING)),
            )
            .order_by(findings.c.id)
            .limit(limit)
        )
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        found = [finding_from_row(row) for row in rows]
        analyses = await AnalysisStore(self._engine).analyses_for([item.id for item in found])
        return [AlertCandidate(item, analyses.get(item.id)) for item in found]

    async def recently_notified(self, key: str, *, since: datetime) -> bool:
        """Whether a message with this key was sent or queued at or after ``since``."""
        statement = (
            select(func.count())
            .select_from(notifications)
            .where(
                notifications.c.dedupe_key == key[:600],
                notifications.c.status.in_(["pending", "sent"]),
                notifications.c.created_at >= since,
            )
        )
        async with self._engine.connect() as connection:
            return int((await connection.execute(statement)).scalar_one()) > 0

    async def enqueue(
        self,
        *,
        kind: str,
        key: str,
        message: OutgoingMessage,
        now: datetime,
        finding_id: int | None = None,
        status: str = "pending",
        reason: str | None = None,
    ) -> int:
        """Add a message to the outbox and return its id."""
        values = _row(
            kind=kind,
            key=key,
            message=message,
            now=now,
            finding_id=finding_id,
            status=status,
            reason=reason,
        )
        async with self._engine.begin() as connection:
            result = await connection.execute(notifications.insert().values(**values))
            return _new_id(result)

    async def last_health_message(self, check_key: str) -> tuple[str, str, datetime] | None:
        """The latest health message about a check that reached, or is on its way to, the user.

        Returns ``problem`` or ``resolved``, the title and the time. Messages that
        were skipped (no channel) or failed do not count: the user never saw them.
        """
        problem, resolved = f"health|{check_key}", f"health|{check_key}|resolved"
        statement = (
            select(notifications.c.dedupe_key, notifications.c.title, notifications.c.created_at)
            .where(
                notifications.c.kind == "health",
                notifications.c.dedupe_key.in_([problem, resolved]),
                notifications.c.status.in_(["pending", "sent"]),
            )
            .order_by(notifications.c.id.desc())
            .limit(1)
        )
        async with self._engine.connect() as connection:
            row = (await connection.execute(statement)).one_or_none()
        if row is None:
            return None
        kind = "resolved" if row.dedupe_key == resolved else "problem"
        return kind, row.title, row.created_at

    # --- delivering ----------------------------------------------------------------------

    async def due(self, now: datetime, *, limit: int = 20) -> list[OutboxItem]:
        """Pending messages whose time has come, oldest first."""
        statement = (
            select(notifications)
            .where(notifications.c.status == "pending", notifications.c.next_attempt_at <= now)
            .order_by(notifications.c.next_attempt_at, notifications.c.id)
            .limit(limit)
        )
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [_item(row) for row in rows]

    async def _update(self, item_id: int, **values: Any) -> None:
        async with self._engine.begin() as connection:
            await connection.execute(
                update(notifications).where(notifications.c.id == item_id).values(**values)
            )

    async def mark_sent(self, item_id: int, *, now: datetime, attempts: int) -> None:
        """Record a successful delivery."""
        await self._update(item_id, status="sent", sent_at=now, attempts=attempts, reason=None)

    async def reschedule(self, item_id: int, *, at: datetime, attempts: int, reason: str) -> None:
        """Try again at ``at`` after a temporary failure."""
        await self._update(item_id, next_attempt_at=at, attempts=attempts, reason=reason[:200])

    async def defer(self, item_id: int, *, until: datetime, reason: str) -> None:
        """Hold a message until ``until`` without counting an attempt."""
        await self._update(item_id, next_attempt_at=until, reason=reason[:200])

    async def finish(
        self, item_id: int, *, status: str, reason: str, attempts: int | None = None
    ) -> None:
        """Close a message without sending it (``failed`` or ``skipped``)."""
        values: dict[str, Any] = {"status": status, "reason": reason[:200]}
        if attempts is not None:
            values["attempts"] = attempts
        await self._update(item_id, **values)

    async def recent(self, *, limit: int) -> list[OutboxItem]:
        """The newest messages, newest first."""
        statement = select(notifications).order_by(notifications.c.id.desc()).limit(limit)
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [_item(row) for row in rows]

    # --- digests ---------------------------------------------------------------------------

    async def last_digest_end(self) -> datetime | None:
        """End of the most recent digest period, if any digest exists."""
        async with self._engine.connect() as connection:
            result = await connection.execute(select(func.max(digests.c.period_end)))
            last: datetime | None = result.scalar_one_or_none()
            return last

    async def record_digest(
        self,
        *,
        period_start: datetime,
        period_end: datetime,
        now: datetime,
        message: OutgoingMessage,
        data: dict[str, Any],
    ) -> int:
        """Archive a digest and queue it for delivery, in one transaction."""
        values = _row(
            kind="digest",
            key=f"digest|{period_end.isoformat()}",
            message=message,
            now=now,
            finding_id=None,
            status="pending",
            reason=None,
        )
        async with self._engine.begin() as connection:
            queued = await connection.execute(notifications.insert().values(**values))
            stored = await connection.execute(
                digests.insert().values(
                    period_start=period_start,
                    period_end=period_end,
                    generated_at=now,
                    title=message.title[:300],
                    body=message.body,
                    data=data,
                    notification_id=_new_id(queued),
                )
            )
            return _new_id(stored)

    async def digests(self, *, limit: int) -> list[StoredDigest]:
        """Archived digests, newest first."""
        statement = select(digests).order_by(digests.c.period_end.desc()).limit(limit)
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [
            StoredDigest(
                id=row.id,
                period_start=row.period_start,
                period_end=row.period_end,
                generated_at=row.generated_at,
                title=row.title,
                body=row.body,
                data=row.data,
                notification_id=row.notification_id,
            )
            for row in rows
        ]
