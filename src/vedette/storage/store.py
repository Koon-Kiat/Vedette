"""Reads and writes events and collector state.

Events are inserted idempotently (the event id is the primary key), and a
stream event is always committed in the same transaction as the cursor that
follows it. Those two properties are what make a kill at any moment safe:
after a restart the collector resumes from a cursor that matches exactly what
is on disk.
"""

from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import event, func, select, tuple_, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import make_url
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import ConnectionPoolEntry

from vedette.rules.model import Finding, Severity
from vedette.sources.base import DnsEvent, Reason
from vedette.storage.models import collector_state, events, finding_analysis, findings


@dataclass(frozen=True, slots=True)
class CollectorState:
    """Where a profile's collector should resume.

    Attributes:
        stream_cursor: Live-stream position matching what is stored; ``None``
            until a backfill completes or after the source rejects it.
        synced_through: Every event up to this time is stored. Moves only when
            a backfill completes or a stream event is committed, never while
            newest-first history pages are still arriving.
        backfill_completed_at: When the first full backfill finished.
    """

    profile_id: str
    stream_cursor: str | None
    synced_through: datetime | None
    backfill_completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class StoredFinding:
    """A finding as stored: repeated sightings are merged into one row.

    Attributes:
        id: Database id.
        rule_id: The rule that fired.
        severity: The rule's severity floor.
        profile_id: Profile the finding belongs to.
        subject: Device id, or ``None`` when the rule keyed on the profile.
        device_mode: Whether ``subject`` is a real device.
        target: What the finding is about.
        first_ts: Time of the first triggering event.
        last_ts: Time of the latest triggering event.
        event_count: Number of triggering events merged into this row.
        evidence: Evidence recorded at the first sighting. Untrusted strings.
        status: ``open`` until acted on.
    """

    id: int
    rule_id: str
    severity: Severity
    profile_id: str
    subject: str | None
    device_mode: bool
    target: str
    first_ts: datetime
    last_ts: datetime
    event_count: int
    evidence: dict[str, Any]
    status: str


def finding_from_row(row: Any) -> StoredFinding:
    """Build a :class:`StoredFinding` from a row of the findings table."""
    return StoredFinding(
        id=row.id,
        rule_id=row.rule_id,
        severity=Severity(row.severity),
        profile_id=row.profile_id,
        subject=row.subject,
        device_mode=row.device_mode,
        target=row.target,
        first_ts=row.first_ts,
        last_ts=row.last_ts,
        event_count=row.event_count,
        evidence=row.evidence,
        status=row.status,
    )


def to_event(row: Any) -> DnsEvent:
    """Build a :class:`DnsEvent` from a row of the events table."""
    return DnsEvent(
        event_id=row.event_id,
        profile_id=row.profile_id,
        ts=row.ts,
        fqdn=row.fqdn,
        root=row.root,
        status=row.status,
        reasons=tuple(Reason(**reason) for reason in row.reasons),
        device_id=row.device_id,
        device_name=row.device_name,
        client_ip=row.client_ip,
        protocol=row.protocol,
        encrypted=row.encrypted,
        tracker=row.tracker,
        source=row.source,
    )


def _sqlite_pragmas(connection: DBAPIConnection, record: ConnectionPoolEntry) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
    finally:
        cursor.close()


def _row(item: DnsEvent, ingested_at: datetime) -> dict[str, Any]:
    return {
        "event_id": item.event_id,
        "profile_id": item.profile_id,
        "ts": item.ts,
        "fqdn": item.fqdn,
        "root": item.root,
        "status": item.status,
        "reasons": [reason.model_dump() for reason in item.reasons],
        "device_id": item.device_id,
        "device_name": item.device_name,
        "client_ip": item.client_ip,
        "protocol": item.protocol,
        "encrypted": item.encrypted,
        "tracker": item.tracker,
        "source": item.source,
        "ingested_at": ingested_at,
    }


class Store:
    """Database access for the collector. Open with :meth:`open`."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Wrap an existing engine. Prefer :meth:`open`."""
        self._engine = engine

    @classmethod
    def open(cls, database_url: str) -> Store:
        """Connect to a database whose schema is already migrated."""
        if make_url(database_url).get_backend_name() == "sqlite":
            # Enough pooled connections for every worker and the dashboard, so new
            # connections are opened mostly at start-up. (aiosqlite cannot cancel a
            # connect cleanly: one interrupted by shutdown is left to the garbage
            # collector, which closes it; SQLite itself is unaffected.)
            engine = create_async_engine(database_url, pool_size=15, max_overflow=10)
            event.listen(engine.sync_engine, "connect", _sqlite_pragmas)
        else:
            engine = create_async_engine(database_url)
        return cls(engine)

    @property
    def engine(self) -> AsyncEngine:
        """The underlying engine, shared with the reference-data store."""
        return self._engine

    async def close(self) -> None:
        """Release all database connections."""
        await self._engine.dispose()

    async def _insert(self, connection: AsyncConnection, items: Sequence[DnsEvent]) -> int:
        unique = {item.event_id: item for item in items}
        if not unique:
            return 0
        now = datetime.now(UTC)
        statement = (
            sqlite_insert(events)
            .on_conflict_do_nothing(index_elements=["event_id"])
            .returning(events.c.event_id)
        )
        result = await connection.execute(statement, [_row(item, now) for item in unique.values()])
        return len(result.all())

    async def _write_state(
        self, connection: AsyncConnection, profile_id: str, values: dict[str, Any]
    ) -> None:
        values = {**values, "updated_at": datetime.now(UTC)}
        updated = await connection.execute(
            collector_state.update()
            .where(collector_state.c.profile_id == profile_id)
            .values(**values)
        )
        if updated.rowcount == 0:
            await connection.execute(
                collector_state.insert().values(profile_id=profile_id, **values)
            )

    async def save_events(self, items: Sequence[DnsEvent]) -> int:
        """Store history events and return how many were new.

        Collector state is left untouched: history pages arrive newest first,
        so they say nothing yet about how far the profile is fully synced.
        """
        async with self._engine.begin() as connection:
            return await self._insert(connection, items)

    async def save_stream_events(
        self, profile_id: str, items: Sequence[DnsEvent], *, stream_cursor: str | None
    ) -> int:
        """Store live events and advance the cursor in one transaction.

        Returns how many events were new. ``synced_through`` only moves forward.
        """
        async with self._engine.begin() as connection:
            inserted = await self._insert(connection, items)
            current = await self._read_state(connection, profile_id)
            values: dict[str, Any] = {}
            if stream_cursor is not None:
                values["stream_cursor"] = stream_cursor
            newest = max((item.ts for item in items), default=None)
            previous = current.synced_through if current else None
            if newest is not None and (previous is None or newest > previous):
                values["synced_through"] = newest
            if values:
                await self._write_state(connection, profile_id, values)
            return inserted

    async def complete_backfill(
        self, profile_id: str, *, stream_cursor: str, synced_through: datetime | None
    ) -> None:
        """Record that history is fully stored and where the stream continues."""
        async with self._engine.begin() as connection:
            current = await self._read_state(connection, profile_id)
            values: dict[str, Any] = {
                "stream_cursor": stream_cursor,
                "synced_through": synced_through,
            }
            if current is None or current.backfill_completed_at is None:
                values["backfill_completed_at"] = datetime.now(UTC)
            await self._write_state(connection, profile_id, values)

    async def clear_stream_cursor(self, profile_id: str) -> None:
        """Forget a cursor the source rejected, keeping the resume point."""
        async with self._engine.begin() as connection:
            await self._write_state(connection, profile_id, {"stream_cursor": None})

    async def _read_state(
        self, connection: AsyncConnection, profile_id: str
    ) -> CollectorState | None:
        row = (
            await connection.execute(
                select(collector_state).where(collector_state.c.profile_id == profile_id)
            )
        ).one_or_none()
        if row is None:
            return None
        return CollectorState(
            profile_id=row.profile_id,
            stream_cursor=row.stream_cursor,
            synced_through=row.synced_through,
            backfill_completed_at=row.backfill_completed_at,
        )

    async def get_state(self, profile_id: str) -> CollectorState | None:
        """Return the collector state for a profile, or ``None`` if it has none."""
        async with self._engine.connect() as connection:
            return await self._read_state(connection, profile_id)

    async def count_events(self, profile_id: str) -> int:
        """Number of stored events for a profile."""
        async with self._engine.connect() as connection:
            result = await connection.execute(
                select(func.count()).select_from(events).where(events.c.profile_id == profile_id)
            )
            return int(result.scalar_one())

    async def list_events(self, profile_id: str, *, limit: int | None = None) -> list[DnsEvent]:
        """Stored events for a profile, oldest first."""
        statement = (
            select(events)
            .where(events.c.profile_id == profile_id)
            .order_by(events.c.ts, events.c.event_id)
        )
        if limit is not None:
            statement = statement.limit(limit)
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [to_event(row) for row in rows]

    # --- processing ---------------------------------------------------------------

    async def fetch_unprocessed(self, profile_id: str, *, limit: int) -> list[DnsEvent]:
        """Oldest events of a profile that have not been through the rules yet."""
        statement = (
            select(events)
            .where(events.c.profile_id == profile_id, events.c.processed_at.is_(None))
            .order_by(events.c.ts, events.c.event_id)
            .limit(limit)
        )
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [to_event(row) for row in rows]

    async def count_unprocessed(self, profile_id: str) -> int:
        """Number of a profile's events still waiting for the rules."""
        async with self._engine.connect() as connection:
            result = await connection.execute(
                select(func.count())
                .select_from(events)
                .where(events.c.profile_id == profile_id, events.c.processed_at.is_(None))
            )
            return int(result.scalar_one())

    async def latest_event_ts(self, profile_id: str) -> datetime | None:
        """Time of the newest stored event of a profile."""
        async with self._engine.connect() as connection:
            result = await connection.execute(
                select(func.max(events.c.ts)).where(events.c.profile_id == profile_id)
            )
            latest: datetime | None = result.scalar_one_or_none()
            return latest

    async def earliest_event_ts(self, profile_id: str) -> datetime | None:
        """Time of the oldest stored event of a profile."""
        async with self._engine.connect() as connection:
            result = await connection.execute(
                select(func.min(events.c.ts)).where(events.c.profile_id == profile_id)
            )
            earliest: datetime | None = result.scalar_one_or_none()
            return earliest

    async def iter_processed_fields(
        self, profile_id: str, *, since: datetime, chunk: int = 5000
    ) -> AsyncIterator[tuple[str, str | None, datetime, str, str | None, str]]:
        """Yield ``(profile_id, device_id, ts, fqdn, root, status)`` of processed events.

        Oldest first, from ``since`` on. Used to rebuild the rule engine's
        windows and baselines after a restart without loading whole events.
        """
        position: tuple[datetime, str] | None = None
        while True:
            statement = (
                select(
                    events.c.profile_id,
                    events.c.device_id,
                    events.c.ts,
                    events.c.fqdn,
                    events.c.root,
                    events.c.status,
                    events.c.event_id,
                )
                .where(
                    events.c.profile_id == profile_id,
                    events.c.processed_at.is_not(None),
                    events.c.ts >= since,
                )
                .order_by(events.c.ts, events.c.event_id)
                .limit(chunk)
            )
            if position is not None:
                statement = statement.where(tuple_(events.c.ts, events.c.event_id) > position)
            async with self._engine.connect() as connection:
                rows = (await connection.execute(statement)).all()
            for row in rows:
                yield (row.profile_id, row.device_id, row.ts, row.fqdn, row.root, row.status)
            if len(rows) < chunk:
                return
            position = (rows[-1].ts, rows[-1].event_id)

    async def commit_processed(self, event_ids: Sequence[str], found: Sequence[Finding]) -> None:
        """Mark events as processed and store their findings, atomically.

        Findings sharing a ``dedupe_key`` (in this call or already stored) are
        merged: the count grows, the time range widens, and the evidence of
        the first sighting is kept.
        """
        now = datetime.now(UTC)
        merged: dict[str, dict[str, Any]] = {}
        for item in found:
            row = merged.get(item.dedupe_key)
            if row is None:
                merged[item.dedupe_key] = {
                    "dedupe_key": item.dedupe_key,
                    "rule_id": item.rule_id,
                    "severity": item.severity.value,
                    "profile_id": item.profile_id,
                    "subject": item.subject,
                    "device_mode": item.device_mode,
                    "target": item.target[:256],
                    "first_ts": item.ts,
                    "last_ts": item.ts,
                    "event_count": 1,
                    "evidence": item.evidence,
                    "event_id": item.event_id,
                    "status": "open",
                    "created_at": now,
                    "updated_at": now,
                }
            else:
                row["event_count"] += 1
                row["first_ts"] = min(row["first_ts"], item.ts)
                row["last_ts"] = max(row["last_ts"], item.ts)
        async with self._engine.begin() as connection:
            if merged:
                statement = sqlite_insert(findings)
                await connection.execute(
                    statement.on_conflict_do_update(
                        index_elements=["dedupe_key"],
                        set_={
                            "event_count": findings.c.event_count + statement.excluded.event_count,
                            "first_ts": func.min(findings.c.first_ts, statement.excluded.first_ts),
                            "last_ts": func.max(findings.c.last_ts, statement.excluded.last_ts),
                            "updated_at": now,
                        },
                    ),
                    list(merged.values()),
                )
            for start in range(0, len(event_ids), 500):
                await connection.execute(
                    update(events)
                    .where(events.c.event_id.in_(event_ids[start : start + 500]))
                    .values(processed_at=now)
                )

    async def finding(self, finding_id: int) -> StoredFinding | None:
        """One finding by its number."""
        async with self._engine.connect() as connection:
            row = (
                await connection.execute(select(findings).where(findings.c.id == finding_id))
            ).one_or_none()
        return None if row is None else finding_from_row(row)

    async def list_findings(
        self,
        *,
        profile_id: str | None = None,
        rule_id: str | None = None,
        min_severity: Severity | None = None,
        limit: int = 50,
    ) -> list[StoredFinding]:
        """Stored findings, most recently seen first.

        ``min_severity`` compares against a finding's effective priority: the
        one its analysis gave it if there is one, otherwise the rule's floor.
        """
        statement = select(findings).order_by(findings.c.last_ts.desc(), findings.c.id.desc())
        if profile_id is not None:
            statement = statement.where(findings.c.profile_id == profile_id)
        if rule_id is not None:
            statement = statement.where(findings.c.rule_id == rule_id)
        if min_severity is not None:
            wanted = [level.value for level in Severity if level.rank >= min_severity.rank]
            effective = func.coalesce(finding_analysis.c.priority, findings.c.severity)
            statement = statement.outerjoin(
                finding_analysis, finding_analysis.c.finding_id == findings.c.id
            ).where(effective.in_(wanted))
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement.limit(limit))).all()
        return [finding_from_row(row) for row in rows]
