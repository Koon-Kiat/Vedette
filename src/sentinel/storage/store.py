"""Reads and writes events and collector state.

Events are inserted idempotently (the event id is the primary key), and a
stream event is always committed in the same transaction as the cursor that
follows it. Those two properties are what make a kill at any moment safe:
after a restart the collector resumes from a cursor that matches exactly what
is on disk.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import event, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import make_url
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import ConnectionPoolEntry

from sentinel.sources.base import DnsEvent, Reason
from sentinel.storage.models import collector_state, events


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
        engine = create_async_engine(database_url)
        if make_url(database_url).get_backend_name() == "sqlite":
            event.listen(engine.sync_engine, "connect", _sqlite_pragmas)
        return cls(engine)

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
        return [
            DnsEvent(
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
            for row in rows
        ]
