"""How long local data is kept, and wiping it.

DNS history is sensitive personal data. Raw events are kept for
``retention.events_days`` and findings for ``retention.findings_days``; a
scheduled purge removes anything older, together with what was derived from
it (analyses, messages, decisions). ``vedette purge --all`` wipes everything.

Kept on purpose until a full wipe: the first-seen index (what makes a device or
domain "new"), the downloaded reference lists and the registration-date cache,
and stored allowlist entries, which keep working after their finding is gone.
"""

import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine

from vedette.storage.models import (
    allowlist,
    audit_log,
    digests,
    events,
    finding_analysis,
    findings,
    llm_calls,
    metadata,
    notifications,
)

_KEEP_ON_WIPE = frozenset({"alembic_version"})


@dataclass(slots=True)
class Purged:
    """How many rows each table lost."""

    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        """Rows removed in all."""
        return sum(self.counts.values())


def sqlite_path(database_url: str) -> Path | None:
    """The database file behind a SQLite URL; ``None`` for anything else."""
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return None
    return Path(url.database)


def restrict_permissions(database_url: str) -> None:
    """Make the database directory and files readable by their owner only.

    Files created later get the same treatment from the process umask that
    ``vedette`` sets at start-up; this fixes files created before it did.
    """
    path = sqlite_path(database_url)
    if path is None:
        return
    directory = path.parent
    if directory.is_dir() and stat.S_IMODE(directory.stat().st_mode) & 0o077:
        directory.chmod(0o700)
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal")):
        if candidate.is_file() and stat.S_IMODE(candidate.stat().st_mode) & 0o077:
            candidate.chmod(0o600)


def private_umask() -> None:
    """Create every later file owner-only (database, WAL, logs written to disk)."""
    os.umask(0o077)


async def purge_expired(
    engine: AsyncEngine, *, now: datetime, events_days: int, findings_days: int
) -> Purged:
    """Delete events and findings past their retention, with what came from them.

    Events still waiting for the rules are kept until they have been processed.
    """
    event_cutoff = now - timedelta(days=events_days)
    finding_cutoff = now - timedelta(days=findings_days)
    purged = Purged()
    async with engine.begin() as connection:
        old = select(findings.c.id).where(findings.c.last_ts < finding_cutoff)
        ids = [row[0] for row in (await connection.execute(old)).all()]
        steps = [
            (
                "events",
                delete(events).where(
                    events.c.ts < event_cutoff, events.c.processed_at.is_not(None)
                ),
            ),
            (
                "finding_analysis",
                delete(finding_analysis).where(finding_analysis.c.finding_id.in_(ids)),
            ),
            ("audit_log", delete(audit_log).where(audit_log.c.finding_id.in_(ids))),
            (
                "notifications",
                delete(notifications).where(
                    notifications.c.finding_id.in_(ids)
                    | (
                        notifications.c.finding_id.is_(None)
                        & (notifications.c.created_at < finding_cutoff)
                    )
                ),
            ),
            ("digests", delete(digests).where(digests.c.period_end < finding_cutoff)),
            ("llm_calls", delete(llm_calls).where(llm_calls.c.started_at < finding_cutoff)),
            ("findings", delete(findings).where(findings.c.id.in_(ids))),
        ]
        await connection.execute(
            update(allowlist).where(allowlist.c.finding_id.in_(ids)).values(finding_id=None)
        )
        for name, statement in steps:
            result = await connection.execute(statement)
            if result.rowcount:
                purged.counts[name] = result.rowcount
    return purged


async def purge_all(engine: AsyncEngine) -> Purged:
    """Delete every row of every table, then compact the file so nothing lingers."""
    purged = Purged()
    async with engine.begin() as connection:
        for table in reversed(metadata.sorted_tables):
            if table.name in _KEEP_ON_WIPE:
                continue
            result = await connection.execute(delete(table))
            if result.rowcount:
                purged.counts[table.name] = result.rowcount
    if engine.dialect.name == "sqlite":
        async with engine.connect() as connection:
            raw = await connection.execution_options(isolation_level="AUTOCOMMIT")
            await raw.exec_driver_sql("VACUUM")
            await raw.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    return purged
