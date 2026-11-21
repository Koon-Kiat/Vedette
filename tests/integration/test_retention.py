"""Retention: the scheduled purge, ``vedette purge`` and owner-only files."""

import asyncio
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from structlog.testing import capture_logs
from typer.testing import CliRunner

from vedette.cli import app
from vedette.pipeline.retention import RetentionWorker
from vedette.storage.migrate import run_migrations
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
from vedette.storage.retention import purge_all, purge_expired, restrict_permissions
from vedette.storage.store import Store

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
OLD_EVENT = NOW - timedelta(days=31)
NEW_EVENT = NOW - timedelta(days=29)
OLD_FINDING = NOW - timedelta(days=181)
NEW_FINDING = NOW - timedelta(days=179)


async def seed(store: Store) -> None:
    """Old and recent rows in every table the purge touches."""

    def event(event_id: str, ts: datetime, *, processed: bool = True) -> dict[str, Any]:
        return {
            "event_id": event_id,
            "profile_id": "abc123",
            "ts": ts,
            "fqdn": f"{event_id}.example",
            "root": f"{event_id}.example",
            "status": "default",
            "reasons": [],
            "source": "nextdns",
            "ingested_at": ts,
            "processed_at": ts if processed else None,
        }

    def finding(finding_id: int, last: datetime) -> dict[str, Any]:
        return {
            "id": finding_id,
            "dedupe_key": f"key-{finding_id}",
            "rule_id": "young-domain",
            "severity": "high",
            "profile_id": "abc123",
            "subject": None,
            "device_mode": False,
            "target": f"site{finding_id}.example",
            "first_ts": last,
            "last_ts": last,
            "event_count": 1,
            "evidence": {},
            "event_id": "x",
            "status": "benign",
            "created_at": last,
            "updated_at": last,
        }

    def analysis(finding_id: int) -> dict[str, Any]:
        return {
            "finding_id": finding_id,
            "summary": "s",
            "likely_cause": "c",
            "recommended_action": "a",
            "priority": "high",
            "group_key": "g",
            "confidence": 0.5,
            "source": "llm",
            "created_at": NOW,
        }

    def message(finding_id: int | None, created: datetime, key: str) -> dict[str, Any]:
        return {
            "kind": "alert" if finding_id else "health",
            "dedupe_key": key,
            "finding_id": finding_id,
            "title": "t",
            "body": "b",
            "priority": "high",
            "tags": [],
            "status": "sent",
            "attempts": 1,
            "next_attempt_at": created,
            "created_at": created,
        }

    async with store.engine.begin() as connection:
        await connection.execute(
            events.insert(),
            [
                event("old", OLD_EVENT),
                event("old-waiting", OLD_EVENT, processed=False),
                event("new", NEW_EVENT),
            ],
        )
        await connection.execute(
            findings.insert(), [finding(1, OLD_FINDING), finding(2, NEW_FINDING)]
        )
        await connection.execute(finding_analysis.insert(), [analysis(1), analysis(2)])
        await connection.execute(
            audit_log.insert(),
            [
                {
                    "at": NOW,
                    "actor": "cli",
                    "action": "mark_benign",
                    "finding_id": 1,
                    "detail": "d",
                },
                {
                    "at": NOW,
                    "actor": "cli",
                    "action": "mark_benign",
                    "finding_id": 2,
                    "detail": "d",
                },
            ],
        )
        await connection.execute(
            notifications.insert(),
            [
                message(1, NOW, "alert-1"),
                message(2, NOW, "alert-2"),
                message(None, OLD_FINDING, "health-old"),
                message(None, NEW_FINDING, "health-new"),
            ],
        )
        await connection.execute(
            digests.insert(),
            [
                {
                    "period_start": when - timedelta(days=1),
                    "period_end": when,
                    "generated_at": when,
                    "title": "t",
                    "body": "b",
                    "data": {},
                }
                for when in (OLD_FINDING, NEW_FINDING)
            ],
        )
        await connection.execute(
            llm_calls.insert(),
            [
                {
                    "started_at": when,
                    "duration_ms": 10,
                    "findings": 1,
                    "outcome": "ok",
                    "model": "m",
                }
                for when in (OLD_FINDING, NEW_FINDING)
            ],
        )
        await connection.execute(
            allowlist.insert(),
            [
                {
                    "root": "site1.example",
                    "profile_id": "abc123",
                    "device_id": None,
                    "finding_id": 1,
                    "created_at": NOW,
                    "created_by": "cli",
                }
            ],
        )


async def column(store: Store, table: Any, name: str) -> list[Any]:
    async with store.engine.connect() as connection:
        rows = await connection.execute(select(table.c[name]).order_by(table.c[name]))
        return [row[0] for row in rows]


async def test_the_purge_removes_only_what_is_past_retention(store: Store) -> None:
    await seed(store)

    purged = await purge_expired(store.engine, now=NOW, events_days=30, findings_days=180)

    assert await column(store, events, "event_id") == ["new", "old-waiting"]
    assert await column(store, findings, "id") == [2]
    assert await column(store, finding_analysis, "finding_id") == [2]
    assert await column(store, audit_log, "finding_id") == [2]
    assert await column(store, notifications, "dedupe_key") == ["alert-2", "health-new"]
    assert len(await column(store, digests, "id")) == 1
    assert len(await column(store, llm_calls, "id")) == 1
    assert purged.counts == {
        "audit_log": 1,
        "digests": 1,
        "events": 1,
        "finding_analysis": 1,
        "findings": 1,
        "llm_calls": 1,
        "notifications": 2,
    }


async def test_an_allowlist_entry_outlives_the_finding_that_made_it(store: Store) -> None:
    await seed(store)

    await purge_expired(store.engine, now=NOW, events_days=30, findings_days=180)

    async with store.engine.connect() as connection:
        (row,) = (await connection.execute(select(allowlist))).all()
    assert (row.root, row.finding_id) == ("site1.example", None)


async def test_a_second_purge_finds_nothing(store: Store) -> None:
    await seed(store)
    await purge_expired(store.engine, now=NOW, events_days=30, findings_days=180)

    again = await purge_expired(store.engine, now=NOW, events_days=30, findings_days=180)

    assert again.total == 0


async def test_purge_all_empties_every_table(store: Store) -> None:
    await seed(store)

    purged = await purge_all(store.engine)

    assert purged.total > 0
    async with store.engine.connect() as connection:
        for table in metadata.sorted_tables:
            count = (await connection.execute(select(func.count()).select_from(table))).scalar_one()
            assert count == 0, table.name


async def test_the_worker_logs_what_it_removed(store: Store) -> None:
    await seed(store)
    worker = RetentionWorker(store.engine, events_days=30, findings_days=180, clock=lambda: NOW)

    with capture_logs() as logs:
        removed = await worker.purge_once()

    assert removed == 8
    (entry,) = [e for e in logs if e["event"] == "retention_purged"]
    assert entry["rows"] == 8 and entry["events"] == 1


def test_the_database_is_made_owner_only(tmp_path: Path) -> None:
    folder = tmp_path / "data"
    folder.mkdir(mode=0o755)
    database = folder / "vedette.db"
    url = f"sqlite+aiosqlite:///{database}"
    run_migrations(url)
    database.chmod(0o644)
    folder.chmod(0o755)

    restrict_permissions(url)

    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


# --- vedette purge ----------------------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def cli_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'cli.db'}"
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')
    return url


def seeded(url: str) -> None:
    run_migrations(url)

    async def write() -> None:
        store = Store.open(url)
        try:
            await seed(store)
        finally:
            await store.close()

    asyncio.run(write())


def event_ids(url: str) -> list[Any]:
    async def read() -> list[Any]:
        store = Store.open(url)
        try:
            return await column(store, events, "event_id")
        finally:
            await store.close()

    return asyncio.run(read())


def test_purge_all_asks_first_and_can_be_declined(cli_database: str) -> None:
    seeded(cli_database)

    result = runner.invoke(app, ["purge", "--all"], input="n\n")

    assert result.exit_code == 1
    assert "Delete ALL local data" in result.output
    assert len(event_ids(cli_database)) == 3


def test_purge_all_with_yes_wipes_the_data(cli_database: str) -> None:
    seeded(cli_database)

    result = runner.invoke(app, ["purge", "--all", "--yes"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("Deleted ")
    assert event_ids(cli_database) == []


def test_purge_without_a_database_says_so(cli_database: str) -> None:
    result = runner.invoke(app, ["purge", "--yes"])

    assert result.exit_code == 0
    assert "No local data to purge." in result.output
