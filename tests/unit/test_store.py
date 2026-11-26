import contextlib
import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import QueuePool

from vedette.shared.models import Finding, Severity
from vedette.sources.base import DnsEvent
from vedette.sources.nextdns import parse_log_entry
from vedette.storage.migrate import run_migrations
from vedette.storage.models import metadata
from vedette.storage.store import Store

T0 = datetime(2026, 3, 15, 4, 0, 0, tzinfo=UTC)


def make_event(n: int, profile: str = "abc123") -> DnsEvent:
    return parse_log_entry(
        profile,
        {
            "timestamp": (T0 + timedelta(seconds=n)).isoformat(),
            "domain": f"host{n}.example",
            "root": "host.example",
            "status": "default",
            "protocol": "DNS-over-HTTPS",
            "clientIp": "198.51.100.7",
            "encrypted": True,
            "reasons": [{"id": "r", "name": "Reason"}],
            "device": {"id": "D1", "name": "Laptop"},
        },
    )


@pytest.fixture
def database_url(tmp_path: Path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"


@pytest.fixture
async def store(database_url: str) -> AsyncIterator[Store]:
    run_migrations(database_url)
    opened = Store.open(database_url)
    yield opened
    await opened.close()


def test_migrations_create_exactly_the_tables_the_models_describe(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'm.db'}"

    run_migrations(url)

    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    inspector = inspect(engine)
    for table in metadata.sorted_tables:
        migrated = {column["name"] for column in inspector.get_columns(table.name)}
        assert migrated == {column.name for column in table.columns}, table.name
    engine.dispose()


async def test_the_pool_serves_every_worker_and_the_dashboard_at_once(database_url: str) -> None:
    run_migrations(database_url)
    store = Store.open(database_url)
    try:
        async with contextlib.AsyncExitStack() as stack:
            held = [await stack.enter_async_context(store.engine.connect()) for _ in range(25)]
            assert len(held) == 25
        pool = store.engine.pool
        assert isinstance(pool, QueuePool) and pool.size() == 15
    finally:
        await store.close()


async def test_timestamps_come_back_timezone_aware(store: Store) -> None:
    saved = make_event(1)
    await store.save_events([saved])

    (stored,) = await store.list_events("abc123")

    assert stored.ts.utcoffset() == timedelta(0)
    assert stored.ts == saved.ts


def test_migrations_can_run_twice(database_url: str) -> None:
    run_migrations(database_url)
    run_migrations(database_url)


async def test_database_uses_write_ahead_logging(store: Store, tmp_path: Path) -> None:
    await store.save_events([make_event(1)])

    connection = sqlite3.connect(tmp_path / "vedette.db")
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)
    finally:
        connection.close()


async def test_saving_events_reports_how_many_were_new(store: Store) -> None:
    assert await store.save_events([make_event(1), make_event(2)]) == 2
    assert await store.count_events("abc123") == 2


async def test_saving_the_same_event_twice_stores_it_once(store: Store) -> None:
    await store.save_events([make_event(1), make_event(2)])

    assert await store.save_events([make_event(2), make_event(3)]) == 1
    assert await store.count_events("abc123") == 3


async def test_duplicates_inside_one_batch_are_stored_once(store: Store) -> None:
    assert await store.save_events([make_event(1), make_event(1)]) == 1


async def test_saving_nothing_is_a_no_op(store: Store) -> None:
    assert await store.save_events([]) == 0


async def test_a_full_page_of_a_thousand_events_is_stored(store: Store) -> None:
    assert await store.save_events([make_event(n) for n in range(1000)]) == 1000


async def test_stored_events_round_trip_unchanged(store: Store) -> None:
    event = make_event(7)
    await store.save_events([event])

    assert await store.list_events("abc123") == [event]


async def test_events_are_listed_oldest_first_per_profile(store: Store) -> None:
    await store.save_events([make_event(3), make_event(1), make_event(2, profile="other")])

    assert [e.fqdn for e in await store.list_events("abc123")] == ["host1.example", "host3.example"]


async def test_state_is_absent_before_anything_is_collected(store: Store) -> None:
    assert await store.get_state("abc123") is None


async def test_backfill_pages_do_not_move_the_resume_point(store: Store) -> None:
    await store.save_events([make_event(5)])

    assert await store.get_state("abc123") is None


async def test_completing_a_backfill_records_cursor_and_resume_point(store: Store) -> None:
    await store.complete_backfill("abc123", stream_cursor="s10", synced_through=T0)

    state = await store.get_state("abc123")
    assert state is not None
    assert state.stream_cursor == "s10"
    assert state.synced_through == T0
    assert state.backfill_completed_at is not None


async def test_stream_events_and_cursor_are_committed_together(store: Store) -> None:
    await store.complete_backfill("abc123", stream_cursor="s10", synced_through=T0)

    inserted = await store.save_stream_events("abc123", [make_event(11)], stream_cursor="s11")

    state = await store.get_state("abc123")
    assert inserted == 1
    assert state is not None
    assert state.stream_cursor == "s11"
    assert state.synced_through == T0 + timedelta(seconds=11)
    assert await store.count_events("abc123") == 1


async def test_resume_point_never_moves_backwards(store: Store) -> None:
    await store.complete_backfill("abc123", stream_cursor="s10", synced_through=T0)
    await store.save_stream_events("abc123", [make_event(30)], stream_cursor="s11")

    await store.save_stream_events("abc123", [make_event(20)], stream_cursor="s12")

    state = await store.get_state("abc123")
    assert state is not None
    assert state.stream_cursor == "s12"
    assert state.synced_through == T0 + timedelta(seconds=30)


async def test_clearing_the_cursor_keeps_the_resume_point(store: Store) -> None:
    await store.complete_backfill("abc123", stream_cursor="s10", synced_through=T0)

    await store.clear_stream_cursor("abc123")

    state = await store.get_state("abc123")
    assert state is not None
    assert state.stream_cursor is None
    assert state.synced_through == T0
    assert state.backfill_completed_at is not None


async def test_state_is_kept_per_profile(store: Store) -> None:
    await store.complete_backfill("abc123", stream_cursor="a", synced_through=T0)
    await store.complete_backfill("zzz999", stream_cursor="z", synced_through=T0)

    first = await store.get_state("abc123")
    second = await store.get_state("zzz999")
    assert first is not None
    assert second is not None
    assert (first.stream_cursor, second.stream_cursor) == ("a", "z")


async def test_data_survives_closing_and_reopening(database_url: str) -> None:
    run_migrations(database_url)
    first = Store.open(database_url)
    await first.save_events([make_event(1)])
    await first.complete_backfill("abc123", stream_cursor="s1", synced_through=T0)
    await first.close()

    second = Store.open(database_url)
    try:
        state = await second.get_state("abc123")
        assert await second.count_events("abc123") == 1
        assert state is not None
        assert state.stream_cursor == "s1"
    finally:
        await second.close()


# --- processing and findings -----------------------------------------------------


def make_finding(
    n: int, *, rule: str = "young-domain", severity: str = "high", key: str | None = None
) -> Finding:
    item = make_event(n)
    return Finding(
        rule_id=rule,
        severity=Severity(severity),
        profile_id=item.profile_id,
        subject=item.device_id,
        device_mode=True,
        target="host.example",
        ts=item.ts,
        dedupe_key=key or f"{rule}|{n}",
        evidence={"fqdn": item.fqdn, "n": n},
        event_id=item.event_id,
    )


async def test_unprocessed_events_come_back_oldest_first_up_to_the_limit(store: Store) -> None:
    await store.save_events(
        [make_event(3), make_event(1), make_event(2), make_event(9, profile="other")]
    )

    batch = await store.fetch_unprocessed("abc123", limit=2)

    assert [item.fqdn for item in batch] == ["host1.example", "host2.example"]
    assert await store.count_unprocessed("abc123") == 3


async def test_committing_a_batch_marks_events_processed_and_stores_findings(store: Store) -> None:
    await store.save_events([make_event(1), make_event(2), make_event(3)])
    batch = await store.fetch_unprocessed("abc123", limit=2)

    await store.commit_processed([item.event_id for item in batch], [make_finding(1)])

    assert [item.fqdn for item in await store.fetch_unprocessed("abc123", limit=10)] == [
        "host3.example"
    ]
    (stored,) = await store.list_findings()
    assert (stored.rule_id, stored.severity.value, stored.event_count) == (
        "young-domain",
        "high",
        1,
    )
    assert stored.evidence == {"fqdn": "host1.example", "n": 1}
    assert stored.subject == "D1"
    assert stored.status == "open"


async def test_findings_with_the_same_key_merge_into_one_row(store: Store) -> None:
    await store.commit_processed([], [make_finding(5, key="k"), make_finding(1, key="k")])
    await store.commit_processed([], [make_finding(9, key="k")])

    (stored,) = await store.list_findings()
    assert stored.event_count == 3
    assert stored.first_ts == T0 + timedelta(seconds=1)
    assert stored.last_ts == T0 + timedelta(seconds=9)
    assert stored.evidence["n"] == 5, "the evidence of the first sighting is kept"


async def test_findings_can_be_filtered_and_are_newest_first(store: Store) -> None:
    await store.commit_processed(
        [],
        [
            make_finding(1, rule="volume-spike", severity="low"),
            make_finding(2, rule="young-domain", severity="high"),
            make_finding(3, rule="threat-intel-allowed", severity="critical"),
        ],
    )

    everything = await store.list_findings()
    serious = await store.list_findings(min_severity=Severity.HIGH)
    one_rule = await store.list_findings(rule_id="volume-spike")
    limited = await store.list_findings(limit=1)
    elsewhere = await store.list_findings(profile_id="other")

    assert [f.rule_id for f in everything] == [
        "threat-intel-allowed",
        "young-domain",
        "volume-spike",
    ]
    assert [f.rule_id for f in serious] == ["threat-intel-allowed", "young-domain"]
    assert [f.rule_id for f in one_rule] == ["volume-spike"]
    assert [f.rule_id for f in limited] == ["threat-intel-allowed"]
    assert elsewhere == []


async def test_processed_events_can_be_replayed_in_order_for_warm_up(store: Store) -> None:
    items = [make_event(n) for n in range(1, 8)]
    await store.save_events(items)
    await store.commit_processed([item.event_id for item in items[:5]], [])

    replayed = [
        row
        async for row in store.iter_processed_fields(
            "abc123", since=T0 + timedelta(seconds=2), chunk=2
        )
    ]

    assert [row[3] for row in replayed] == [
        "host2.example",
        "host3.example",
        "host4.example",
        "host5.example",
    ]
    assert replayed[0] == (
        "abc123",
        "D1",
        T0 + timedelta(seconds=2),
        "host2.example",
        "host.example",
        "default",
    )


async def test_earliest_event_time_is_reported_per_profile(store: Store) -> None:
    assert await store.earliest_event_ts("abc123") is None

    await store.save_events([make_event(5), make_event(2)])

    assert await store.earliest_event_ts("abc123") == T0 + timedelta(seconds=2)
