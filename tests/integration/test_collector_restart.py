"""Collector behaviour across kills, restarts and upstream failures.

The acceptance test for the collector: killing and restarting it must leave
zero gaps and zero duplicates.
"""

import asyncio
import contextlib
from datetime import timedelta

import httpx
from structlog.testing import capture_logs

from sentinel.pipeline.collector import ProfileCollector
from sentinel.sources.nextdns import NextDnsSource, parse_log_entry
from sentinel.storage.store import Store
from tests.integration.conftest import SleepRecorder, wait_until
from tests.integration.fake_nextdns import T0, FakeNextDns

NOW = T0 + timedelta(hours=1)


def make_collector(source: NextDnsSource, store: Store, sleeps: SleepRecorder) -> ProfileCollector:
    return ProfileCollector(
        "abc123",
        source,
        store,
        backfill_days=7,
        clock=lambda: NOW,
        sleep=sleeps,
        rng=lambda: 1.0,
    )


async def run_until(
    collector: ProfileCollector, store: Store, count: int, cursor: str | None = None
) -> None:
    """Run the collector until ``count`` events are stored, then kill it.

    With ``cursor``, also wait until that stream cursor has been committed, so
    the kill lands at a known point.
    """
    task = asyncio.create_task(collector.run())
    try:

        async def reached() -> bool:
            if await store.count_events("abc123") < count:
                return False
            if cursor is None:
                return True
            state = await store.get_state("abc123")
            return state is not None and state.stream_cursor == cursor

        await wait_until(reached)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def assert_no_gaps_and_no_duplicates(server: FakeNextDns, store: Store) -> None:
    stored = await store.list_events("abc123")
    expected = [parse_log_entry("abc123", entry) for entry in server.entries]
    assert [event.event_id for event in stored] == [event.event_id for event in expected]
    assert await store.count_events("abc123") == len(server.entries)


async def test_first_run_backfills_history_then_follows_the_live_stream(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(35)
    server.hold_stream_open = True
    task = asyncio.create_task(make_collector(source, store, sleeps).run())
    try:

        async def backfilled() -> bool:
            return await store.count_events("abc123") == 35

        await wait_until(backfilled)
        server.add_entries(5)

        async def caught_up() -> bool:
            return await store.count_events("abc123") == 40

        await wait_until(caught_up)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    await assert_no_gaps_and_no_duplicates(server, store)
    state = await store.get_state("abc123")
    assert state is not None
    assert state.stream_cursor == "s40"


async def test_kill_mid_stream_and_restart_leaves_no_gaps_and_no_duplicates(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(30)
    server.hold_stream_open = True
    await run_until(make_collector(source, store, sleeps), store, 30, "s30")
    server.add_entries(4)
    await run_until(make_collector(source, store, sleeps), store, 34, "s34")
    state_at_kill = await store.get_state("abc123")
    assert state_at_kill is not None
    log_requests_before = len(server.log_requests)
    stream_requests_before = len(server.stream_requests)

    server.add_entries(10)  # arrives while the collector is down
    await run_until(make_collector(source, store, sleeps), store, 44, "s44")

    await assert_no_gaps_and_no_duplicates(server, store)
    assert len(server.log_requests) == log_requests_before, "restart must not re-run the backfill"
    resumed_with = server.stream_requests[stream_requests_before].url.params["id"]
    assert resumed_with == state_at_kill.stream_cursor == "s34"


async def test_kill_mid_backfill_and_restart_leaves_no_gaps_and_no_duplicates(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(45)
    server.block_logs_after = 3  # the fourth /logs request hangs
    await run_until(make_collector(source, store, sleeps), store, 20)
    interrupted = await store.get_state("abc123")
    assert interrupted is None or interrupted.stream_cursor is None
    assert await store.count_events("abc123") < 45

    server.block_logs_after = None
    server.add_entries(5)  # arrives while the collector is down
    await run_until(make_collector(source, store, sleeps), store, 50, "s50")

    await assert_no_gaps_and_no_duplicates(server, store)
    state = await store.get_state("abc123")
    assert state is not None
    assert state.backfill_completed_at is not None


async def test_rejected_stream_cursor_falls_back_to_logs_from_the_resume_point(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(30)
    server.hold_stream_open = True
    await run_until(make_collector(source, store, sleeps), store, 30, "s30")
    server.add_entries(3)
    await run_until(make_collector(source, store, sleeps), store, 33, "s33")
    state = await store.get_state("abc123")
    assert state is not None
    assert state.stream_cursor == "s33"
    assert state.synced_through is not None
    log_requests_before = len(server.log_requests)

    server.rejected_stream_ids.add("s33")
    server.add_entries(12)  # arrives while the collector is down
    with capture_logs() as logs:
        await run_until(make_collector(source, store, sleeps), store, 45, "s45")

    await assert_no_gaps_and_no_duplicates(server, store)
    assert "collector_stream_cursor_rejected" in [entry["event"] for entry in logs]
    gap_fill = server.log_requests[log_requests_before + 1]
    assert gap_fill.url.params["from"] == (state.synced_through - timedelta(minutes=5)).isoformat()
    recovered = await store.get_state("abc123")
    assert recovered is not None
    assert recovered.stream_cursor == "s45"


async def test_stream_closed_by_the_server_is_reopened_from_the_last_cursor(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(12)
    task = asyncio.create_task(make_collector(source, store, sleeps).run())
    try:

        async def reconnected() -> bool:
            return len(server.stream_requests) >= 3

        await wait_until(reconnected)
        server.add_entries(3)

        async def caught_up() -> bool:
            return await store.count_events("abc123") == 15

        await wait_until(caught_up)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    await assert_no_gaps_and_no_duplicates(server, store)
    assert server.stream_requests[0].url.params["id"] == "s12"
    assert server.stream_requests[1].url.params["id"] == "s12"
    assert sleeps.delays, "an idle stream must not be reopened in a hot loop"


async def test_upstream_outage_during_streaming_is_survived(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(10)
    server.stream_failures.extend(
        [
            httpx.Response(503),
            httpx.ConnectError("down"),
            httpx.Response(429, headers={"Retry-After": "7"}),
        ]
    )
    server.hold_stream_open = True
    task = asyncio.create_task(make_collector(source, store, sleeps).run())
    try:

        async def streaming() -> bool:
            return len(server.stream_requests) >= 4

        await wait_until(streaming)
        server.add_entries(5)

        async def caught_up() -> bool:
            return await store.count_events("abc123") == 15

        await wait_until(caught_up)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    await assert_no_gaps_and_no_duplicates(server, store)
    # Pause after the backfill, growing backoff for two failures, then Retry-After.
    assert sleeps.delays[:4] == [1.0, 2.0, 4.0, 7.0]


async def test_upstream_outage_during_backfill_is_survived(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(25)
    server.log_failures.extend([httpx.Response(503)] * 8)  # more than one request's retries
    server.hold_stream_open = True

    await run_until(make_collector(source, store, sleeps), store, 25)

    await assert_no_gaps_and_no_duplicates(server, store)


async def test_rejected_api_key_is_logged_and_retried_slowly_without_crashing(
    server: FakeNextDns, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(5)
    source = NextDnsSource("wrong-key-value", sleep=sleeps)
    task = asyncio.create_task(make_collector(source, store, sleeps).run())
    try:
        with capture_logs() as logs:

            async def retried() -> bool:
                return len(server.log_requests) >= 2

            await wait_until(retried)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await source.aclose()

    assert "collector_auth_failed" in [entry["event"] for entry in logs]
    assert 300.0 in sleeps.delays
    assert await store.count_events("abc123") == 0
    assert "wrong-key-value" not in str(logs)
