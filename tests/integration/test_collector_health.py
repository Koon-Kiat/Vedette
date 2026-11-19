"""The collector tells the health monitor whether NextDNS is reachable."""

import asyncio
import contextlib
from datetime import timedelta

import httpx
import pytest
from structlog.testing import capture_logs

from sentinel.health.state import HealthState
from sentinel.pipeline.collector import ProfileCollector
from sentinel.sources.base import SourceUnavailable, StreamIdle
from sentinel.sources.nextdns import NextDnsSource
from sentinel.storage.store import Store
from tests.integration.conftest import SleepRecorder, wait_until
from tests.integration.fake_nextdns import T0, FakeNextDns

NOW = T0 + timedelta(hours=1)


def collector(
    source: NextDnsSource, store: Store, sleeps: SleepRecorder, state: HealthState
) -> ProfileCollector:
    return ProfileCollector(
        "abc123",
        source,
        store,
        backfill_days=7,
        clock=lambda: NOW,
        sleep=sleeps,
        rng=lambda: 1.0,
        health=state,
    )


async def run_while(worker: ProfileCollector, done: object) -> None:
    task = asyncio.create_task(worker.run())
    try:
        await wait_until(done)  # type: ignore[arg-type]
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def test_an_open_stream_clears_an_earlier_failure(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(5)
    server.hold_stream_open = True
    state = HealthState()
    state.source_failed("abc123", "earlier trouble", now=NOW - timedelta(hours=1))

    async def streaming() -> bool:
        return len(server.stream_requests) >= 1 and state.failing_since("abc123") is None

    await run_while(collector(source, store, sleeps, state), streaming)


async def test_failures_are_reported_with_their_reason(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(5)
    server.stream_failures.extend([httpx.Response(503)] * 5)
    state = HealthState()

    async def failing() -> bool:
        return len(server.stream_requests) >= 2

    await run_while(collector(source, store, sleeps, state), failing)

    failing_since = state.failing_since("abc123")
    assert failing_since is not None
    assert failing_since == (NOW, "NextDNS answered HTTP 503")


async def test_a_quiet_stream_timing_out_is_not_an_error(
    server: FakeNextDns, source: NextDnsSource, store: Store, sleeps: SleepRecorder
) -> None:
    server.add_entries(3)
    server.idle_after = 0
    state = HealthState()

    with capture_logs() as logs:

        async def reconnected() -> bool:
            return len(server.stream_requests) >= 3

        await run_while(collector(source, store, sleeps, state), reconnected)

    events = [entry["event"] for entry in logs]
    assert "collector_stream_idle" in events
    assert "collector_source_unavailable" not in events
    assert state.failing_since("abc123") is None


async def test_the_source_reports_idleness_only_after_the_stream_opened(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.add_entries(2)
    server.idle_after = 1
    opened: list[bool] = []

    with pytest.raises(StreamIdle):
        _ = [
            item
            async for item in source.stream("abc123", "s0", on_open=lambda: opened.append(True))
        ]

    assert opened == [True]


async def test_a_timeout_before_the_stream_opens_is_a_real_failure(
    server: FakeNextDns, source: NextDnsSource
) -> None:
    server.stream_failures.append(httpx.ConnectTimeout("no route"))
    opened: list[bool] = []

    with pytest.raises(SourceUnavailable):
        _ = [
            item
            async for item in source.stream("abc123", "s0", on_open=lambda: opened.append(True))
        ]

    assert opened == []
