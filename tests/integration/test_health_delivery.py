"""Alert delivery as a health check, and the heartbeat that proves Vedette is alive."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from structlog.testing import capture_logs

from tests.integration.test_health import ROUTER, SGT, Clock, Disk, FakeProbe, add_event
from vedette.config import HealthConfig
from vedette.health.heartbeat import Heartbeat
from vedette.health.monitor import HealthMonitor
from vedette.health.state import HealthState
from vedette.shared.models import OutgoingMessage, Severity
from vedette.storage.health import HealthStore
from vedette.storage.notifications import NotificationStore
from vedette.storage.store import Store

T0 = datetime(2026, 3, 15, 4, 0, tzinfo=UTC)
PING = "https://hc-ping.com/0f0c1d2e-not-a-real-check"
REJECTED = "Discord rejected the credentials"


def message(title: str = "HIGH: Burst of blocked queries, router (router)") -> OutgoingMessage:
    return OutgoingMessage(title=title, body="body", priority=Severity.HIGH, tags=())


def monitor_for(store: Store, tmp_path: Path, clock: Clock, channel: str) -> HealthMonitor:
    return HealthMonitor(
        store=store,
        state=HealthState(),
        health_store=HealthStore(store.engine),
        notifications=NotificationStore(store.engine),
        profiles=[ROUTER],
        config=HealthConfig(),
        ollama=FakeProbe(),
        data_path=tmp_path,
        tz=SGT,
        clock=clock,
        disk_usage=Disk(),
        started_at=T0 - timedelta(days=1),
        channel=channel,
    )


async def queued(outbox: NotificationStore, n: int = 0) -> int:
    return await outbox.enqueue(
        kind="alert", key=f"alert|{n}", message=message(), now=T0 - timedelta(minutes=30)
    )


def delivery(checks: list[Any]) -> Any:
    return next(check for check in checks if check.key == "delivery")


# --- what the outbox says about delivery --------------------------------------------------


async def test_the_newest_finished_message_tells_whether_delivery_works(store: Store) -> None:
    outbox = NotificationStore(store.engine)
    assert (await outbox.delivery_status()).last_outcome is None

    failed = await queued(outbox, 1)
    await outbox.finish(failed, status="failed", reason=REJECTED, attempts=1)
    status = await outbox.delivery_status()
    assert (status.last_outcome, status.last_reason) == ("failed", REJECTED)

    sent = await queued(outbox, 2)
    await outbox.mark_sent(sent, now=T0, attempts=1)
    assert (await outbox.delivery_status()).last_outcome == "sent"


async def test_skipped_messages_are_not_a_delivery_outcome(store: Store) -> None:
    outbox = NotificationStore(store.engine)
    sent = await queued(outbox, 1)
    await outbox.mark_sent(sent, now=T0, attempts=1)
    skipped = await queued(outbox, 2)
    await outbox.finish(skipped, status="skipped", reason="cooldown")

    assert (await outbox.delivery_status()).last_outcome == "sent"


async def test_a_message_held_for_quiet_hours_is_not_counted_as_retrying(store: Store) -> None:
    outbox = NotificationStore(store.engine)
    held = await queued(outbox)
    await outbox.defer(held, until=T0 + timedelta(hours=3), reason="quiet_hours")

    assert (await outbox.delivery_status()).retry_attempts == 0


async def test_the_most_retried_pending_message_is_reported(store: Store) -> None:
    outbox = NotificationStore(store.engine)
    first, second = await queued(outbox, 1), await queued(outbox, 2)
    await outbox.reschedule(first, at=T0, attempts=1, reason="ntfy answered HTTP 502")
    await outbox.reschedule(second, at=T0, attempts=3, reason="ntfy answered HTTP 503")

    status = await outbox.delivery_status()

    assert (status.retry_attempts, status.retry_reason) == (3, "ntfy answered HTTP 503")


# --- the health check ---------------------------------------------------------------------


async def test_with_no_channel_delivery_is_not_a_problem(store: Store, tmp_path: Path) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    monitor = monitor_for(store, tmp_path, Clock(T0), channel="none")

    check = delivery(await monitor.run_once())

    assert (check.label, check.ok) == ("Alert delivery", True)
    assert check.detail == "No channel set: alerts are kept, not sent"


async def test_a_failed_delivery_is_a_problem_until_a_message_gets_through(
    store: Store, tmp_path: Path
) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    outbox = NotificationStore(store.engine)
    failed = await queued(outbox, 1)
    await outbox.finish(failed, status="failed", reason=REJECTED, attempts=1)
    clock = Clock(T0)
    monitor = monitor_for(store, tmp_path, clock, channel="discord")

    check = delivery(await monitor.run_once())
    assert not check.ok
    assert check.detail == "Alerts are not reaching Discord: Discord rejected the credentials"

    sent = await queued(outbox, 2)
    await outbox.mark_sent(sent, now=T0, attempts=1)
    clock.now += timedelta(minutes=1)
    assert delivery(await monitor.run_once()).ok


async def test_retrying_is_fine_until_three_tries_have_failed(store: Store, tmp_path: Path) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    outbox = NotificationStore(store.engine)
    item = await queued(outbox)
    monitor = monitor_for(store, tmp_path, Clock(T0), channel="ntfy")

    await outbox.reschedule(item, at=T0, attempts=2, reason="ntfy answered HTTP 502")
    check = delivery(await monitor.run_once())
    assert (check.ok, check.detail) == (True, "Retrying: ntfy answered HTTP 502")

    await outbox.reschedule(item, at=T0, attempts=3, reason="ntfy answered HTTP 502")
    check = delivery(await monitor.run_once())
    assert not check.ok
    assert check.detail == "Alerts are not reaching ntfy: ntfy answered HTTP 502 (3 tries)"


# --- the heartbeat ------------------------------------------------------------------------


def heartbeat(monitor: HealthMonitor, clock: Clock, client: httpx.AsyncClient) -> Heartbeat:
    return Heartbeat(monitor, PING, client=client, interval=timedelta(minutes=5), clock=clock)


@respx.mock
async def test_the_heartbeat_pings_while_checks_run_and_alerts_get_out(
    store: Store, tmp_path: Path
) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    clock = Clock(T0)
    monitor = monitor_for(store, tmp_path, clock, channel="discord")
    await monitor.run_once()
    route = respx.get(PING).mock(return_value=httpx.Response(200, text="OK"))

    async with httpx.AsyncClient() as client:
        assert await heartbeat(monitor, clock, client).beat_once() is True

    assert route.call_count == 1


@respx.mock
async def test_the_heartbeat_is_withheld_while_alerts_cannot_get_out(
    store: Store, tmp_path: Path
) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    outbox = NotificationStore(store.engine)
    failed = await queued(outbox)
    await outbox.finish(failed, status="failed", reason=REJECTED, attempts=1)
    clock = Clock(T0)
    monitor = monitor_for(store, tmp_path, clock, channel="discord")
    await monitor.run_once()
    route = respx.get(PING).mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        with capture_logs() as logs:
            assert await heartbeat(monitor, clock, client).beat_once() is False

    assert route.call_count == 0
    assert any(entry["event"] == "heartbeat_withheld" for entry in logs)


@respx.mock
async def test_the_heartbeat_waits_for_checks_and_stops_when_they_stall(
    store: Store, tmp_path: Path
) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    clock = Clock(T0)
    monitor = monitor_for(store, tmp_path, clock, channel="none")
    route = respx.get(PING).mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        beat = heartbeat(monitor, clock, client)
        assert await beat.beat_once() is False, "no check has run yet"
        await monitor.run_once()
        assert await beat.beat_once() is True
        clock.now += timedelta(minutes=10)  # checks every minute; none for ten
        assert await beat.beat_once() is False

    assert route.call_count == 1


@respx.mock
async def test_a_failed_ping_is_logged_without_the_url(store: Store, tmp_path: Path) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    clock = Clock(T0)
    monitor = monitor_for(store, tmp_path, clock, channel="none")
    await monitor.run_once()
    respx.get(PING).mock(side_effect=httpx.ConnectError("no route"))

    async with httpx.AsyncClient() as client:
        with capture_logs() as logs:
            assert await heartbeat(monitor, clock, client).beat_once() is False

    failed = [entry for entry in logs if entry["event"] == "heartbeat_failed"]
    assert failed and all(PING not in str(entry) for entry in logs)


@respx.mock
async def test_the_heartbeat_repeats_on_its_interval(store: Store, tmp_path: Path) -> None:
    await add_event(store, T0 - timedelta(minutes=5))
    clock = Clock(T0)
    monitor = monitor_for(store, tmp_path, clock, channel="none")
    await monitor.run_once()
    route = respx.get(PING).mock(return_value=httpx.Response(200))
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)
        if len(waits) == 3:
            raise RuntimeError("stop")

    async with httpx.AsyncClient() as client:
        beat = Heartbeat(
            monitor, PING, client=client, interval=timedelta(minutes=5), clock=clock, sleep=sleep
        )
        with pytest.raises(RuntimeError, match="stop"):
            await beat.run()

    assert waits == [300.0, 300.0, 300.0]
    assert route.call_count == 3
