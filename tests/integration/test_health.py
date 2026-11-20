"""Health monitoring: each check, alerts on change, and the /healthz endpoint."""

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx

from sentinel.config import HealthConfig, ProfileConfig
from sentinel.health.monitor import HealthMonitor, OllamaProbe
from sentinel.health.server import start_health_server
from sentinel.health.state import HealthState
from sentinel.sources.nextdns import parse_log_entry
from sentinel.storage.health import HealthStore
from sentinel.storage.notifications import NotificationStore
from sentinel.storage.store import Store

SGT = ZoneInfo("Asia/Singapore")
T0 = datetime(2026, 3, 15, 4, 0, tzinfo=UTC)  # 12:00 in Singapore
ROUTER = ProfileConfig(id="abc123", label="router")


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class FakeProbe:
    def __init__(self) -> None:
        self.problem: str | None = None

    async def check(self) -> str | None:
        return self.problem


class Usage(NamedTuple):
    total: int
    used: int
    free: int


class Disk:
    def __init__(self) -> None:
        self.used_pct = 40

    def __call__(self, path: Path) -> Usage:
        return Usage(100 * 2**30, self.used_pct * 2**30, (100 - self.used_pct) * 2**30)


async def add_event(store: Store, at: datetime, profile: str = "abc123", n: int = 0) -> None:
    await store.save_events(
        [
            parse_log_entry(
                profile,
                {"timestamp": at.isoformat(), "domain": f"h{n}.site.example", "status": "default"},
            )
        ]
    )


class Kit(NamedTuple):
    monitor: HealthMonitor
    clock: Clock
    state: HealthState
    probe: FakeProbe
    disk: Disk
    outbox: NotificationStore


@pytest.fixture
def kit_factory(store: Store, tmp_path: Path) -> Any:
    def make(
        profiles: list[ProfileConfig] | None = None,
        started_at: datetime = T0 - timedelta(days=1),
        **config: Any,
    ) -> Kit:
        clock, state, probe, disk = Clock(), HealthState(), FakeProbe(), Disk()
        outbox = NotificationStore(store.engine)
        monitor = HealthMonitor(
            store=store,
            state=state,
            health_store=HealthStore(store.engine),
            notifications=outbox,
            profiles=profiles or [ROUTER],
            config=HealthConfig(**config),
            ollama=probe,
            data_path=tmp_path,
            tz=SGT,
            clock=clock,
            disk_usage=disk,
            started_at=started_at,
        )
        return Kit(monitor, clock, state, probe, disk, outbox)

    return make


def by_key(checks: list[Any]) -> dict[str, Any]:
    return {check.key: check for check in checks}


async def health_messages(outbox: NotificationStore) -> list[str]:
    return [item.title for item in reversed(await outbox.recent(limit=50)) if item.kind == "health"]


# --- the checks ---------------------------------------------------------------------------


async def test_a_healthy_system_reports_every_check_ok_in_a_fixed_order(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory()
    await add_event(store, T0 - timedelta(minutes=5))

    checks = await kit.monitor.run_once()

    assert [(c.key, c.label, c.ok) for c in checks] == [
        ("events:abc123", "Events from router", True),
        ("api:abc123", "NextDNS API (router)", True),
        ("ollama", "Local model", True),
        ("backlog", "Processing backlog", True),
        ("disk", "Disk space", True),
    ]
    assert [row.key for row in await HealthStore(store.engine).read()] == [c.key for c in checks]
    assert await health_messages(kit.outbox) == []


async def test_silence_beyond_the_window_raises_one_alert_and_one_recovery(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory(stale_after_minutes=120)
    await add_event(store, T0 - timedelta(hours=3))

    first = by_key(await kit.monitor.run_once())["events:abc123"]
    kit.clock.now += timedelta(minutes=1)
    await kit.monitor.run_once()
    await add_event(store, kit.clock.now, n=1)
    kit.clock.now += timedelta(minutes=1)
    recovered = by_key(await kit.monitor.run_once())["events:abc123"]
    assert len(await health_messages(kit.outbox)) == 1, "one OK check is not yet a recovery"
    kit.clock.now += timedelta(minutes=1)
    await kit.monitor.run_once()

    assert (first.ok, first.detail) == (False, "No events from router for 3 h 0 min")
    assert recovered.ok
    assert await health_messages(kit.outbox) == [
        "Health problem: No events from router for 3 h 0 min",
        "Resolved: No events from router for 3 h 0 min",
    ]


async def test_silence_inside_the_window_is_fine(store: Store, kit_factory: Any) -> None:
    kit = kit_factory(stale_after_minutes=120)
    await add_event(store, T0 - timedelta(minutes=119))

    assert by_key(await kit.monitor.run_once())["events:abc123"].ok


async def test_a_profiles_quiet_hours_do_not_count_as_silence(
    store: Store, kit_factory: Any
) -> None:
    laptop = ProfileConfig(id="abc123", label="laptop", quiet_hours="23:00-07:00")
    kit = kit_factory([laptop], stale_after_minutes=120)
    await add_event(store, datetime(2026, 3, 15, 22, 30, tzinfo=SGT))

    kit.clock.now = datetime(2026, 3, 16, 7, 30, tzinfo=SGT).astimezone(UTC)
    assert by_key(await kit.monitor.run_once())["events:abc123"].ok

    kit.clock.now = datetime(2026, 3, 16, 9, 31, tzinfo=SGT).astimezone(UTC)
    assert not by_key(await kit.monitor.run_once())["events:abc123"].ok


async def test_a_profile_can_switch_the_silence_check_off(store: Store, kit_factory: Any) -> None:
    laptop = ProfileConfig(id="abc123", label="laptop", stale_after_minutes=0)
    kit = kit_factory([laptop])
    await add_event(store, T0 - timedelta(days=5))

    check = by_key(await kit.monitor.run_once())["events:abc123"]

    assert (check.ok, check.detail) == (True, "Check switched off for this profile")


async def test_a_profile_with_no_events_at_all_counts_from_service_start(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory(stale_after_minutes=120)

    check = by_key(await kit.monitor.run_once())["events:abc123"]

    assert (check.ok, check.detail) == (False, "No events received from router yet")


# --- after a start-up --------------------------------------------------------------------


async def test_silence_from_while_sentinel_was_off_is_not_reported(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory(started_at=T0)
    await add_event(store, T0 - timedelta(hours=13))  # stored before Sentinel stopped

    check = by_key(await kit.monitor.run_once())["events:abc123"]
    assert (check.ok, check.detail, check.pending) == (True, "Catching up after start-up", True)

    await add_event(store, T0 + timedelta(minutes=1), n=1)  # the collector catches up
    kit.state.caught_up("abc123")
    for minutes in (1, 2, 3):
        kit.clock.now = T0 + timedelta(minutes=minutes)
        check = by_key(await kit.monitor.run_once())["events:abc123"]
        assert (check.ok, check.detail) == (True, "OK")

    assert await health_messages(kit.outbox) == []


async def test_a_profile_still_silent_after_catching_up_is_reported(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory(started_at=T0)
    await add_event(store, T0 - timedelta(hours=13))
    await kit.monitor.run_once()

    kit.state.caught_up("abc123")  # caught up, and nothing new arrived
    kit.clock.now = T0 + timedelta(minutes=1)
    await kit.monitor.run_once()

    assert await health_messages(kit.outbox) == [
        "Health problem: No events from router for 13 h 1 min"
    ]


async def test_a_collector_that_never_catches_up_is_judged_after_the_grace(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory(started_at=T0)
    await add_event(store, T0 - timedelta(hours=13))

    kit.clock.now = T0 + timedelta(minutes=9)
    assert by_key(await kit.monitor.run_once())["events:abc123"].pending
    kit.clock.now = T0 + timedelta(minutes=10)
    assert not by_key(await kit.monitor.run_once())["events:abc123"].ok

    assert await health_messages(kit.outbox) == [
        "Health problem: No events from router for 13 h 10 min"
    ]


async def test_a_problem_told_before_a_restart_is_not_resolved_by_the_catch_up(
    store: Store, kit_factory: Any
) -> None:
    first = kit_factory(started_at=T0 - timedelta(days=1))
    await add_event(store, T0 - timedelta(hours=13))
    await first.monitor.run_once()  # queued, so it is on its way to the user

    restarted = kit_factory(started_at=T0 + timedelta(hours=1))
    for minutes in (60, 61, 62):
        restarted.clock.now = T0 + timedelta(minutes=minutes)
        await restarted.monitor.run_once()

    assert await health_messages(restarted.outbox) == [
        "Health problem: No events from router for 13 h 0 min"
    ], "a pending check neither repeats nor resolves the problem"


async def test_api_errors_alert_only_once_they_have_lasted_the_window(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory(api_error_minutes=5)
    await add_event(store, T0)
    kit.state.source_failed("abc123", "NextDNS answered HTTP 503", now=T0)

    kit.clock.now = T0 + timedelta(minutes=4)
    assert by_key(await kit.monitor.run_once())["api:abc123"].ok

    kit.clock.now = T0 + timedelta(minutes=5)
    check = by_key(await kit.monitor.run_once())["api:abc123"]
    assert not check.ok
    assert check.detail == "NextDNS API failing for 5 min (router): NextDNS answered HTTP 503"

    kit.state.source_ok("abc123", now=kit.clock.now)
    assert by_key(await kit.monitor.run_once())["api:abc123"].ok
    await kit.monitor.run_once()
    assert await health_messages(kit.outbox) == [
        f"Health problem: {check.detail}",
        f"Resolved: {check.detail}",
    ]


async def test_an_unreachable_model_alerts_after_the_window(store: Store, kit_factory: Any) -> None:
    kit = kit_factory(ollama_down_minutes=5)
    await add_event(store, T0)
    kit.probe.problem = "Local model unreachable"

    first = by_key(await kit.monitor.run_once())["ollama"]
    kit.clock.now = T0 + timedelta(minutes=5)
    later = by_key(await kit.monitor.run_once())["ollama"]

    assert first.ok
    assert (later.ok, later.detail) == (False, "Local model unreachable for 5 min")


async def test_a_persistent_backlog_alerts(store: Store, kit_factory: Any) -> None:
    kit = kit_factory(max_backlog_events=3, backlog_minutes=10)
    for n in range(5):
        await add_event(store, T0 - timedelta(seconds=n), n=n)

    assert by_key(await kit.monitor.run_once())["backlog"].ok
    kit.clock.now = T0 + timedelta(minutes=10)
    check = by_key(await kit.monitor.run_once())["backlog"]

    assert (check.ok, check.detail) == (False, "5 events waiting for the rules for 10 min")


async def test_a_nearly_full_disk_alerts_at_once(store: Store, kit_factory: Any) -> None:
    kit = kit_factory(max_disk_percent=90)
    await add_event(store, T0)
    kit.disk.used_pct = 95

    check = by_key(await kit.monitor.run_once())["disk"]

    assert (check.ok, check.detail) == (False, "Disk 95% full (5.0 GB free)")


async def test_a_single_good_check_in_a_bad_spell_is_not_a_recovery(
    store: Store, kit_factory: Any
) -> None:
    kit = kit_factory()
    await add_event(store, T0)
    for minutes, used in ((0, 95), (1, 40), (2, 95)):
        kit.clock.now = T0 + timedelta(minutes=minutes)
        kit.disk.used_pct = used
        await kit.monitor.run_once()

    assert await health_messages(kit.outbox) == ["Health problem: Disk 95% full (5.0 GB free)"]


async def test_a_problem_that_returns_after_a_recovery_is_reported_again(
    store: Store, kit_factory: Any
) -> None:
    """Found in a live test: a cooldown hid the second problem after a "Resolved"."""
    kit = kit_factory()
    await add_event(store, T0)
    for minutes, used in ((0, 95), (1, 40), (2, 40), (3, 95)):
        kit.clock.now = T0 + timedelta(minutes=minutes)
        kit.disk.used_pct = used
        await kit.monitor.run_once()

    assert await health_messages(kit.outbox) == [
        "Health problem: Disk 95% full (5.0 GB free)",
        "Resolved: Disk 95% full (5.0 GB free)",
        "Health problem: Disk 95% full (5.0 GB free)",
    ]


async def test_a_restart_during_a_problem_neither_repeats_nor_forgets_it(
    store: Store, kit_factory: Any
) -> None:
    first = kit_factory()
    await add_event(store, T0)
    first.disk.used_pct = 95
    await first.monitor.run_once()

    restarted = kit_factory()
    restarted.disk.used_pct = 95
    await restarted.monitor.run_once()
    assert await health_messages(restarted.outbox) == [
        "Health problem: Disk 95% full (5.0 GB free)"
    ], "the user was already told"

    restarted.disk.used_pct = 40
    for minutes in (1, 2):
        restarted.clock.now = T0 + timedelta(minutes=minutes)
        await restarted.monitor.run_once()
    assert await health_messages(restarted.outbox) == [
        "Health problem: Disk 95% full (5.0 GB free)",
        "Resolved: Disk 95% full (5.0 GB free)",
    ]


async def test_a_problem_that_cleared_while_the_service_was_down_is_resolved(
    store: Store, kit_factory: Any
) -> None:
    first = kit_factory()
    await add_event(store, T0)
    first.disk.used_pct = 95
    await first.monitor.run_once()

    restarted = kit_factory()
    for minutes in (1, 2):
        restarted.clock.now = T0 + timedelta(minutes=minutes)
        await restarted.monitor.run_once()

    assert await health_messages(restarted.outbox) == [
        "Health problem: Disk 95% full (5.0 GB free)",
        "Resolved: Disk 95% full (5.0 GB free)",
    ]


# --- the Ollama probe ----------------------------------------------------------------------


@pytest.fixture
def web() -> Any:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


@pytest.mark.parametrize(
    ("answer", "problem"),
    [
        (httpx.Response(200, json={"models": [{"name": "qwen3:8b", "model": "qwen3:8b"}]}), None),
        (
            httpx.Response(200, json={"models": [{"name": "llama3:8b", "model": "llama3:8b"}]}),
            "Model qwen3:8b is not downloaded",
        ),
        (httpx.Response(500), "Local model unreachable"),
        (httpx.ConnectError("down"), "Local model unreachable"),
        (httpx.Response(200, text="not json"), "Local model unreachable"),
    ],
)
async def test_the_probe_checks_ollama_and_the_model(
    web: Any, answer: httpx.Response | Exception, problem: str | None
) -> None:
    route = web.get("http://ollama.test/api/tags")
    if isinstance(answer, Exception):
        route.mock(side_effect=answer)
    else:
        route.mock(return_value=answer)
    probe = OllamaProbe("http://ollama.test", "qwen3:8b")
    try:
        assert await probe.check() == problem
    finally:
        await probe.aclose()


async def test_a_model_without_a_tag_means_latest(web: Any) -> None:
    web.get("http://ollama.test/api/tags").mock(
        return_value=httpx.Response(200, json={"models": [{"name": "qwen3:latest"}]})
    )
    probe = OllamaProbe("http://ollama.test", "qwen3")
    try:
        assert await probe.check() is None
    finally:
        await probe.aclose()


# --- /healthz ------------------------------------------------------------------------------


async def http_get(port: int, raw: bytes) -> tuple[int, dict[str, Any] | None]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    response = await reader.read()
    writer.close()
    head, _, body = response.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1])
    return status, json.loads(body) if body else None


@pytest.fixture
async def served(store: Store, kit_factory: Any) -> AsyncIterator[tuple[Kit, int]]:
    kit = kit_factory()
    server = await start_health_server(kit.monitor.snapshot, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    yield kit, port
    server.close()
    await server.wait_closed()


async def test_healthz_listens_on_loopback_only(store: Store, kit_factory: Any) -> None:
    kit = kit_factory()
    server = await start_health_server(kit.monitor.snapshot, host="127.0.0.1", port=0)
    try:
        assert [sock.getsockname()[0] for sock in server.sockets] == ["127.0.0.1"]
    finally:
        server.close()
        await server.wait_closed()


async def test_healthz_is_unavailable_until_the_first_check(served: tuple[Kit, int]) -> None:
    _, port = served

    status, body = await http_get(port, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")

    assert (status, body) == (503, {"status": "starting"})


async def test_healthz_reports_ok_or_degraded_with_every_check(
    store: Store, served: tuple[Kit, int]
) -> None:
    kit, port = served
    await add_event(store, T0)
    await kit.monitor.run_once()

    status, body = await http_get(port, b"GET /healthz HTTP/1.1\r\n\r\n")
    assert status == 200
    assert body is not None
    assert body["status"] == "ok"
    assert [check["check"] for check in body["checks"]][:2] == ["events:abc123", "api:abc123"]

    kit.disk.used_pct = 95
    await kit.monitor.run_once()
    status, body = await http_get(port, b"GET /healthz HTTP/1.1\r\n\r\n")
    assert status == 200
    assert body is not None
    assert body["status"] == "degraded"


async def test_healthz_fails_when_checks_have_stopped_running(
    store: Store, served: tuple[Kit, int]
) -> None:
    kit, port = served
    await add_event(store, T0)
    await kit.monitor.run_once()

    kit.clock.now = T0 + timedelta(minutes=10)
    status, body = await http_get(port, b"GET /healthz HTTP/1.1\r\n\r\n")

    assert status == 503
    assert body is not None
    assert body["status"] == "stalled"


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (b"GET /other HTTP/1.1\r\n\r\n", 404),
        (b"POST /healthz HTTP/1.1\r\n\r\n", 405),
        (b"nonsense\r\n\r\n", 400),
        (b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\n\r\n", 400),
    ],
)
async def test_healthz_rejects_anything_else(
    served: tuple[Kit, int], raw: bytes, status: int
) -> None:
    _, port = served

    got, _ = await http_get(port, raw)

    assert got == status


async def test_a_problem_never_delivered_is_announced_again_after_a_restart(
    store: Store, kit_factory: Any
) -> None:
    first = kit_factory()
    await add_event(store, T0)
    first.disk.used_pct = 95
    await first.monitor.run_once()
    (item,) = await first.outbox.recent(limit=10)
    await first.outbox.finish(item.id, status="skipped", reason="no_channel")

    restarted = kit_factory()
    restarted.disk.used_pct = 95
    await restarted.monitor.run_once()

    assert [i.status for i in await restarted.outbox.recent(limit=10)] == ["pending", "skipped"]
