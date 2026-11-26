"""The dashboard runs inside the pipeline, over real TCP, and stops with it."""

import asyncio
import socket
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
import respx
from structlog.testing import capture_logs

from tests.integration.conftest import wait_until
from tests.integration.fake_nextdns import API_KEY, FakeNextDns
from vedette.config import load_settings
from vedette.pipeline.runner import Pipeline

TOKEN = "a-dashboard-token-of-enough-length-1234"  # noqa: S105 - fake value for tests


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
def port(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> int:
    chosen = free_port()
    for name, value in {
        "NEXTDNS_API_KEY": API_KEY,
        "DASHBOARD_TOKEN": TOKEN,
        "VEDETTE_STORAGE__DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'p.db'}",
        "VEDETTE_PROFILES": '[{"id": "abc123", "label": "router"}]',
        "VEDETTE_ENRICH__RDAP__ENABLED": "false",
        "VEDETTE_ENRICH__THREAT_INTEL__FEEDS": "[]",
        "VEDETTE_ENRICH__POPULARITY__URL": "https://lists.test/top.zip",
        "VEDETTE_DASHBOARD__PORT": str(chosen),
        "VEDETTE_HEALTH__HEALTHZ_PORT": str(free_port()),
    }.items():
        monkeypatch.setenv(name, value)
    router.get("https://lists.test/top.zip").respond(404)
    return chosen


STARTED = {"rule_engine_warmed_up", "collector_backfill_completed"}


async def started(logs: Sequence[Mapping[str, Any]]) -> None:
    """Wait until start-up has finished, so stopping does not interrupt it."""

    async def done() -> bool:
        return {str(entry["event"]) for entry in logs} >= STARTED

    await wait_until(done, timeout=10)


async def get(port: int, path: str) -> tuple[int, str]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    raw = await reader.read()
    writer.close()
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    return int(head.split(" ")[1]), head


async def test_the_dashboard_serves_while_the_pipeline_runs(server: FakeNextDns, port: int) -> None:
    server.add_entries(3)
    stop = asyncio.Event()
    with capture_logs() as logs:
        task = asyncio.create_task(Pipeline(load_settings()).run(stop))
        await started(logs)
    try:

        async def up() -> bool:
            try:
                return (await get(port, "/login"))[0] == 200
            except OSError:
                return False

        await wait_until(up, timeout=10)
        status, head = await get(port, "/")
        assert status == 303
        assert "content-security-policy" in head.lower()
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=10)

    with pytest.raises(OSError):
        await get(port, "/login")


async def test_a_busy_port_leaves_the_rest_of_the_pipeline_running(
    server: FakeNextDns, port: int
) -> None:
    server.add_entries(3)
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", port))
    blocker.listen()
    stop = asyncio.Event()
    try:
        with capture_logs() as logs:
            task = asyncio.create_task(Pipeline(load_settings()).run(stop))

            async def warned() -> bool:
                return any(entry["event"] == "dashboard_unavailable" for entry in logs)

            await wait_until(warned, timeout=10)
            await started(logs)
            assert not task.done()
            stop.set()
            await asyncio.wait_for(task, timeout=10)
    finally:
        blocker.close()


async def test_without_a_token_the_dashboard_stays_off(
    server: FakeNextDns, port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DASHBOARD_TOKEN")
    server.add_entries(3)
    stop = asyncio.Event()
    with capture_logs() as logs:
        task = asyncio.create_task(Pipeline(load_settings()).run(stop))

        await started(logs)
        stop.set()
        await asyncio.wait_for(task, timeout=10)

    (entry,) = [e for e in logs if e["event"] == "dashboard_disabled"]
    assert entry["reason"] == "DASHBOARD_TOKEN is not set"
