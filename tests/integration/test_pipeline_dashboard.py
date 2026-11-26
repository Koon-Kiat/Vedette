"""The dashboard runs inside the pipeline, over real TCP, and stops with it."""

import asyncio
import logging
import socket
from pathlib import Path

import pytest
import respx
from structlog.testing import capture_logs

from tests.integration.conftest import (
    free_port,
    pipeline_env,
    running_pipeline,
    started,
    wait_until,
)
from tests.integration.fake_nextdns import FakeNextDns
from tests.integration.web_helpers import TOKEN


@pytest.fixture
def port(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> int:
    chosen = free_port()
    pipeline_env(
        monkeypatch,
        router,
        f"sqlite+aiosqlite:///{tmp_path / 'p.db'}",
        extra={"DASHBOARD_TOKEN": TOKEN, "VEDETTE_DASHBOARD__PORT": str(chosen)},
    )
    return chosen


async def get(port: int, path: str) -> tuple[int, str]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    raw = await reader.read()
    writer.close()
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    return int(head.split(" ")[1]), head


async def test_the_dashboard_serves_while_the_pipeline_runs(
    server: FakeNextDns, port: int, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="uvicorn.access")
    server.add_entries(3)
    with capture_logs() as logs:
        async with running_pipeline():
            await started(logs)

            async def up() -> bool:
                try:
                    return (await get(port, "/login"))[0] == 200
                except OSError:
                    return False

            await wait_until(up, timeout=10)
            status, head = await get(port, "/")
            assert status == 303
            assert "content-security-policy" in head.lower()
            headers = [line.split(":", 1)[0].lower() for line in head.splitlines()[1:]]
            assert "server" not in headers and "date" not in headers

    assert not [record for record in caplog.records if record.name == "uvicorn.access"]

    with pytest.raises(OSError):
        await get(port, "/login")


async def test_a_busy_port_leaves_the_rest_of_the_pipeline_running(
    server: FakeNextDns, port: int
) -> None:
    server.add_entries(3)
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", port))
    blocker.listen()
    try:
        with capture_logs() as logs:
            async with running_pipeline() as task:

                async def warned() -> bool:
                    return any(entry["event"] == "dashboard_unavailable" for entry in logs)

                await wait_until(warned, timeout=10)
                await started(logs)
                assert not task.done()
    finally:
        blocker.close()


async def test_without_a_token_the_dashboard_stays_off(
    server: FakeNextDns, port: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DASHBOARD_TOKEN")
    server.add_entries(3)
    with capture_logs() as logs:
        async with running_pipeline():
            await started(logs)

    (entry,) = [e for e in logs if e["event"] == "dashboard_disabled"]
    assert entry["reason"] == "DASHBOARD_TOKEN is not set"
