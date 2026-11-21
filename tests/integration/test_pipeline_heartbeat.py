"""With HEARTBEAT_URL set, the running pipeline pings it once the health checks have run."""

import asyncio
from pathlib import Path

import httpx
import pytest
import respx
from structlog.testing import capture_logs

from tests.integration.conftest import wait_until
from tests.integration.fake_nextdns import API_KEY, FakeNextDns
from tests.integration.test_pipeline_dashboard import free_port, started
from vedette.config import load_settings
from vedette.pipeline.runner import Pipeline

PING = "https://hc.test/ping/0f0c1d2e"


@pytest.fixture
def settings_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> None:
    for name, value in {
        "NEXTDNS_API_KEY": API_KEY,
        "HEARTBEAT_URL": PING,
        "VEDETTE_STORAGE__DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'p.db'}",
        "VEDETTE_PROFILES": '[{"id": "abc123", "label": "router"}]',
        "VEDETTE_ENRICH__RDAP__ENABLED": "false",
        "VEDETTE_ENRICH__THREAT_INTEL__FEEDS": "[]",
        "VEDETTE_ENRICH__POPULARITY__URL": "https://lists.test/top.zip",
        "VEDETTE_HEALTH__HEALTHZ_PORT": str(free_port()),
    }.items():
        monkeypatch.setenv(name, value)
    router.get("https://lists.test/top.zip").respond(404)


async def test_the_pipeline_pings_the_heartbeat_once_checks_have_run(
    server: FakeNextDns, settings_env: None, router: respx.MockRouter
) -> None:
    server.add_entries(3)
    ping = router.get(PING).mock(return_value=httpx.Response(200, text="OK"))
    stop = asyncio.Event()
    with capture_logs() as logs:
        task = asyncio.create_task(Pipeline(load_settings()).run(stop))
        await started(logs)
        try:

            async def pinged() -> bool:
                return ping.called

            await wait_until(pinged, timeout=10)
        finally:
            stop.set()
            await task

    assert any(entry["event"] == "heartbeat_enabled" for entry in logs)
    assert not any(entry["event"] == "heartbeat_withheld" for entry in logs)
    assert all(PING not in str(entry) for entry in logs)
