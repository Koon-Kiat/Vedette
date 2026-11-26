"""With HEARTBEAT_URL set, the running pipeline pings it once the health checks have run."""

from pathlib import Path

import httpx
import pytest
import respx
from structlog.testing import capture_logs

from tests.integration.conftest import pipeline_env, running_pipeline, started, wait_until
from tests.integration.fake_nextdns import FakeNextDns

PING = "https://hc.test/ping/0f0c1d2e"


@pytest.fixture
def settings_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'p.db'}"
    pipeline_env(monkeypatch, router, database_url, extra={"HEARTBEAT_URL": PING})


async def test_the_pipeline_pings_the_heartbeat_once_checks_have_run(
    server: FakeNextDns, settings_env: None, router: respx.MockRouter
) -> None:
    server.add_entries(3)
    ping = router.get(PING).mock(return_value=httpx.Response(200, text="OK"))
    with capture_logs() as logs:
        async with running_pipeline():
            await started(logs)

            async def pinged() -> bool:
                return ping.called

            await wait_until(pinged, timeout=10)

    assert any(entry["event"] == "heartbeat_enabled" for entry in logs)
    assert not any(entry["event"] == "heartbeat_withheld" for entry in logs)
    assert all(PING not in str(entry) for entry in logs)
