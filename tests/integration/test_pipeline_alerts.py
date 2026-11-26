"""End to end: a listed domain in the NextDNS logs becomes an ntfy alert, and /healthz answers."""

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from tests.integration.conftest import pipeline_env, running_pipeline, wait_until
from tests.integration.fake_nextdns import FakeNextDns

NTFY = "https://ntfy.example/"


@pytest.fixture
def settings_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> int:
    port = pipeline_env(
        monkeypatch,
        router,
        f"sqlite+aiosqlite:///{tmp_path / 'p.db'}",
        findings=True,
        extra={
            "VEDETTE_LLM__BASE_URL": "http://ollama.test",
            "VEDETTE_NOTIFY__CHANNEL": "ntfy",
            "VEDETTE_NOTIFY__NTFY__URL": "https://ntfy.example",
            "NTFY_TOPIC": "pipeline-test",
            "VEDETTE_NOTIFY__QUIET_HOURS": "00:00-00:00",
            "VEDETTE_NOTIFY__ANALYSIS_WAIT_SECONDS": "0",
            # The fake server's events are from 2026-03-15, far in the past.
            "VEDETTE_NOTIFY__ALERT_MAX_AGE_MINUTES": "10000000",
        },
    )
    router.post("http://ollama.test/api/chat").mock(side_effect=httpx.ConnectError("no model"))
    return port


async def healthz(port: int) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET /healthz HTTP/1.1\r\n\r\n")
    await writer.drain()
    head = await reader.read()
    writer.close()
    return int(head.split(b" ")[1])


async def test_a_listed_domain_reaches_ntfy_as_a_critical_alert(
    server: FakeNextDns, settings_env: int, router: respx.MockRouter
) -> None:
    server.add_entries(10)  # entry 3 is an allowed query under site3.example
    ntfy = router.post(NTFY).mock(return_value=httpx.Response(200, json={}))
    async with running_pipeline():

        def threat_alerts() -> list[dict[str, Any]]:
            # The fake server's events are months old, so the health monitor may
            # also (correctly) send a "no events" message; pick out the alert.
            sent = [json.loads(call.request.content) for call in ntfy.calls]
            return [
                m for m in sent if m["title"].startswith("CRITICAL: Threat-feed domain allowed")
            ]

        async def alerted() -> bool:
            return len(threat_alerts()) >= 1

        await wait_until(alerted, timeout=20)

        async def healthy() -> bool:
            try:
                return await healthz(settings_env) == 200
            except OSError:
                return False

        await wait_until(healthy, timeout=10)

    (sent,) = threat_alerts()
    assert sent["topic"] == "pipeline-test"
    assert sent["priority"] == 5
    assert sent["title"].startswith("CRITICAL: Threat-feed domain allowed, site3[.]example")
    assert "site3.example" not in sent["message"]
