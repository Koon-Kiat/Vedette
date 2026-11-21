"""End to end: a listed domain in the NextDNS logs becomes an ntfy alert, and /healthz answers."""

import asyncio
import json
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from sentinel.config import load_settings
from sentinel.pipeline.runner import Pipeline
from tests.integration.conftest import wait_until
from tests.integration.fake_nextdns import API_KEY, FakeNextDns
from tests.unit.test_reference_parsing import tranco_zip

NTFY = "https://ntfy.example/"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
def settings_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> int:
    port = free_port()
    for name, value in {
        "NEXTDNS_API_KEY": API_KEY,
        "SENTINEL_STORAGE__DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'p.db'}",
        "SENTINEL_PROFILES": '[{"id": "abc123", "label": "router"}]',
        "SENTINEL_INGEST__PAGE_SIZE": "10",
        "SENTINEL_INGEST__BACKFILL_DAYS": "36500",
        "SENTINEL_ENRICH__POPULARITY__URL": "https://lists.test/top.zip",
        "SENTINEL_ENRICH__RDAP__ENABLED": "false",
        "SENTINEL_ENRICH__THREAT_INTEL__FEEDS": '[{"name": "phish", "url": "https://feeds.test/p.txt"}]',
        "SENTINEL_RULES__LEARNING_DAYS": "0",
        "SENTINEL_LLM__BASE_URL": "http://ollama.test",
        "SENTINEL_NOTIFY__CHANNEL": "ntfy",
        "SENTINEL_NOTIFY__NTFY__URL": "https://ntfy.example",
        "NTFY_TOPIC": "pipeline-test",
        "SENTINEL_NOTIFY__QUIET_HOURS": "00:00-00:00",
        "SENTINEL_NOTIFY__ANALYSIS_WAIT_SECONDS": "0",
        # The fake server's events are from 2026-03-15, far in the past.
        "SENTINEL_NOTIFY__ALERT_MAX_AGE_MINUTES": "10000000",
        "SENTINEL_HEALTH__HEALTHZ_PORT": str(port),
    }.items():
        monkeypatch.setenv(name, value)
    router.get("https://lists.test/top.zip").mock(
        return_value=httpx.Response(200, content=tranco_zip("1,site1.example\r\n"))
    )
    router.get("https://feeds.test/p.txt").mock(
        return_value=httpx.Response(200, text="site3.example\n")
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
    stop = asyncio.Event()
    task = asyncio.create_task(Pipeline(load_settings()).run(stop))
    try:

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
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=10)

    (sent,) = threat_alerts()
    assert sent["topic"] == "pipeline-test"
    assert sent["priority"] == 5
    assert sent["title"].startswith("CRITICAL: Threat-feed domain allowed, site3[.]example")
    assert "site3.example" not in sent["message"]
