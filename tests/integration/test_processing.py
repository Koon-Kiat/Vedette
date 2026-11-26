"""The whole pipeline: collect, enrich, evaluate rules, store findings."""

import asyncio
from pathlib import Path

import httpx
import pytest
import respx
from sqlalchemy.exc import OperationalError

from tests.integration.conftest import wait_until
from tests.integration.fake_nextdns import API_KEY, FakeNextDns
from tests.unit.test_reference_parsing import tranco_zip
from vedette.config import load_settings
from vedette.pipeline.runner import Pipeline
from vedette.storage.store import Store, StoredFinding

TRANCO_URL = "https://lists.test/top-1m.csv.zip"
FEED_URL = "https://feeds.test/phish.txt"


@pytest.fixture
def database_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'pipeline.db'}"
    monkeypatch.setenv("NEXTDNS_API_KEY", API_KEY)
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')
    monkeypatch.setenv("VEDETTE_INGEST__PAGE_SIZE", "10")
    monkeypatch.setenv("VEDETTE_INGEST__BACKFILL_DAYS", "36500")
    monkeypatch.setenv("VEDETTE_ENRICH__POPULARITY__URL", TRANCO_URL)
    monkeypatch.setenv("VEDETTE_ENRICH__RDAP__ENABLED", "false")
    monkeypatch.setenv(
        "VEDETTE_ENRICH__THREAT_INTEL__FEEDS", f'[{{"name": "phish", "url": "{FEED_URL}"}}]'
    )
    monkeypatch.setenv("VEDETTE_RULES__LEARNING_DAYS", "0")
    router.get(TRANCO_URL).mock(
        return_value=httpx.Response(200, content=tranco_zip("1,site1.example\r\n"))
    )
    router.get(FEED_URL).mock(return_value=httpx.Response(200, text="site3.example\n"))
    return url


async def run_until_processed(server: FakeNextDns, database_url: str, tmp_path: Path) -> None:
    """Run the pipeline until every server entry is stored and processed, then stop it."""
    stop = asyncio.Event()
    task = asyncio.create_task(Pipeline(load_settings()).run(stop))
    try:

        async def done() -> bool:
            if not (tmp_path / "pipeline.db").exists():
                return False
            reader = Store.open(database_url)
            try:
                return (
                    await reader.count_events("abc123") == len(server.entries)
                    and await reader.count_unprocessed("abc123") == 0
                )
            except OperationalError:
                return False
            finally:
                await reader.close()

        await wait_until(done, timeout=15)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=10)


async def threat_findings(database_url: str) -> list[StoredFinding]:
    reader = Store.open(database_url)
    try:
        return await reader.list_findings(rule_id="threat-intel-allowed")
    finally:
        await reader.close()


async def test_allowed_queries_to_a_listed_domain_become_findings(
    server: FakeNextDns, database_url: str, tmp_path: Path
) -> None:
    server.add_entries(40)

    await run_until_processed(server, database_url, tmp_path)

    # Entries 3, 17, 24, 31 and 38 are allowed queries under site3.example
    # (entry 10 is blocked): two without a device, two from DEV2, one from DEV1.
    found = await threat_findings(database_url)
    assert {(f.subject, f.device_mode, f.event_count) for f in found} == {
        (None, False, 2),
        ("DEV2", True, 2),
        ("DEV1", True, 1),
    }
    for finding in found:
        assert finding.severity.value == "critical"
        assert finding.target == "site3.example"
        assert finding.evidence["threat_feeds"] == ["phish"]


async def test_restarting_the_pipeline_does_not_duplicate_or_inflate_findings(
    server: FakeNextDns, database_url: str, tmp_path: Path
) -> None:
    server.add_entries(40)
    await run_until_processed(server, database_url, tmp_path)
    before = {(f.id, f.event_count) for f in await threat_findings(database_url)}

    await run_until_processed(server, database_url, tmp_path)

    assert {(f.id, f.event_count) for f in await threat_findings(database_url)} == before


async def test_events_arriving_after_a_restart_are_processed_too(
    server: FakeNextDns, database_url: str, tmp_path: Path
) -> None:
    server.add_entries(40)
    await run_until_processed(server, database_url, tmp_path)

    # Of the new entries under site3.example, 45 is blocked, 52 is an allowed
    # query from DEV1 and 59 an allowed query from DEV2.
    server.add_entries(20)
    await run_until_processed(server, database_url, tmp_path)

    counts = {f.subject: f.event_count for f in await threat_findings(database_url)}
    assert counts == {None: 2, "DEV2": 3, "DEV1": 2}
