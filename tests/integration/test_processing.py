"""The whole pipeline: collect, enrich, evaluate rules, store findings."""

from pathlib import Path

import pytest
import respx

from tests.integration.conftest import (
    pipeline_env,
    read_when_migrated,
    running_pipeline,
    wait_until,
)
from tests.integration.fake_nextdns import FakeNextDns
from vedette.storage.store import Store, StoredFinding


@pytest.fixture
def database_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'pipeline.db'}"
    pipeline_env(monkeypatch, router, url, findings=True)
    return url


async def run_until_processed(server: FakeNextDns, database_url: str) -> None:
    """Run the pipeline until every server entry is stored and processed, then stop it."""

    async def processed(reader: Store) -> bool:
        return (
            await reader.count_events("abc123") == len(server.entries)
            and await reader.count_unprocessed("abc123") == 0
        )

    async def done() -> bool:
        return await read_when_migrated(database_url, processed) is True

    async with running_pipeline():
        await wait_until(done, timeout=15)


async def threat_findings(database_url: str) -> list[StoredFinding]:
    reader = Store.open(database_url)
    try:
        return await reader.list_findings(rule_id="threat-intel-allowed")
    finally:
        await reader.close()


async def test_allowed_queries_to_a_listed_domain_become_findings(
    server: FakeNextDns, database_url: str
) -> None:
    server.add_entries(40)

    await run_until_processed(server, database_url)

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
    server: FakeNextDns, database_url: str
) -> None:
    server.add_entries(40)
    await run_until_processed(server, database_url)
    before = {(f.id, f.event_count) for f in await threat_findings(database_url)}

    await run_until_processed(server, database_url)

    assert {(f.id, f.event_count) for f in await threat_findings(database_url)} == before


async def test_events_arriving_after_a_restart_are_processed_too(
    server: FakeNextDns, database_url: str
) -> None:
    server.add_entries(40)
    await run_until_processed(server, database_url)

    # Of the new entries under site3.example, 45 is blocked, 52 is an allowed
    # query from DEV1 and 59 an allowed query from DEV2.
    server.add_entries(20)
    await run_until_processed(server, database_url)

    counts = {f.subject: f.event_count for f in await threat_findings(database_url)}
    assert counts == {None: 2, "DEV2": 3, "DEV1": 2}
