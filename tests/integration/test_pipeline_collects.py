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
from vedette.sources.nextdns import parse_log_entry
from vedette.storage.store import Store


async def test_pipeline_migrates_collects_and_stops_cleanly(
    server: FakeNextDns,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    router: respx.MockRouter,
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'pipeline.db'}"
    profiles = (
        '[{"id": "abc123", "label": "router"}, {"id": "off999", "label": "pc", "enabled": false}]'
    )
    pipeline_env(
        monkeypatch,
        router,
        database_url,
        extra={
            "VEDETTE_PROFILES": profiles,
            "VEDETTE_INGEST__PAGE_SIZE": "10",
            # The fake server's entries have fixed past dates; make the window cover them.
            "VEDETTE_INGEST__BACKFILL_DAYS": "36500",
        },
    )
    server.add_entries(25)

    async def collected() -> bool:
        count = await read_when_migrated(database_url, lambda reader: reader.count_events("abc123"))
        return count == 25

    async with running_pipeline(stop_timeout=5):
        await wait_until(collected)

    reader = Store.open(database_url)
    try:
        stored = [event.event_id for event in await reader.list_events("abc123")]
        assert stored == [parse_log_entry("abc123", entry).event_id for entry in server.entries]
        assert await reader.count_events("off999") == 0
    finally:
        await reader.close()
    assert {request.url.params["limit"] for request in server.log_requests} == {"10"}
