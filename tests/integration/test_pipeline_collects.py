import asyncio
from pathlib import Path

import pytest

from sentinel.config import load_settings
from sentinel.pipeline.runner import Pipeline
from sentinel.sources.nextdns import parse_log_entry
from sentinel.storage.store import Store
from tests.integration.conftest import wait_until
from tests.integration.fake_nextdns import API_KEY, FakeNextDns


async def test_pipeline_migrates_collects_and_stops_cleanly(
    server: FakeNextDns, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'pipeline.db'}"
    monkeypatch.setenv("NEXTDNS_API_KEY", API_KEY)
    monkeypatch.setenv("SENTINEL_STORAGE__DATABASE_URL", database_url)
    monkeypatch.setenv(
        "SENTINEL_PROFILES",
        '[{"id": "abc123", "label": "router"}, {"id": "off999", "label": "pc", "enabled": false}]',
    )
    monkeypatch.setenv("SENTINEL_INGEST__PAGE_SIZE", "10")
    # The fake server's entries have fixed past dates; make the window cover them.
    monkeypatch.setenv("SENTINEL_INGEST__BACKFILL_DAYS", "36500")
    server.add_entries(25)
    stop = asyncio.Event()

    task = asyncio.create_task(Pipeline(load_settings()).run(stop))
    try:

        async def collected() -> bool:
            if not (tmp_path / "pipeline.db").exists():
                return False
            reader = Store.open(database_url)
            try:
                return await reader.count_events("abc123") == 25
            except Exception:  # noqa: BLE001 - schema may not exist yet; keep polling
                return False
            finally:
                await reader.close()

        await wait_until(collected)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=5)

    reader = Store.open(database_url)
    try:
        stored = [event.event_id for event in await reader.list_events("abc123")]
        assert stored == [parse_log_entry("abc123", entry).event_id for entry in server.entries]
        assert await reader.count_events("off999") == 0
    finally:
        await reader.close()
    assert {request.url.params["limit"] for request in server.log_requests} == {"10"}
