"""The live feed: the stream, the Live page and the partials it refreshes."""

import json
from datetime import timedelta
from typing import Any

import pytest

from tests.integration.web_helpers import NOW, logged_in, make_client
from tests.web_fixture import build_web_fixture
from vedette.sources.base import DnsEvent, Reason
from vedette.storage.store import Store

HOSTILE = "<script>alert(1)</script>.evil.example"
FAST: dict[str, Any] = {
    "live_poll_seconds": 0.01,
    "live_stats_seconds": 0.0,
    "live_max_seconds": 0.2,
}


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    await store.save_events(
        [
            DnsEvent(
                event_id="live-1",
                profile_id="def456",
                ts=NOW - timedelta(seconds=30),
                fqdn="live-site.example",
                root="live-site.example",
                status="default",
                device_id="D1",
                device_name="Laptop",
                source="nextdns",
            ),
            DnsEvent(
                event_id="live-2",
                profile_id="abc123",
                ts=NOW - timedelta(seconds=20),
                fqdn=HOSTILE,
                root="evil.example",
                status="blocked",
                reasons=(Reason(id="x", name="<b>Ads</b>"),),
                source="nextdns",
            ),
        ]
    )
    return store


def events_of(body: str) -> list[tuple[str, Any]]:
    out = []
    for block in body.split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "event" in lines:
            out.append((lines["event"], json.loads(lines["data"])))
    return out


async def test_the_stream_needs_a_session(filled: Store) -> None:
    async with make_client(filled, **FAST) as client:
        response = await client.get("/live/stream")

    assert (response.status_code, response.headers["location"]) == (303, "/login")


async def test_the_stream_sends_new_queries_and_counters(filled: Store) -> None:
    async with logged_in(filled, **FAST) as (client, _):
        response = await client.get("/live/stream")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store"
    assert response.text.startswith("retry: 3000")
    received = events_of(response.text)
    queries = [item for name, data in received if name == "queries" for item in data]
    assert [item["id"] for item in queries] == ["live-1", "live-2"]
    first, hostile = queries
    assert first["domain"] == "live-site[.]example"
    assert first["t"] == int((NOW - timedelta(seconds=30)).timestamp())
    assert (first["profile"], first["device"], first["status"]) == ("pc", "Laptop", "allowed")
    assert hostile["status"] == "blocked"
    assert "evil[.]example" in hostile["domain"]
    assert "<" not in response.text  # escaped even inside the JSON
    stats = next(data for name, data in received if name == "stats")
    assert stats["last_minute"] == 2
    assert stats["blocked_last_minute"] == 1
    assert len(stats["per_minute"]) == 30
    assert stats["open_findings"] >= 1


async def test_a_second_poll_does_not_repeat_queries(filled: Store) -> None:
    async with logged_in(filled, **{**FAST, "live_max_seconds": 0.3}) as (client, _):
        response = await client.get("/live/stream")

    ids = [
        item["id"] for name, data in events_of(response.text) if name == "queries" for item in data
    ]
    assert sorted(ids) == ["live-1", "live-2"]


async def test_too_many_streams_are_refused(filled: Store) -> None:
    async with logged_in(filled, **{**FAST, "live_max_streams": 0}) as (client, _):
        response = await client.get("/live/stream")

    assert response.status_code == 429


async def test_the_live_page_shows_recent_queries(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/live")

    assert page.status_code == 200
    assert "live-site[.]example" in page.text
    assert "evil[.]example" in page.text
    assert "<script>alert(1)" not in page.text
    assert 'data-live="feed"' in page.text and "data-filterable" in page.text
    assert page.text.count('class="minute-bar') == 30


async def test_the_decision_partial_is_a_fragment(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        decide = await client.get("/partials/decide")

    assert decide.status_code == 200
    assert "<html" not in decide.text
    assert 'id="finding-' in decide.text
    assert decide.text.count('class="bar-allowed"') == 0


async def test_the_overview_has_the_live_parts(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/")

    assert 'hx-trigger="vedette:findings from:body"' in page.text
    assert 'src="/static/live.js?v=' in page.text  # versioned by its content
    assert "live-site[.]example" in page.text
