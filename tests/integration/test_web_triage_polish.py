"""Rule names, triage order, live open counts, the Mark benign confirmation,
health states, outside names in the evidence, error titles and the narrow layout."""

import json
import re
from datetime import timedelta

import pytest

from tests.digest_fixture import PROFILES, _event
from tests.integration.web_helpers import NOW, logged_in
from tests.web_fixture import build_web_fixture
from vedette.rules.model import Finding, Severity
from vedette.storage.health import HealthCheck, HealthStore
from vedette.storage.live import LiveQueries
from vedette.storage.store import Store
from vedette.web.app import _average

RANKS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    return store


async def first(store: Store, rule_id: str) -> int:
    return next(f.id for f in await store.list_findings(limit=100) if f.rule_id == rule_id)


async def test_every_findings_list_opens_highest_priority_first(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        html = (await client.get("/findings?status=all")).text

    levels = re.findall(r'<tr id="finding-\d+" class="status-\w+ sev-(\w+)', html)
    assert len(set(levels)) > 2
    assert levels == sorted(levels, key=lambda level: -RANKS[level])
    assert re.search(r'data-sorted="descending">Priority', html)


async def test_findings_are_titled_by_rule_name_with_the_id_beside_it(filled: Store) -> None:
    young, dga = await first(filled, "young-domain"), await first(filled, "dga-like")
    async with logged_in(filled) as (client, _):
        listing = (await client.get("/findings?status=all")).text
        page = (await client.get(f"/findings/{young}")).text
        analysed = (await client.get(f"/findings/{dga}")).text

    assert '">Newly registered domain</a></td>' in listing
    assert '<option value="young-domain">Newly registered domain</option>' in listing
    assert '<span class="rule-name">Newly registered domain</span>' in page
    assert '<dt>Rule</dt><dd class="figure">young-domain</dd>' in page
    # What the rule checks is on every finding's page, analysed or not.
    for html in (page, analysed):
        assert "<h3>What the rule checks</h3>" in html
    assert "random-looking label" in analysed


async def test_a_reason_is_shown_by_name_with_its_id_beside_it(filled: Store) -> None:
    event = _event(
        "def456", NOW - timedelta(minutes=5), "ads.tracker.example", device=("D1", "Laptop")
    )
    await filled.save_events([event])
    await filled.commit_processed(
        [],
        [
            Finding(
                rule_id="new-destination-category",
                severity=Severity.LOW,
                profile_id="def456",
                subject="D1",
                device_mode=True,
                target="ads",
                ts=NOW - timedelta(minutes=5),
                dedupe_key="reason-test",
                evidence={
                    "category": "ads",
                    "category_name": "Ads and trackers",
                    "fqdn": "ads.tracker.example",
                },
                event_id=event.event_id,
            )
        ],
    )
    reason = await first(filled, "new-destination-category")
    async with logged_in(filled) as (client, _):
        listing = (await client.get("/findings")).text
        page = (await client.get(f"/findings/{reason}")).text

    assert '<span class="name">Ads and trackers</span>' in listing
    assert '<span class="name">Ads and trackers</span> <span class="reason-id">ads</span>' in page


async def test_outside_names_in_the_evidence_are_marked(filled: Store) -> None:
    young = await first(filled, "young-domain")
    async with logged_in(filled) as (client, _):
        page = (await client.get(f"/findings/{young}")).text

    rows = dict(re.findall(r'<th scope="row">([^<]+)</th><td>(.*?)</td>', page))
    assert rows["Name queried"].startswith('<span class="name">') and "[.]" in rows["Name queried"]
    assert rows["NextDNS status"] == "allowed"
    assert rows["Domain age, days"] == "5"


async def test_a_decision_carries_every_open_count(filled: Store) -> None:
    young = await first(filled, "young-domain")
    async with logged_in(filled) as (client, csrf):
        before = (await client.get("/")).text
        response = await client.post(
            f"/findings/{young}/acknowledge",
            data={"csrf_token": csrf, "next": "/"},
            headers={"HX-Request": "true"},
        )

    counts = json.loads(response.headers["HX-Trigger"])["vedette-counts"]["layers"]
    shown = dict(re.findall(r'data-live="open-layer-(\d)">(\d+) open', before))
    assert counts["0"] == int(shown["0"]) - 1
    assert counts["2"] == int(shown["2"]) - 1, "the pc profile's count drops"
    assert counts["1"] == int(shown["1"])
    assert counts["0"] == counts["1"] + counts["2"]


async def test_live_stats_count_open_findings_per_profile(filled: Store) -> None:
    stats = await LiveQueries(filled.engine, profiles=PROFILES).stats(NOW)

    assert set(stats.open_by_profile) == {profile.id for profile in PROFILES}
    assert sum(stats.open_by_profile.values()) == stats.open_findings > 0


async def test_mark_benign_asks_with_a_title_and_a_marked_name(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        html = (await client.get("/findings")).text

    assert 'data-confirm-title="Mark this finding benign?"' in html
    body = re.search(r'<template class="confirm-body">(.*?)</template>', html)
    assert body is not None
    assert '<span class="name">' in body[1]
    assert body[1].endswith("Reopen the finding to undo this.")


async def test_a_retrying_api_check_reads_retrying(filled: Store) -> None:
    await HealthStore(filled.engine).save(
        [
            HealthCheck(
                "api:abc123",
                "NextDNS API (router)",
                True,
                "NextDNS is rate-limiting Vedette since 08:20. Vedette waits and tries again.",
            ),
            HealthCheck("events:abc123", "Events from router", True, "OK"),
        ],
        now=NOW,
    )
    async with logged_in(filled) as (client, _):
        html = (await client.get("/health")).text

    assert '<tr class="watch"><td>NextDNS API (router)</td><td><span class="state">Retrying' in html
    assert '<tr class="ok"><td>Events from router</td><td><span class="state">OK' in html
    assert "All 2 checks OK" in html, "a retrying check has raised no alert"


async def test_a_missing_finding_is_titled_in_words(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        response = await client.get("/findings/9999")

    assert response.status_code == 404
    assert "<title>Finding 9999 not found · Vedette</title>" in response.text
    assert "<h1>Finding 9999 not found</h1>" in response.text
    assert '<dt>Status</dt><dd class="figure">404</dd>' in response.text


async def test_a_narrow_window_gets_the_decision_after_the_explanation(filled: Store) -> None:
    young = await first(filled, "young-domain")
    async with logged_in(filled) as (client, _):
        page = (await client.get(f"/findings/{young}")).text

    inline = page.index('class="panel decide decide-inline"')
    assert page.index('id="explain-title"') < inline < page.index('id="evidence-title"')
    assert 'class="panel decide decide-side"' in page
    assert page.count('aria-labelledby="decide-title-') == 2


async def test_the_filters_fold_and_say_how_many_are_set(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        plain = (await client.get("/findings")).text
        narrowed = (await client.get("/findings?severity=high&rule=young-domain")).text

    assert '<details class="filters-fold" data-ui="filters-fold" open>' in plain
    assert "data-filters-count></span>" in plain
    assert "data-filters-count>2 set</span>" in narrowed


def test_averages_drop_tenths_once_they_reach_a_hundred() -> None:
    assert _average(30219.7) == "30,220"
    assert _average(970.6) == "971"
    assert _average(0.3) == "0.3"
    assert _average(2.0) == "2"
    assert _average(None) == "n/a"
