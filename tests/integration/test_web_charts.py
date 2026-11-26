"""The interactive charts: the series and window queries, and the endpoints behind them."""

import json
from datetime import datetime, timedelta

import pytest

from tests.digest_fixture import PROFILES, _event
from tests.integration.test_web_xss import audit
from tests.integration.web_helpers import NOW, logged_in, make_client
from vedette.shared.models import Finding, Severity
from vedette.storage.series import SeriesQueries
from vedette.storage.store import Store

T0 = NOW - timedelta(minutes=10)  # on a whole minute
HOSTILE = "<script>alert(1)</script>.evil.example"


def epoch(moment: datetime) -> int:
    return int(moment.timestamp())


def span(minutes: int) -> str:
    return f"from={epoch(T0)}&to={epoch(T0 + timedelta(minutes=minutes))}"


@pytest.fixture
async def charted(store: Store) -> Store:
    await store.save_events(
        [
            _event("abc123", T0 + timedelta(seconds=10), "www.site.example"),
            _event("abc123", T0 + timedelta(seconds=50), "x.ads.example", blocked=True),
            _event("abc123", T0 + timedelta(seconds=90), "www.site.example"),
            _event("def456", T0 + timedelta(seconds=100), f"x.{HOSTILE}", device=("D1", "Laptop")),
            # A profile the dashboard does not show.
            _event("zzz999", T0 + timedelta(seconds=20), "www.other.example"),
        ]
    )
    await store.commit_processed(
        [],
        [
            Finding(
                rule_id="young-domain",
                severity=Severity.HIGH,
                profile_id="def456",
                subject="D1",
                device_mode=True,
                target=HOSTILE,
                ts=T0 + timedelta(minutes=2),
                dedupe_key="chart-1",
                evidence={"fqdn": f"x.{HOSTILE}"},
                event_id="1" * 64,
            )
        ],
    )
    return store


async def test_the_series_counts_queries_per_bar(charted: Store) -> None:
    series = await SeriesQueries(charted.engine, profiles=PROFILES).series(
        T0, T0 + timedelta(minutes=5)
    )

    assert series.step == 60
    assert series.t == [epoch(T0) + 60 * n for n in range(6)]
    assert series.allowed == [1, 2, 0, 0, 0, 0]
    assert series.blocked == [1, 0, 0, 0, 0, 0]
    # Four queries over the 290 seconds since the first, per 60-second bar.
    assert series.usual == round(4 * 60 / 290, 2)
    (finding,) = series.findings
    assert (finding.t, finding.rule, finding.priority, finding.status) == (
        epoch(T0) + 120,
        "young-domain",
        "high",
        "open",
    )


async def test_the_window_has_totals_roots_findings_and_the_latest_queries(
    charted: Store,
) -> None:
    window = await SeriesQueries(charted.engine, profiles=PROFILES).window(
        T0, T0 + timedelta(minutes=5)
    )

    assert (window.allowed, window.blocked) == (3, 1)
    assert (window.top[0].root, window.top[0].queries, window.top[0].blocked) == (
        "site.example",
        2,
        0,
    )
    assert [event.fqdn for event in window.latest] == [
        f"x.{HOSTILE}",
        "www.site.example",
        "x.ads.example",
        "www.site.example",
    ]
    assert [finding.rule for finding in window.findings] == ["young-domain"]


async def test_the_series_needs_a_session(charted: Store) -> None:
    async with make_client(charted) as client:
        response = await client.get(f"/api/series?{span(5)}")

    assert (response.status_code, response.headers["location"]) == (303, "/login")


async def test_the_series_is_json_with_names_cleaned_and_markup_escaped(charted: Store) -> None:
    async with logged_in(charted) as (client, _):
        response = await client.get(f"/api/series?{span(5)}")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    assert "<" not in response.text
    body = json.loads(response.text)
    assert (body["step"], body["now"]) == (60, epoch(NOW))
    assert (body["allowed"][:2], body["blocked"][:2]) == ([1, 2], [1, 0])
    (finding,) = body["findings"]
    assert finding["about"].endswith("evil[.]example")
    assert set(finding) == {"id", "t", "priority", "rule", "about", "status", "profile", "ink"}
    router, pc = body["layers"]  # each profile drawn as its own layer, in config order
    assert [(layer["label"], layer["ink"]) for layer in (router, pc)] == [("router", 1), ("pc", 2)]
    assert (router["allowed"][:2], router["blocked"][:2]) == ([1, 1], [1, 0])
    assert (pc["allowed"][:2], pc["blocked"][:2]) == ([0, 1], [0, 0])
    assert [a + b for a, b in zip(router["allowed"], pc["allowed"], strict=True)] == body["allowed"]


async def test_the_series_never_reaches_past_now(charted: Store) -> None:
    async with logged_in(charted) as (client, _):
        default = (await client.get("/api/series")).json()
        future = (await client.get(f"/api/series?to={epoch(NOW) + 86400}")).json()

    assert default["step"] == 900  # the last 24 hours
    assert default["end"] == future["end"] == epoch(NOW)


async def test_the_chart_can_ask_for_more_bars(charted: Store) -> None:
    async with logged_in(charted) as (client, _):
        default = (await client.get("/api/series")).json()
        wide = (await client.get("/api/series?points=300")).json()
        too_many = (await client.get("/api/series?points=9999")).json()
        bad = await client.get("/api/series?points=many")

    assert (default["step"], len(default["t"])) == (900, 97)
    assert (wide["step"], len(wide["t"])) == (300, 289)
    assert too_many["step"] == 300  # held at 480 bars at most
    assert bad.status_code == 422


@pytest.mark.parametrize("query", ["from=soon", "to=1.5", "from=99999999999999999999"])
async def test_a_bad_time_is_refused(charted: Store, query: str) -> None:
    async with logged_in(charted) as (client, _):
        series = await client.get(f"/api/series?{query}")
        window = await client.get(f"/partials/window?{query}")

    assert series.status_code == window.status_code == 422


async def test_the_window_partial_is_a_safe_fragment(charted: Store) -> None:
    async with logged_in(charted) as (client, _):
        response = await client.get(f"/partials/window?{span(5)}")

    assert response.status_code == 200
    assert "<html" not in response.text
    assert audit(response.text) == []
    assert "&lt;script&gt;" in response.text
    assert "<script>alert" not in response.text
    assert "site[.]example" in response.text
    assert 'href="/findings/' in response.text
    assert 'data-action="clear-detail"' in response.text


async def test_only_the_chart_pages_load_the_chart_code(charted: Store) -> None:
    async with logged_in(charted) as (client, _):
        overview = await client.get("/")
        live = await client.get("/live")
        findings = await client.get("/findings")

    for page in (overview, live):
        assert page.text.count("data-chart ") == 1
        assert 'src="/static/vendor/uPlot-1.6.32.iife.min.js"' in page.text
        assert 'src="/static/charts.js?v=' in page.text
    assert "uPlot" not in findings.text
    assert "every 60s" not in overview.text  # the chart follows live instead of polling
