"""Every dashboard page from fixture data, the findings filters, and triage actions."""

import re

import pytest
from sqlalchemy import select

from sentinel.storage.models import allowlist, audit_log, findings
from sentinel.storage.store import Store
from tests.integration.web_helpers import logged_in
from tests.web_fixture import build_web_fixture

RAW_NAMES = ("bad.example", "fresh-site.example", "ads.example", "c2-site.example", "site0.example")


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    return store


async def finding_id(store: Store, rule: str, target: str | None = None) -> int:
    found = await store.list_findings(rule_id=rule, limit=100)
    return next(f.id for f in found if target is None or f.target == target)


def rows(html: str) -> list[str]:
    return re.findall(r'<tr id="finding-(\d+)"', html)


def assert_no_raw_names(html: str) -> None:
    for name in RAW_NAMES:
        assert name not in html, name


# --- pages -------------------------------------------------------------------------------


async def test_overview_compares_the_last_day_with_the_week(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/")

    html = page.text
    assert page.status_code == 200
    assert "Last 24 hours" in html
    assert "router" in html and "pc" in html
    assert "1 critical" in html and "2 high" in html
    assert "D2" in html and "Kitchen tablet" in html
    assert html.count('class="bar-allowed"') == 24
    assert "threat-intel-allowed" in html and "bad[.]example" in html
    assert_no_raw_names(html)


async def test_findings_default_to_open_ones(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/findings")

    assert page.status_code == 200
    assert len(rows(page.text)) == 6
    assert_no_raw_names(page.text)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("profile=def456", 4),
        ("device=D2", 1),
        ("rule=dga-like", 1),
        ("severity=high", 4),
        ("date=2026-03-14", 4),
        ("status=acknowledged", 0),
        ("profile=abc123&severity=critical", 1),
    ],
)
async def test_findings_can_be_filtered(filled: Store, query: str, expected: int) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get(f"/findings?{query}")

    assert page.status_code == 200
    assert len(rows(page.text)) == expected


async def test_filtering_with_htmx_returns_only_the_table(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/findings?rule=dga-like", headers={"HX-Request": "true"})

    assert "<html" not in page.text
    assert len(rows(page.text)) == 1


async def test_bad_filter_values_are_rejected(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/findings?date=yesterday")

    assert page.status_code == 422


async def test_finding_detail_shows_evidence_enrichment_explanation_and_queries(
    filled: Store,
) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    async with logged_in(filled) as (client, _):
        page = await client.get(f"/findings/{fid}")

    html = page.text
    assert page.status_code == 200
    assert "domain_age_days" in html
    assert "The laptop visited fresh-site[.]example" in html
    assert "Registered 5 days ago" in html
    assert "Not on the top-sites list" in html
    assert "login[.]fresh-site[.]example" in html
    assert "Laptop" in html
    assert_no_raw_names(html)


async def test_an_unknown_finding_is_not_found(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/findings/99999")

    assert page.status_code == 404


async def test_domains_page_lists_allowed_blocked_new_and_young(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/domains")

    html = page.text
    assert page.status_code == 200
    assert "site0[.]example" in html and ">50<" in html
    assert "ads[.]example" in html
    assert "recipes[.]example" in html
    assert "fresh-site[.]example" in html and "5 days" in html
    assert_no_raw_names(html)


async def test_devices_page_shows_devices_or_why_there_are_none(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/devices")

    html = page.text
    assert page.status_code == 200
    assert "Device attribution unavailable" in html
    assert "Laptop" in html and "Kitchen tablet" in html


async def test_digests_page_lists_and_shows_archived_digests(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        listing = await client.get("/digests")
        digest_id = re.search(r'href="/digests/(\d+)"', listing.text)
        assert digest_id
        detail = await client.get(f"/digests/{digest_id.group(1)}")

    assert "Sentinel digest 2026-03-15: 1 critical, 2 high" in listing.text
    assert "pending" in listing.text
    assert "QUERIES AND BLOCKING" in detail.text
    assert_no_raw_names(detail.text)


async def test_health_page_shows_lag_queues_latency_and_cache(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/health")

    html = page.text
    assert page.status_code == 200
    assert "No events from pc for 3 h 0 min" in html
    assert "p50 3.0 s" in html and "p95 4.8 s" in html
    assert "25%" in html
    assert "Local model" in html


async def test_evaluation_page_explains_that_nothing_has_run(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/evaluation")

    assert page.status_code == 200
    assert "No evaluation has run yet" in page.text


# --- triage ------------------------------------------------------------------------------


async def state(store: Store, fid: int) -> tuple[str, list[str], list[tuple[str, str]]]:
    async with store.engine.connect() as connection:
        status = (
            await connection.execute(select(findings.c.status).where(findings.c.id == fid))
        ).scalar_one()
        roots = [
            row.root
            for row in await connection.execute(
                select(allowlist.c.root).where(allowlist.c.finding_id == fid)
            )
        ]
        audit = [
            (row.action, row.detail)
            for row in await connection.execute(
                select(audit_log.c.action, audit_log.c.detail)
                .where(audit_log.c.finding_id == fid)
                .order_by(audit_log.c.id)
            )
        ]
    return status, roots, audit


async def test_acknowledging_updates_the_row_and_the_audit_log(filled: Store) -> None:
    fid = await finding_id(filled, "dga-like")
    async with logged_in(filled) as (client, csrf):
        response = await client.post(
            f"/findings/{fid}/acknowledge",
            data={"csrf_token": csrf},
            headers={"HX-Request": "true"},
        )

    assert response.status_code == 200
    assert "<html" not in response.text
    assert "acknowledged" in response.text
    status, roots, audit = await state(filled, fid)
    assert (status, roots) == ("acknowledged", [])
    assert [action for action, _ in audit] == ["acknowledge"]


async def test_marking_a_domain_finding_benign_allowlists_its_root(filled: Store) -> None:
    fid = await finding_id(filled, "threat-intel-allowed")
    async with logged_in(filled) as (client, csrf):
        await client.post(f"/findings/{fid}/benign", data={"csrf_token": csrf})

    status, roots, audit = await state(filled, fid)
    assert (status, roots) == ("benign", ["bad.example"])
    assert audit[0][0] == "mark_benign"
    assert "bad.example" in audit[0][1]


async def test_marking_a_device_finding_benign_allowlists_nothing(filled: Store) -> None:
    fid = await finding_id(filled, "new-device")
    async with logged_in(filled) as (client, csrf):
        await client.post(f"/findings/{fid}/benign", data={"csrf_token": csrf})

    status, roots, _ = await state(filled, fid)
    assert (status, roots) == ("benign", [])


async def test_reopening_undoes_the_allowlist_entry(filled: Store) -> None:
    fid = await finding_id(filled, "threat-intel-allowed")
    async with logged_in(filled) as (client, csrf):
        await client.post(f"/findings/{fid}/benign", data={"csrf_token": csrf})
        await client.post(f"/findings/{fid}/reopen", data={"csrf_token": csrf})

    status, roots, audit = await state(filled, fid)
    assert (status, roots) == ("open", [])
    assert [action for action, _ in audit] == ["mark_benign", "reopen"]


@pytest.mark.parametrize(
    ("next_url", "location"),
    [
        ("/findings?status=open", "/findings?status=open"),
        ("//evil.example/", "/findings"),
        ("https://evil.example/", "/findings"),
        ("", "/findings"),
    ],
)
async def test_plain_form_posts_redirect_only_within_the_dashboard(
    filled: Store, next_url: str, location: str
) -> None:
    fid = await finding_id(filled, "dga-like")
    async with logged_in(filled) as (client, csrf):
        response = await client.post(
            f"/findings/{fid}/acknowledge", data={"csrf_token": csrf, "next": next_url}
        )

    assert (response.status_code, response.headers["location"]) == (303, location)


async def test_actions_on_an_unknown_finding_are_not_found(filled: Store) -> None:
    async with logged_in(filled) as (client, csrf):
        response = await client.post("/findings/99999/benign", data={"csrf_token": csrf})

    assert response.status_code == 404
