"""Fixes from the dashboard evaluation: plain words, honest gaps, error pages, keyboard paths."""

from datetime import timedelta

import pytest

from sentinel.config import ProfileConfig
from sentinel.storage.health import HealthCheck, HealthStore
from sentinel.storage.store import Store
from tests.digest_fixture import PROFILES, _event
from tests.integration.web_helpers import NOW, hidden, logged_in, make_client
from tests.web_fixture import build_web_fixture


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    return store


async def test_evidence_is_labelled_in_words(filled: Store) -> None:
    fid = next(f.id for f in await filled.list_findings(limit=100) if f.rule_id == "young-domain")
    async with logged_in(filled) as (client, _):
        html = (await client.get(f"/findings/{fid}")).text

    assert "Evidence when it fired" in html
    assert "What the local caches know now" in html
    assert (
        '<th scope="row">Name queried</th>' in html
        and '<th scope="row">Domain age, days</th>' in html
    )
    assert "domain_age_days" not in html and "<th>fqdn</th>" not in html
    assert "<td>allowed</td>" in html and "<td>default</td>" not in html


async def test_health_details_keep_numbers_and_point_at_the_settings(filled: Store) -> None:
    await HealthStore(filled.engine).save(
        [
            HealthCheck(
                "disk", "Disk space", True, "Disk 2% full (935.5 GB free), see api.example.net"
            ),
            HealthCheck(
                "events:def456", "Events from pc", False, "No events from pc for 3 h 0 min"
            ),
        ],
        now=NOW,
    )
    async with logged_in(filled) as (client, _):
        html = (await client.get("/health")).text

    assert "935.5 GB free" in html and "935[.]5" not in html
    assert "api[.]example[.]net" in html
    assert "<code>stale_after_minutes</code>" in html


async def test_a_silent_profile_is_called_silent_not_unattributed(filled: Store) -> None:
    profiles = [*PROFILES, ProfileConfig(id="abcdef", label="spare")]
    async with logged_in(filled, profiles=profiles) as (client, _):
        html = (await client.get("/devices")).text

    assert "No queries from this profile in the last 7 days" in html
    assert html.count("Device attribution unavailable") == 1  # the router only


async def test_a_missing_finding_says_so_and_keeps_the_menu(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/findings/99999")

    assert page.status_code == 404
    assert "There is no finding 99999." in page.text
    assert 'class="rail"' in page.text


async def test_an_unknown_page_without_a_session_stays_bare(filled: Store) -> None:
    async with make_client(filled) as client:
        page = await client.get("/no-such-page")

    assert page.status_code == 404
    assert "That page does not exist." in page.text
    assert 'class="rail"' not in page.text


async def test_a_wrong_token_is_tied_to_the_field(filled: Store) -> None:
    async with make_client(filled) as client:
        form = await client.get("/login")
        page = await client.post(
            "/login", data={"login_nonce": hidden(form.text, "login_nonce"), "token": "wrong"}
        )

    assert page.status_code == 401
    assert 'aria-invalid="true"' in page.text
    assert 'aria-describedby="login-error"' in page.text and 'id="login-error"' in page.text
    assert "must match DASHBOARD_TOKEN in your .env file exactly" in page.text


async def test_the_digests_page_names_the_digest_time(store: Store) -> None:
    async with logged_in(store, digest_time="08:00") as (client, _):
        html = (await client.get("/digests")).text

    assert "The first one is produced at 08:00 (Asia/Singapore)." in html


async def test_pages_offer_a_skip_link_and_a_status_region(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        html = (await client.get("/findings")).text

    assert '<a class="skip-link" href="#main">Skip to the content</a>' in html
    assert '<main id="main" tabindex="-1">' in html
    assert 'role="status" data-live="announce"' in html


async def test_our_static_files_are_versioned_and_revalidated(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        page = await client.get("/")
        url = (
            "/static/style.css" + page.text.split('href="/static/style.css', 1)[1].split('"', 1)[0]
        )
        css = await client.get(url)

    assert url.startswith("/static/style.css?v=") and len(url.split("v=")[1]) == 12
    assert css.status_code == 200
    assert css.headers["cache-control"] == "no-cache"


async def test_the_live_line_counts_in_words_and_rows_carry_their_time(filled: Store) -> None:
    moment = NOW - timedelta(seconds=10)
    await filled.save_events([_event("abc123", moment, "www.one.example")])
    async with logged_in(filled) as (client, _):
        html = (await client.get("/")).text

    assert '<span data-live="queries-word">query</span> in the last minute' in html
    assert f'data-t="{int(moment.timestamp())}"' in html  # the feed orders rows by it
