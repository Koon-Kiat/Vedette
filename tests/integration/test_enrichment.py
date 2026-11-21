"""Enrichment against a real SQLite database, with every HTTP source mocked."""

from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx

from tests.unit.rule_helpers import T0, event
from tests.unit.test_reference_parsing import tranco_zip
from vedette.enrich.enricher import Enricher
from vedette.enrich.first_seen import FirstSeenTracker
from vedette.enrich.popularity import PopularityList
from vedette.enrich.public_suffix import PublicSuffixList
from vedette.enrich.rdap import DomainAges, RdapClient
from vedette.enrich.threat_intel import Feed, ThreatIntel
from vedette.storage.reference import ReferenceStore
from vedette.storage.store import Store

NOW = T0 + timedelta(minutes=5)
TRANCO_URL = "https://lists.test/top-1m.csv.zip"
FEED_URL = "https://feeds.test/phish.txt"
BOOTSTRAP_URL = "https://bootstrap.test/dns.json"
RDAP_BASE = "https://rdap.test/v1/"
BOOTSTRAP = {"services": [[["example", "org"], [RDAP_BASE]], [["nordap"], []]]}


def rdap_answer(registered: datetime) -> dict[str, object]:
    return {
        "objectClassName": "domain",
        "events": [
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            {
                "eventAction": "registration",
                "eventDate": registered.isoformat().replace("+00:00", "Z"),
            },
        ],
    }


@pytest.fixture
def web() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        router.get(BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
        yield router


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(follow_redirects=True) as created:
        yield created


@pytest.fixture
def reference(store: Store) -> ReferenceStore:
    return ReferenceStore(store.engine)


# --- popularity -----------------------------------------------------------------


async def test_popularity_is_unknown_until_a_list_is_loaded(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    popularity = PopularityList(reference, client, url=TRANCO_URL, refresh_days=7)
    await popularity.load()

    assert popularity.known is False
    assert await popularity.ranks(["google.com"]) == {"google.com": None}


async def test_popularity_refresh_downloads_and_serves_ranks(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    web.get(TRANCO_URL).mock(
        return_value=httpx.Response(200, content=tranco_zip("1,google.com\r\n2,example.org\r\n"))
    )
    popularity = PopularityList(reference, client, url=TRANCO_URL, refresh_days=7)

    assert await popularity.refresh_if_stale(NOW) is True

    assert popularity.known is True
    assert await popularity.ranks(["example.org", "nobody.example"]) == {
        "example.org": 2,
        "nobody.example": None,
    }


async def test_popularity_is_refreshed_weekly_not_on_every_check(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    route = web.get(TRANCO_URL).mock(
        return_value=httpx.Response(200, content=tranco_zip("1,google.com\r\n"))
    )
    popularity = PopularityList(reference, client, url=TRANCO_URL, refresh_days=7)
    await popularity.refresh_if_stale(NOW)

    assert await popularity.refresh_if_stale(NOW + timedelta(days=6)) is False
    assert route.call_count == 1
    assert await popularity.refresh_if_stale(NOW + timedelta(days=8)) is True
    assert route.call_count == 2


async def test_popularity_survives_a_restart_without_downloading_again(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    route = web.get(TRANCO_URL).mock(
        return_value=httpx.Response(200, content=tranco_zip("1,google.com\r\n"))
    )
    await PopularityList(reference, client, url=TRANCO_URL, refresh_days=7).refresh_if_stale(NOW)

    restarted = PopularityList(reference, client, url=TRANCO_URL, refresh_days=7)
    await restarted.load()

    assert await restarted.refresh_if_stale(NOW + timedelta(hours=1)) is False
    assert restarted.known is True
    assert await restarted.ranks(["google.com"]) == {"google.com": 1}
    assert route.call_count == 1


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(httpx.Response(503), id="server-error"),
        pytest.param(httpx.Response(200, content=b"<html>nope</html>"), id="not-a-zip"),
        pytest.param(httpx.Response(200, content=tranco_zip("garbage\r\n")), id="no-usable-rows"),
        pytest.param(httpx.ConnectError("down"), id="network-error"),
    ],
)
async def test_failed_popularity_refresh_keeps_the_previous_list(
    reference: ReferenceStore,
    client: httpx.AsyncClient,
    web: respx.MockRouter,
    bad: httpx.Response | Exception,
) -> None:
    route = web.get(TRANCO_URL)
    route.mock(return_value=httpx.Response(200, content=tranco_zip("1,google.com\r\n")))
    popularity = PopularityList(reference, client, url=TRANCO_URL, refresh_days=7)
    await popularity.refresh_if_stale(NOW)
    if isinstance(bad, Exception):
        route.mock(side_effect=bad)
    else:
        route.mock(return_value=bad)

    assert await popularity.refresh_if_stale(NOW + timedelta(days=8)) is False

    assert popularity.known is True
    assert await popularity.ranks(["google.com"]) == {"google.com": 1}


# --- threat intelligence ----------------------------------------------------------


def make_intel(reference: ReferenceStore, client: httpx.AsyncClient) -> ThreatIntel:
    feeds = [Feed(name="phish", url=FEED_URL, format="domains")]
    return ThreatIntel(reference, client, feeds=feeds, refresh_hours=24)


async def test_threat_feed_matches_listed_names_and_their_subdomains(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    web.get(FEED_URL).mock(
        return_value=httpx.Response(200, text="# c\nbad.example\nx.evil.example\n")
    )
    intel = make_intel(reference, client)
    await intel.refresh_if_stale(NOW)

    matches = await intel.match_many(
        [
            ("bad.example", "bad.example"),
            ("pay.login.bad.example", "bad.example"),
            ("x.evil.example", "evil.example"),
            ("evil.example", "evil.example"),
            ("y.evil.example", "evil.example"),
            ("notbad.example", "notbad.example"),
        ]
    )

    assert matches["bad.example"] == (("phish",), "bad.example")
    assert matches["pay.login.bad.example"] == (("phish",), "bad.example")
    assert matches["x.evil.example"] == (("phish",), "x.evil.example")
    assert "evil.example" not in matches, "a listed subdomain must not taint its parent"
    assert "y.evil.example" not in matches, "nor its siblings"
    assert "notbad.example" not in matches


async def test_threat_feed_is_refreshed_on_schedule(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    route = web.get(FEED_URL).mock(return_value=httpx.Response(200, text="bad.example\n"))
    intel = make_intel(reference, client)

    assert await intel.refresh_if_stale(NOW) is True
    assert await intel.refresh_if_stale(NOW + timedelta(hours=23)) is False
    assert await intel.refresh_if_stale(NOW + timedelta(hours=25)) is True
    assert route.call_count == 2


async def test_refreshed_feed_replaces_entries_that_were_delisted(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    route = web.get(FEED_URL)
    route.mock(return_value=httpx.Response(200, text="old.example\n"))
    intel = make_intel(reference, client)
    await intel.refresh_if_stale(NOW)
    route.mock(return_value=httpx.Response(200, text="new.example\n"))

    await intel.refresh_if_stale(NOW + timedelta(hours=25))

    matches = await intel.match_many(
        [("old.example", "old.example"), ("new.example", "new.example")]
    )
    assert set(matches) == {"new.example"}


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(httpx.Response(410), id="gone"),
        pytest.param(httpx.Response(200, text="# only comments\n"), id="empty-feed"),
        pytest.param(httpx.ConnectError("down"), id="network-error"),
    ],
)
async def test_failed_or_empty_feed_refresh_keeps_the_previous_entries(
    reference: ReferenceStore,
    client: httpx.AsyncClient,
    web: respx.MockRouter,
    bad: httpx.Response | Exception,
) -> None:
    route = web.get(FEED_URL)
    route.mock(return_value=httpx.Response(200, text="bad.example\n"))
    intel = make_intel(reference, client)
    await intel.refresh_if_stale(NOW)
    if isinstance(bad, Exception):
        route.mock(side_effect=bad)
    else:
        route.mock(return_value=bad)

    assert await intel.refresh_if_stale(NOW + timedelta(hours=25)) is False

    assert set(await intel.match_many([("bad.example", "bad.example")])) == {"bad.example"}


# --- domain age (RDAP) --------------------------------------------------------------


def make_ages(
    reference: ReferenceStore, client: httpx.AsyncClient, enabled: bool = True
) -> DomainAges:
    rdap = RdapClient(client, bootstrap_url=BOOTSTRAP_URL) if enabled else None
    return DomainAges(reference, rdap)


async def test_domain_age_is_days_since_registration(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    web.get(f"{RDAP_BASE}domain/fresh.example").mock(
        return_value=httpx.Response(200, json=rdap_answer(NOW - timedelta(days=5, hours=3)))
    )

    assert await make_ages(reference, client).resolve(["fresh.example"], NOW) == {
        "fresh.example": 5
    }


async def test_domain_age_is_cached_and_survives_a_restart(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    route = web.get(f"{RDAP_BASE}domain/fresh.example").mock(
        return_value=httpx.Response(200, json=rdap_answer(NOW - timedelta(days=5)))
    )
    await make_ages(reference, client).resolve(["fresh.example"], NOW)

    later = NOW + timedelta(days=2)
    restarted = make_ages(reference, client)

    assert await restarted.resolve(["fresh.example"], later) == {"fresh.example": 7}
    assert await restarted.cached(["fresh.example", "never.example"], later) == {
        "fresh.example": 7,
        "never.example": None,
    }
    assert route.call_count == 1


async def test_unregistered_or_dateless_domains_are_unknown_and_not_asked_again_soon(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    missing = web.get(f"{RDAP_BASE}domain/gone.example").mock(return_value=httpx.Response(404))
    dateless = web.get(f"{RDAP_BASE}domain/nodate.example").mock(
        return_value=httpx.Response(200, json={"objectClassName": "domain", "events": []})
    )
    ages = make_ages(reference, client)

    for _ in range(2):
        result = await ages.resolve(["gone.example", "nodate.example"], NOW)
        assert result == {"gone.example": None, "nodate.example": None}

    assert missing.call_count == 1
    assert dateless.call_count == 1


async def test_rdap_outage_is_unknown_and_is_retried_next_time(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    route = web.get(f"{RDAP_BASE}domain/fresh.example")
    route.mock(return_value=httpx.Response(503))
    ages = make_ages(reference, client)

    assert await ages.resolve(["fresh.example"], NOW) == {"fresh.example": None}

    route.mock(return_value=httpx.Response(200, json=rdap_answer(NOW - timedelta(days=9))))
    assert await ages.resolve(["fresh.example"], NOW) == {"fresh.example": 9}


async def test_tld_without_an_rdap_server_is_unknown_without_any_request(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    ages = make_ages(reference, client)

    assert await ages.resolve(["site.nordap", "site.unlisted"], NOW) == {
        "site.nordap": None,
        "site.unlisted": None,
    }


async def test_names_that_are_not_plain_domains_are_never_sent_to_rdap(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    ages = make_ages(reference, client)
    hostile = "a/../../b.example"

    assert await ages.resolve([hostile, "has space.example"], NOW) == {
        hostile: None,
        "has space.example": None,
    }


async def test_with_rdap_disabled_nothing_is_looked_up(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    ages = make_ages(reference, client, enabled=False)

    assert await ages.resolve(["fresh.example"], NOW) == {"fresh.example": None}
    assert not web.calls


# --- first seen ---------------------------------------------------------------------


async def test_first_seen_flags_are_true_once_and_survive_a_restart(
    reference: ReferenceStore,
) -> None:
    tracker = await FirstSeenTracker.load(reference)
    first = event(fqdn="a.site.example", root="site.example", device="D1", n=1)
    second = event(fqdn="b.site.example", root="site.example", device="D1", n=2)

    assert tracker.observe(first).new_device is True
    assert tracker.observe(first).new_root_for_profile is True
    assert tracker.observe(second).new_device is False
    assert tracker.observe(second).new_root_for_profile is False
    await tracker.flush()

    restarted = await FirstSeenTracker.load(reference)
    third = event(fqdn="c.site.example", root="site.example", device="D1", n=3)
    assert restarted.observe(third).new_device is False
    assert restarted.observe(third).new_root_for_device is False


async def test_re_enriching_the_same_event_gives_the_same_flags(
    reference: ReferenceStore,
) -> None:
    tracker = await FirstSeenTracker.load(reference)
    first = event(device="D1", n=1)
    tracker.observe(first)
    await tracker.flush()

    restarted = await FirstSeenTracker.load(reference)

    assert restarted.observe(first).new_device is True, (
        "a replayed batch must not lose its findings"
    )


async def test_first_seen_tracks_devices_addresses_roots_and_categories_separately(
    reference: ReferenceStore,
) -> None:
    tracker = await FirstSeenTracker.load(reference)
    tracker.observe(event(device="D1", n=1))

    other_device = tracker.observe(
        event(device="D2", client_ip="203.0.113.9", reasons=(("blocklist:x", "X"),), n=2)
    )

    assert other_device.new_device is True
    assert other_device.new_client_ip is True
    assert other_device.new_root_for_profile is False
    assert other_device.new_root_for_device is True
    assert other_device.new_categories == ("blocklist:x",)


async def test_first_seen_without_device_data_keys_on_the_profile(
    reference: ReferenceStore,
) -> None:
    tracker = await FirstSeenTracker.load(reference)

    first = tracker.observe(event(device=None, reasons=(("blocklist:x", "X"),), n=1))
    second = tracker.observe(event(device=None, reasons=(("blocklist:x", "X"),), n=2))

    assert first.new_device is False, "there is no device to be new"
    assert first.new_client_ip is True
    assert first.new_categories == ("blocklist:x",)
    assert second.new_client_ip is False
    assert second.new_categories == ()


# --- the enricher as a whole --------------------------------------------------------------


async def make_enricher(
    reference: ReferenceStore,
    client: httpx.AsyncClient,
    web: respx.MockRouter,
    suffixes: PublicSuffixList | None = None,
    **kw: int,
) -> Enricher:
    web.get(TRANCO_URL).mock(
        return_value=httpx.Response(200, content=tranco_zip("1,example.org\r\n"))
    )
    web.get(FEED_URL).mock(return_value=httpx.Response(200, text="bad.example\n"))
    popularity = PopularityList(reference, client, url=TRANCO_URL, refresh_days=7)
    intel = make_intel(reference, client)
    await popularity.refresh_if_stale(NOW)
    await intel.refresh_if_stale(NOW)
    return Enricher(
        popularity=popularity,
        threat_intel=intel,
        ages=make_ages(reference, client),
        first_seen=await FirstSeenTracker.load(reference),
        rdap_max_event_age=timedelta(hours=24),
        rdap_max_lookups_per_batch=kw.get("max_lookups", 20),
        suffixes=suffixes,
    )


async def test_enricher_adds_every_kind_of_context(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    web.get(f"{RDAP_BASE}domain/fresh.example").mock(
        return_value=httpx.Response(200, json=rdap_answer(NOW - timedelta(days=5)))
    )
    web.get(f"{RDAP_BASE}domain/bad.example").mock(return_value=httpx.Response(404))
    enricher = await make_enricher(reference, client, web)
    batch = [
        event(fqdn="www.example.org", root="example.org", n=1),
        event(fqdn="xkq7vbn2mtrp9zlw.fresh.example", root="fresh.example", n=2),
        event(fqdn="pay.bad.example", root="bad.example", n=3),
    ]

    popular, fresh, listed = await enricher.enrich_batch(batch, NOW)

    assert (popular.popularity_rank, popular.popularity_known) == (1, True)
    assert popular.domain_age_days is None
    assert popular.new_device is True
    assert fresh.popularity_rank is None
    assert fresh.domain_age_days == 5
    assert fresh.lexical.label == "xkq7vbn2mtrp9zlw"
    assert fresh.new_device is False
    assert fresh.new_root_for_profile is True
    assert listed.threat_feeds == ("phish",)
    assert listed.threat_match == "bad.example"


async def test_enricher_asks_rdap_only_about_recent_allowed_unpopular_roots(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    rdap = web.get(url__startswith=f"{RDAP_BASE}domain/").mock(return_value=httpx.Response(404))
    enricher = await make_enricher(reference, client, web)
    batch = [
        event(fqdn="www.example.org", root="example.org", n=1),  # popular
        event(fqdn="a.blocked.example", root="blocked.example", status="blocked", n=2),
        event(fqdn="a.old.example", root="old.example", at=-timedelta(days=3), n=3),  # history
        event(fqdn="a.recent.example", root="recent.example", n=4),
        event(fqdn="b.recent.example", root="recent.example", n=5),
    ]

    await enricher.enrich_batch(batch, NOW)

    assert [str(call.request.url) for call in rdap.calls] == [f"{RDAP_BASE}domain/recent.example"]


async def test_enricher_caps_rdap_lookups_per_batch(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    rdap = web.get(url__startswith=f"{RDAP_BASE}domain/").mock(return_value=httpx.Response(404))
    enricher = await make_enricher(reference, client, web, max_lookups=3)
    batch = [event(fqdn=f"a.site{n}.example", root=f"site{n}.example", n=n) for n in range(10)]

    await enricher.enrich_batch(batch, NOW)

    assert rdap.call_count == 3


def test_now_is_timezone_aware() -> None:
    assert NOW.tzinfo is UTC


async def test_enricher_reports_the_rank_of_the_platform_a_name_is_hosted_on(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    rdap = web.get(url__startswith=f"{RDAP_BASE}domain/").mock(return_value=httpx.Response(404))
    enricher = await make_enricher(reference, client, web)  # example.org is rank 1
    batch = [
        event(fqdn="x.customer-app.example.org", root="customer-app.example.org", n=1),
        event(fqdn="www.example.org", root="example.org", n=2),
        event(fqdn="a.lonely.example", root="lonely.example", n=3),
    ]

    hosted, popular, lonely = await enricher.enrich_batch(batch, NOW)

    assert (hosted.popularity_rank, hosted.platform_rank) == (None, 1)
    assert (popular.popularity_rank, popular.platform_rank) == (1, None)
    assert (lonely.popularity_rank, lonely.platform_rank) == (None, None)
    asked = [str(call.request.url) for call in rdap.calls]
    assert asked == [f"{RDAP_BASE}domain/lonely.example"], (
        "platform customer names are not registered domains"
    )


# --- the Public Suffix List ---------------------------------------------------------------

PSL_URL = "https://lists.test/public_suffix_list.dat"
PSL = """\
// ===BEGIN ICANN DOMAINS===
org
example
co.uk
uk
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
pages.example
// ===END PRIVATE DOMAINS===
"""


def make_suffixes(reference: ReferenceStore, client: httpx.AsyncClient) -> PublicSuffixList:
    return PublicSuffixList(reference, client, url=PSL_URL, refresh_days=7)


async def test_the_suffix_list_is_unknown_until_downloaded(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    suffixes = make_suffixes(reference, client)
    await suffixes.load()
    assert suffixes.known is False

    web.get(PSL_URL).mock(return_value=httpx.Response(200, text=PSL))
    assert await suffixes.refresh_if_stale(NOW) is True

    assert suffixes.known is True
    assert suffixes.platform_suffix("shop.pages.example") == "pages.example"
    assert await suffixes.refresh_if_stale(NOW + timedelta(days=1)) is False, "weekly"


async def test_the_suffix_list_survives_a_restart(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    web.get(PSL_URL).mock(return_value=httpx.Response(200, text=PSL))
    await make_suffixes(reference, client).refresh_if_stale(NOW)

    restarted = make_suffixes(reference, client)
    await restarted.load()

    assert restarted.known is True
    assert restarted.platform_suffix("shop.pages.example") == "pages.example"


@pytest.mark.parametrize(
    "failure",
    [httpx.Response(503), httpx.Response(200, text="// nothing but comments\n")],
)
async def test_a_failed_suffix_list_refresh_keeps_the_previous_list(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter, failure: Any
) -> None:
    route = web.get(PSL_URL).mock(return_value=httpx.Response(200, text=PSL))
    suffixes = make_suffixes(reference, client)
    await suffixes.refresh_if_stale(NOW)
    route.mock(return_value=failure)

    assert await suffixes.refresh_if_stale(NOW + timedelta(days=8)) is False

    assert suffixes.platform_suffix("shop.pages.example") == "pages.example"


async def test_with_the_suffix_list_platform_customers_are_known_exactly(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    rdap = web.get(url__startswith=f"{RDAP_BASE}domain/").mock(return_value=httpx.Response(404))
    web.get(PSL_URL).mock(return_value=httpx.Response(200, text=PSL))
    suffixes = make_suffixes(reference, client)
    await suffixes.refresh_if_stale(NOW)
    enricher = await make_enricher(reference, client, web, suffixes=suffixes)
    batch = [
        # Under a private suffix that is on no top-sites list: a customer name.
        event(fqdn="www.shop.pages.example", root="shop.pages.example", n=1),
        # Longer than the domain registered under the list: NextDNS knows a
        # platform the list does not, ranked or not.
        event(fqdn="x.abc.unlisted-cdn.example", root="abc.unlisted-cdn.example", n=2),
        # A registered domain of its own.
        event(fqdn="www.fresh-shop.example", root="fresh-shop.example", n=3),
        # The private suffix itself, reported as the root of a customer's name.
        event(fqdn="xkq7vbn2mtrp9zlwqqhr.pages.example", root="pages.example", n=4),
    ]

    hosted, unlisted, own, suffix = await enricher.enrich_batch(batch, NOW)

    assert hosted.is_platform is True
    assert unlisted.is_platform is True
    assert own.is_platform is False
    assert suffix.is_platform is True
    asked = [str(call.request.url) for call in rdap.calls]
    assert asked == [f"{RDAP_BASE}domain/fresh-shop.example"]


async def test_without_the_suffix_list_a_ranked_parent_still_means_platform(
    reference: ReferenceStore, client: httpx.AsyncClient, web: respx.MockRouter
) -> None:
    web.get(url__startswith=f"{RDAP_BASE}domain/").mock(return_value=httpx.Response(404))
    suffixes = make_suffixes(reference, client)  # never downloaded
    enricher = await make_enricher(reference, client, web, suffixes=suffixes)

    (hosted,) = await enricher.enrich_batch(
        [event(fqdn="x.customer-app.example.org", root="customer-app.example.org")], NOW
    )

    assert hosted.is_platform is True
