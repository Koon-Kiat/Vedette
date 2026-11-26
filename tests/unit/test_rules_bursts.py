"""Slow tunnels and bursts of new unknown domains: patterns over time, not single names."""

from datetime import timedelta
from typing import Any

from tests.unit.rule_helpers import engine, enriched, event, fired
from vedette.enrich.model import EnrichedEvent
from vedette.shared.models import AllowlistEntry, Severity

DATA = "0123456789abcdef" * 4


def tunnel_lookup(index: int, minutes: float, root: str = "drip.example") -> EnrichedEvent:
    fqdn = f"{DATA[:24]}{index:08d}.{DATA[:20]}.{root}"
    return enriched(
        event(fqdn=fqdn, root=root, at=timedelta(minutes=minutes), n=index), popularity_rank=None
    )


# --- slow tunnels -------------------------------------------------------------------------


def test_a_tunnel_at_one_lookup_a_minute_is_caught_over_hours() -> None:
    rules = engine()
    found = []
    for index in range(70):  # one a minute: never more than ten in ten minutes
        found += rules.evaluate(tunnel_lookup(index, minutes=index))

    assert fired(found, "tunnel-like") == []
    (slow,) = fired(found, "tunnel-slow")
    assert slow.severity is Severity.MEDIUM
    assert slow.target == "drip.example"
    assert slow.evidence["unique_subdomains"] == 61
    assert slow.evidence["window_minutes"] == 360


def test_long_subdomains_spread_over_more_than_the_window_do_not_add_up() -> None:
    rules = engine()
    found = []
    for index in range(70):  # one every ten minutes: under 40 in any six hours
        found += rules.evaluate(tunnel_lookup(index, minutes=index * 10))

    assert fired(found, "tunnel-slow") == []


def test_a_popular_root_is_not_a_slow_tunnel() -> None:
    rules = engine()
    found = []
    for index in range(70):
        item = tunnel_lookup(index, minutes=index)
        found += rules.evaluate(item.model_copy(update={"popularity_rank": 500}))

    assert fired(found, "tunnel-slow") == []


# --- bursts of new unknown domains -----------------------------------------------------------


def new_root(index: int, seconds: float, **overrides: Any) -> EnrichedEvent:
    root = f"word{index:03d}garden.example"
    values: dict[str, Any] = {
        "popularity_rank": None,
        "new_root_for_device": True,
        "new_root_for_profile": True,
    }
    values.update(overrides)
    return enriched(
        event(fqdn=f"www.{root}", root=root, at=timedelta(seconds=seconds), n=index), **values
    )


def test_many_new_unknown_domains_in_minutes_are_a_burst() -> None:
    rules = engine()
    found = []
    for index in range(25):  # every 10 seconds: 25 in four minutes
        found += rules.evaluate(new_root(index, seconds=index * 10))

    (burst,) = fired(found, "dga-burst")
    assert burst.severity is Severity.MEDIUM
    assert burst.target == "D1"
    assert burst.evidence["new_roots_in_window"] == 21
    assert burst.evidence["window_minutes"] == 10
    assert len(burst.evidence["sample_roots"]) == 5


def test_a_slow_trickle_of_new_domains_is_ordinary_browsing() -> None:
    rules = engine()
    found = []
    for index in range(25):  # one a minute: never more than ten in ten minutes
        found += rules.evaluate(new_root(index, seconds=index * 60))

    assert fired(found, "dga-burst") == []


def test_ranked_known_or_platform_domains_do_not_count() -> None:
    rules = engine()
    kinds: list[dict[str, Any]] = [
        {"popularity_rank": 4000},
        {"new_root_for_device": False, "new_root_for_profile": False},
        {"platform": True},
    ]
    found = []
    for index in range(30):
        found += rules.evaluate(new_root(index, seconds=index * 5, **kinds[index % 3]))

    assert fired(found, "dga-burst") == []


def test_no_burst_is_reported_while_the_profile_is_learning() -> None:
    rules = engine(learning=timedelta(days=3))
    found = []
    for index in range(25):
        found += rules.evaluate(new_root(index, seconds=index * 10))

    assert fired(found, "dga-burst") == []


def test_allowlisted_domains_do_not_count_towards_a_burst() -> None:
    allow = tuple(AllowlistEntry(root=f"word{index:03d}garden.example") for index in range(25))
    rules = engine(allow=allow)
    found = []
    for index in range(25):
        found += rules.evaluate(new_root(index, seconds=index * 10))

    assert fired(found, "dga-burst") == []
