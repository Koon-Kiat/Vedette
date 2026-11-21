"""The daily digest: what it counts, how it reads, and when it is produced."""

import os
from datetime import UTC, datetime, time, timedelta
from pathlib import Path

import pytest

from tests.digest_fixture import PERIOD_END, PERIOD_START, PROFILES, TZ, build_fixture
from vedette.notify.digest import DigestBuilder, render_digest
from vedette.pipeline.notifier import DigestScheduler
from vedette.sources.nextdns import parse_log_entry
from vedette.storage.notifications import NotificationStore
from vedette.storage.store import Store

EXAMPLE = Path(__file__).resolve().parents[2] / "docs" / "example-digest.txt"


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_fixture(store)
    return store


@pytest.fixture
def builder(store: Store) -> DigestBuilder:
    return DigestBuilder(store.engine, profiles=PROFILES, tz=TZ)


# --- what the digest contains ------------------------------------------------------------


async def test_findings_are_counted_by_effective_priority_against_the_week(
    filled: Store, builder: DigestBuilder
) -> None:
    digest = await builder.build(PERIOD_END)

    assert (digest.period_start, digest.period_end) == (PERIOD_START, PERIOD_END)
    assert digest.counts == {"critical": 1, "high": 2, "medium": 2, "low": 0, "info": 0}
    assert digest.counts_avg["high"] == pytest.approx(1 / 7)
    assert digest.counts_avg["critical"] == 0


async def test_finding_groups_are_ranked_most_serious_first(
    filled: Store, builder: DigestBuilder
) -> None:
    digest = await builder.build(PERIOD_END)

    assert [(g.priority.value, g.rule_id) for g in digest.groups] == [
        ("critical", "threat-intel-allowed"),
        ("high", "volume-spike"),
        ("high", "young-domain"),
        ("medium", "new-device"),
        ("medium", "dga-like"),
    ]
    top = digest.groups[0]
    assert (top.events, top.findings, top.target) == (3, 1, "bad.example")
    assert top.summary.startswith("A device on the router profile reached")
    assert top.explained_by == "qwen3:8b"
    assert digest.groups[-1].explained_by is None


async def test_query_volume_and_blocking_are_compared_with_the_week(
    filled: Store, builder: DigestBuilder
) -> None:
    digest = await builder.build(PERIOD_END)

    router, pc = digest.volumes
    assert (router.profile, router.queries, router.blocked) == ("router", 150, 30)
    assert (router.avg_queries, router.avg_blocked_pct) == (100.0, 10.0)
    assert router.device_attribution is False
    assert (pc.profile, pc.queries, pc.blocked) == ("pc", 65, 0)
    assert (pc.avg_queries, pc.avg_blocked_pct) == (40.0, 5.0)
    assert pc.device_attribution is True


async def test_top_blocked_domains_and_blocklists(filled: Store, builder: DigestBuilder) -> None:
    digest = await builder.build(PERIOD_END)

    assert [(c.name, c.count) for c in digest.top_blocked] == [
        ("ads.example", 20),
        ("tracker.example", 10),
    ]
    assert [(c.name, c.count) for c in digest.top_blocklists] == [
        ("HaGeZi Multi", 20),
        ("Native Tracking (Windows)", 10),
    ]


async def test_new_devices_and_health_are_included(filled: Store, builder: DigestBuilder) -> None:
    digest = await builder.build(PERIOD_END)

    assert [(d.profile, d.device, d.name) for d in digest.new_devices] == [
        ("pc", "D2", "Kitchen tablet")
    ]
    assert digest.health is not None
    assert [(h.label, h.ok) for h in digest.health] == [
        ("NextDNS API (router)", True),
        ("Events from pc", False),
        ("Local model", True),
    ]


async def test_an_empty_database_gives_an_empty_but_valid_digest(builder: DigestBuilder) -> None:
    digest = await builder.build(PERIOD_END)

    title, body = render_digest(digest)
    assert title == "Vedette digest 2026-03-15: no high or critical findings"
    assert "No findings in this period." in body
    assert "No health checks have run yet." in body
    assert "device attribution unavailable" not in body, "no traffic says nothing about devices"


# --- how it reads -------------------------------------------------------------------------


async def test_rendered_digest_reads_well_and_is_safe(
    filled: Store, builder: DigestBuilder
) -> None:
    title, body = render_digest(await builder.build(PERIOD_END))

    assert title == "Vedette digest 2026-03-15: 1 critical, 2 high"
    assert "Covers 2026-03-14 08:00 to 2026-03-15 08:00 (Asia/Singapore)" in body
    assert "1 critical, 2 high, 2 medium, 0 low" in body
    assert "7-day average: 0 critical, 0.1 high" in body
    assert "router: 150 queries, 30 blocked (20.0%)" in body
    assert "device attribution unavailable" in body
    assert "ads[.]example (20)" in body
    assert "pc: D2 (Kitchen tablet)" in body
    assert "PROBLEM since 2026-03-15 05:00: No events from pc for 3 h 0 min" in body
    for raw in ("bad.example", "fresh-site.example", "ads.example", "c2-site.example"):
        assert raw not in body
        assert raw not in title


async def test_example_digest_in_the_docs_matches_the_renderer(
    filled: Store, builder: DigestBuilder
) -> None:
    title, body = render_digest(await builder.build(PERIOD_END))
    rendered = f"Subject: {title}\n\n{body}\n"

    if os.environ.get("UPDATE_EXAMPLE_DIGEST") == "1":
        EXAMPLE.write_text(rendered, encoding="utf-8", newline="\n")

    assert EXAMPLE.read_text(encoding="utf-8") == rendered, (
        "docs/example-digest.txt is out of date: rerun the tests with UPDATE_EXAMPLE_DIGEST=1"
    )


# --- when it is produced ---------------------------------------------------------------------


class Clock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def local(day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 3, day, hour, minute, tzinfo=TZ).astimezone(UTC)


def scheduler(store: Store, builder: DigestBuilder, clock: Clock) -> DigestScheduler:
    return DigestScheduler(
        NotificationStore(store.engine),
        builder,
        digest_time=time(8, 0),
        tz=TZ,
        clock=clock,
        started_at=clock.now,
    )


async def test_the_first_digest_comes_at_the_first_digest_time_after_start(
    store: Store, builder: DigestBuilder
) -> None:
    clock = Clock(local(15, 7, 0))
    digests = scheduler(store, builder, clock)

    clock.now = local(15, 7, 30)
    assert await digests.run_once() is False

    clock.now = local(
        15,
        8,
        0,
    ) + timedelta(seconds=30)
    assert await digests.run_once() is True
    assert await digests.run_once() is False

    outbox = NotificationStore(store.engine)
    (stored,) = await outbox.digests(limit=10)
    assert (stored.period_start, stored.period_end) == (local(14, 8), local(15, 8))
    (queued,) = await outbox.recent(limit=10)
    assert (queued.kind, queued.status) == ("digest", "pending")
    assert queued.title == stored.title


async def test_starting_after_the_digest_time_waits_for_the_next_day(
    store: Store, builder: DigestBuilder
) -> None:
    clock = Clock(local(15, 9, 0))
    digests = scheduler(store, builder, clock)

    assert await digests.run_once() is False
    clock.now = local(16, 8, 0)
    assert await digests.run_once() is True


async def test_a_first_digest_missed_while_the_computer_was_off_comes_late(
    store: Store, builder: DigestBuilder
) -> None:
    profile = PROFILES[0].id
    await store.save_events(
        [
            parse_log_entry(
                profile,
                {
                    "timestamp": local(14, 21).isoformat(),
                    "domain": "a.example",
                    "status": "default",
                },
            )
        ]
    )
    clock = Clock(local(15, 10, 30))  # switched on after the 08:00 digest time
    digests = DigestScheduler(
        NotificationStore(store.engine),
        builder,
        digest_time=time(8, 0),
        tz=TZ,
        clock=clock,
        started_at=clock.now,
        oldest_data=lambda: store.earliest_event_ts(profile),
    )

    assert await digests.run_once() is True
    assert await digests.run_once() is False
    (stored,) = await NotificationStore(store.engine).digests(limit=10)
    assert (stored.period_start, stored.period_end) == (local(14, 8), local(15, 8))


async def test_a_missed_digest_is_sent_late_but_only_once(
    store: Store, builder: DigestBuilder
) -> None:
    clock = Clock(local(15, 7, 0))
    first = scheduler(store, builder, clock)
    clock.now = local(15, 8, 1)
    await first.run_once()

    clock.now = local(18, 9, 30)  # the service was down for three days
    restarted = scheduler(store, builder, clock)
    assert await restarted.run_once() is True
    assert await restarted.run_once() is False

    stored = await NotificationStore(store.engine).digests(limit=10)
    assert [d.period_end for d in stored] == [local(18, 8), local(15, 8)]


def test_large_numbers_are_easy_to_read() -> None:
    from vedette.notify.digest import Digest, VolumeLine

    digest = Digest(
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        timezone="Asia/Singapore",
        counts=dict.fromkeys(["critical", "high", "medium", "low", "info"], 0),
        counts_avg=dict.fromkeys(["critical", "high", "medium", "low", "info"], None),
        groups=[],
        groups_total=0,
        new_devices=[],
        volumes=[
            VolumeLine(
                profile="router",
                queries=34201,
                blocked=2942,
                avg_queries=26535.7,
                avg_blocked_pct=9.3,
                device_attribution=False,
            )
        ],
        top_blocked=[],
        top_blocklists=[],
        health=None,
    )

    _, body = render_digest(digest)

    assert "router: 34,201 queries, 2,942 blocked (8.6%); 7-day average 26,536 queries" in body
