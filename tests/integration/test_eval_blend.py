"""Synthetic attacks blended into a replay of a seeded history."""

import random
from datetime import timedelta
from itertools import pairwise
from pathlib import Path
from typing import Any

from tests.integration.test_eval import FEED, NOW, scratch_store, seed_reference
from vedette.eval import blend, datasets
from vedette.eval.detection import Detector, ReplayResult
from vedette.rules.loader import load_rules
from vedette.sources.base import DnsEvent
from vedette.storage.store import Store

PROFILE = "abc123"
DEVICES = ("laptop", "phone")
LEARNING = timedelta(days=3)
START = NOW - timedelta(days=10)
EVERY = timedelta(minutes=5)


def seeded(seed: int) -> random.Random:
    """A repeatable draw for placing attacks."""
    return random.Random(seed)  # noqa: S311 - not for secrets


def history(devices: tuple[str | None, ...] = DEVICES, days: float = 10) -> list[DnsEvent]:
    """Each device looks up a top site every five minutes."""
    count = int(timedelta(days=days) / EVERY)
    return [
        DnsEvent(
            event_id=f"h-{device}-{n}",
            profile_id=PROFILE,
            ts=START + n * EVERY,
            fqdn=f"www.site{n % 50 + 1}.example",
            root=f"site{n % 50 + 1}.example",
            status="default",
            device_id=device,
            device_name=f"{device} name" if device else None,
            client_ip="192.0.2.10",
            source="api",
        )
        for device in devices
        for n in range(count)
    ]


async def run(store: Store, tmp_path: Path) -> tuple[dict[str, Any], ReplayResult]:
    feeds = [datasets.Name(name, name) for name in FEED]
    scratch = await scratch_store(tmp_path)
    try:
        async with Detector(store.engine, scratch.engine, load_rules(), NOW) as detector:
            clean = await detector.replay(store, [PROFILE], allowlist=[], learning=LEARNING)
            result = await blend.attacks_in_traffic(
                detector,
                store,
                [PROFILE],
                allowlist=[],
                learning=LEARNING,
                clean=clean,
                families=datasets.family_names(),
                feeds=feeds,
            )
    finally:
        await scratch.close()
    return result, clean


async def test_attacks_in_the_history_are_found_and_timed(store: Store, tmp_path: Path) -> None:
    await seed_reference(store)
    await store.save_events(history())

    result, clean = await run(store, tmp_path)

    assert (result["sessions"], result["placed"], result["devices"]) == (83, 83, 2)
    rows = {row["attack"]: row for row in result["kinds"]}
    bursts = rows["Burst of 30 random-character domains in 5 minutes"]
    assert (bursts["detected"], bursts["alone"], bursts["by_rule"]["dga-burst"]) == (10, 10, 10)
    families = rows["Burst of 30 domains from a real DGA family in 5 minutes"]
    assert (families["placed"], families["detected"]) == (13, 13)
    fast = rows["Tunnel, 40 lookups in 5 minutes"]
    assert fast["by_rule"]["tunnel-like"] == 10
    # The 31st different long subdomain fires it: 30 of 40 lookups into 5 minutes.
    assert fast["max_minutes"] == 3.75
    sustained = rows["Tunnel, a lookup a minute for 2 hours"]
    assert sustained["by_rule"]["tunnel-slow"] == 10
    slow = rows["Tunnel, 20 lookups in 10 minutes"]
    assert "tunnel-like" not in slow["by_rule"]
    assert slow["detected"] == slow["alone"]
    young = rows["Visit to a domain registered under 30 days ago"]
    assert (young["detected"], young["by_rule"], young["max_minutes"]) == (
        10,
        {"young-domain": 10},
        0.0,
    )
    feed = rows["Visit to a threat-feed domain"]
    assert (feed["detected"], feed["alerting"]) == (10, 10)  # threat-intel-allowed is critical
    assert all(row["ci"] is not None for row in result["kinds"])
    # Ordinary lookups of top sites raise nothing, with the attacks or without.
    assert clean.findings == {}
    assert result["own"] == []


async def test_attacks_go_to_real_devices_after_learning_and_apart(store: Store) -> None:
    events = history()
    await store.save_events(events)
    seen = {(event.device_id, event.ts) for event in events}
    durations = [timedelta(hours=2)] * 10 + [timedelta(minutes=5)] * 40

    spots = await blend.place(store.engine, [PROFILE], durations, learning=LEARNING, rng=seeded(1))

    assert all(spot is not None for spot in spots)
    placed = [(spot, duration) for spot, duration in zip(spots, durations, strict=True) if spot]
    for spot, _ in placed:
        assert spot.start >= START + LEARNING
        # Just after one of the device's own lookups, with its name and address.
        assert (spot.device_id, spot.start - timedelta(seconds=1)) in seen
        assert (spot.device_name, spot.client_ip) == (f"{spot.device_id} name", "192.0.2.10")
    for device in DEVICES:
        mine = sorted(
            (spot.start, spot.start + duration)
            for spot, duration in placed
            if spot.device_id == device
        )
        assert all(later[0] - earlier[1] >= blend.GAP for earlier, later in pairwise(mine))
    assert {spot.device_id for spot, _ in placed} == set(DEVICES)


async def test_a_profile_without_devices_is_attacked_as_a_whole(store: Store) -> None:
    await store.save_events(history(devices=(None,)))

    spots = await blend.place(
        store.engine, [PROFILE], [timedelta(minutes=5)] * 5, learning=LEARNING, rng=seeded(2)
    )

    assert [spot.device_id if spot else "missing" for spot in spots] == [None] * 5


async def test_a_history_inside_its_learning_period_takes_no_attack(
    store: Store, tmp_path: Path
) -> None:
    await seed_reference(store)
    await store.save_events(history(days=2))

    result, clean = await run(store, tmp_path)

    assert (result["placed"], result["lookups"], result["devices"]) == (0, 0, 0)
    assert all(row["placed"] == 0 and row["rate"] is None for row in result["kinds"])
    # Alone still runs, so the table can be compared with the detection sets.
    assert sum(row["alone"] for row in result["kinds"]) > 0
    assert clean.events == len(DEVICES) * int(timedelta(days=2) / EVERY)


async def test_findings_on_blended_lookups_are_kept_apart_from_the_history(
    store: Store, tmp_path: Path
) -> None:
    await seed_reference(store)
    await store.save_events(history(days=4))
    young = DnsEvent(
        event_id="attack-0-0-0",
        profile_id=PROFILE,
        ts=START + timedelta(days=3, hours=12),
        fqdn="www.brand-new.example",
        root="brand-new.example",
        status="default",
        device_id="laptop",
        source="eval",
    )
    scratch = await scratch_store(tmp_path)
    try:
        async with Detector(store.engine, scratch.engine, load_rules(), NOW) as detector:
            replayed = await detector.replay(
                store,
                [PROFILE],
                allowlist=[],
                learning=LEARNING,
                blend=[young],
                ages={"brand-new.example": 3},
            )
    finally:
        await scratch.close()

    assert replayed.findings == {}
    assert [(hit.event_id, hit.rule, hit.ts) for hit in replayed.hits] == [
        ("attack-0-0-0", "young-domain", young.ts)
    ]
    assert replayed.events == len(DEVICES) * int(timedelta(days=4) / EVERY)
