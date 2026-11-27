"""Synthetic attacks blended into a replay of the owner's own history.

The detection sets run each attack alone: on a device of its own, with fresh
rule state and no learning period. Real detection happens inside a
household's traffic, after learning, with first sightings already built.
Here the same kinds of attack are put into the stored history on the owner's
own devices, each starting just after one of that device's lookups once the
learning period is over, and the whole history is replayed through the rules
once. A finding on an attack's own lookups detects it, and the time from its
first lookup to that finding is its time to detect. Findings on the owner's
own lookups are compared with the plain replay, to show what the attacks
changed around them.

Only counts and timings leave this module: no name from the history or the
threat feeds is kept.
"""

import random
import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vedette.eval import datasets
from vedette.eval.detection import Detector, Hit, ReplayResult
from vedette.eval.stats import wilson
from vedette.shared.models import AllowlistEntry, Severity
from vedette.sources.base import DnsEvent
from vedette.storage.models import events
from vedette.storage.store import Store

#: An attack starts only this soon after one of its device's own lookups, so it
#: lands while the device is in use.
IN_USE = timedelta(minutes=15)
#: Attacks on one device are at least this far apart, so none shares another's
#: ten-minute windows or the clock hour its findings are de-duplicated in.
GAP = timedelta(hours=1)
#: Tries at placing one attack before it is left out.
TRIES = 200
#: A device needs this many lookups after the learning period to be attacked.
MIN_LOOKUPS = 100
#: Sessions taken from each synthetic set (one per family for the real families).
PER_KIND = 10
#: Not counted for attacks. In your traffic an attack reuses a known device, so
#: this rule cannot fire; alone each attack has a new device, so it always does.
NOT_COUNTED = frozenset({"new-device"})

type Lookup = tuple[str, str, float]  # fqdn, root, seconds after the attack starts
type _Key = tuple[int, int]  # kind, session


@dataclass(frozen=True, slots=True)
class AttackKind:
    """One kind of attack: its sessions, and the registration ages they need."""

    name: str
    sessions: tuple[tuple[Lookup, ...], ...]
    ages: Mapping[str, int] = field(default_factory=dict)


def _spread(names: Sequence[datasets.Name], minutes: float) -> tuple[Lookup, ...]:
    """Lookups of ``names`` spread evenly over ``minutes``, as the detection sets do."""
    return tuple(
        (name.fqdn, name.root, minutes * 60 * number / max(len(names), 1))
        for number, name in enumerate(names)
    )


def _tunnels(sessions: Sequence[datasets.TunnelSession]) -> tuple[tuple[Lookup, ...], ...]:
    return tuple(
        _spread([datasets.Name(fqdn, session.root) for fqdn in session.fqdns], session.minutes)
        for session in sessions[:PER_KIND]
    )


def _bursts(bursts: Sequence[datasets.BurstSession]) -> tuple[tuple[Lookup, ...], ...]:
    return tuple(_spread(burst.names, burst.minutes) for burst in bursts[:PER_KIND])


def attack_kinds(
    families: Mapping[str, Sequence[datasets.Name]], feeds: Sequence[datasets.Name]
) -> list[AttackKind]:
    """The attacks to blend in, taken from the detection sets.

    Bursts, tunnels and young domains are the synthetic sessions the detection
    table runs alone (the first ten of each); a real family's burst is 30 of
    its names in five minutes, one burst per family; a feed visit is one lookup
    of a domain the stored feeds list. A kind with no sessions is left out.
    """
    random_bursts, word_bursts = datasets.dga_bursts()
    fast, slow = datasets.tunnel_sessions()
    young, _ = datasets.dated_domains()
    young = young[:PER_KIND]
    kinds = [
        AttackKind("Burst of 30 random-character domains in 5 minutes", _bursts(random_bursts)),
        AttackKind("Burst of 30 dictionary-word domains in 5 minutes", _bursts(word_bursts)),
        AttackKind(
            "Burst of 30 domains from a real DGA family in 5 minutes",
            tuple(_spread(names[:30], 5) for names in families.values()),
        ),
        AttackKind("Tunnel, 40 lookups in 5 minutes", _tunnels(fast)),
        AttackKind("Tunnel, 20 lookups in 10 minutes", _tunnels(slow)),
        AttackKind(
            "Tunnel, a lookup a minute for 2 hours",
            _tunnels(datasets.sustained_tunnel_sessions()),
        ),
        AttackKind(
            "Visit to a domain registered under 30 days ago",
            tuple(((name.fqdn, name.root, 0.0),) for name, _ in young),
            ages={name.root: days for name, days in young},
        ),
        AttackKind(
            "Visit to a threat-feed domain",
            tuple(((name.fqdn, name.root, 0.0),) for name in feeds[:PER_KIND]),
        ),
    ]
    return [kind for kind in kinds if kind.sessions]


def _duration(session: Sequence[Lookup]) -> timedelta:
    return timedelta(seconds=max((seconds for _, _, seconds in session), default=0.0))


@dataclass(frozen=True, slots=True)
class _Device:
    """A device, or a profile without devices, that attacks can go to, and when."""

    profile_id: str
    device_id: str | None
    start: datetime  # the end of the learning period
    end: datetime  # the profile's last stored lookup


@dataclass(frozen=True, slots=True)
class Placement:
    """Where one attack went: a real device, just after one of its own lookups."""

    profile_id: str
    device_id: str | None
    device_name: str | None
    client_ip: str | None
    start: datetime


async def _devices(
    engine: AsyncEngine, profile_ids: Sequence[str], learning: timedelta
) -> list[_Device]:
    """Every device with at least :data:`MIN_LOOKUPS` lookups after its profile's learning."""
    found: list[_Device] = []
    async with engine.connect() as connection:
        for profile_id in profile_ids:
            first, last = (
                await connection.execute(
                    select(func.min(events.c.ts), func.max(events.c.ts)).where(
                        events.c.profile_id == profile_id
                    )
                )
            ).one()
            if first is None or last is None:
                continue
            start = first + learning
            rows = await connection.execute(
                select(events.c.device_id, func.count())
                .where(events.c.profile_id == profile_id, events.c.ts >= start)
                .group_by(events.c.device_id)
                .order_by(events.c.device_id)
            )
            found += [
                _Device(profile_id, device_id, start, last)
                for device_id, count in rows
                if count >= MIN_LOOKUPS
            ]
    return found


async def _place(
    connection: AsyncConnection,
    devices: Sequence[_Device],
    duration: timedelta,
    busy: dict[tuple[str, str | None], list[tuple[datetime, datetime]]],
    rng: random.Random,
) -> Placement | None:
    """One attack on a random device, just after its first lookup from a random time."""
    for _ in range(TRIES):
        if not devices:
            return None
        device = rng.choice(devices)
        room = device.end - duration - device.start
        if room <= timedelta(0):
            continue
        when = device.start + room * rng.random()
        row = (
            await connection.execute(
                select(events.c.ts, events.c.device_name, events.c.client_ip)
                .where(
                    events.c.profile_id == device.profile_id,
                    events.c.device_id.is_not_distinct_from(device.device_id),
                    events.c.ts >= when,
                )
                .order_by(events.c.ts)
                .limit(1)
            )
        ).first()
        if row is None or row.ts - when > IN_USE:
            continue  # the device was not in use then
        start = row.ts + timedelta(seconds=1)
        end = start + duration
        taken = busy[(device.profile_id, device.device_id)]
        if end > device.end or any(
            start < other_end + GAP and other_start < end + GAP for other_start, other_end in taken
        ):
            continue
        taken.append((start, end))
        return Placement(device.profile_id, device.device_id, row.device_name, row.client_ip, start)
    return None


async def place(
    engine: AsyncEngine,
    profile_ids: Sequence[str],
    durations: Sequence[timedelta],
    *,
    learning: timedelta,
    rng: random.Random,
) -> list[Placement | None]:
    """A placement for each attack, in order; ``None`` for one that did not fit.

    Each attack goes to a device drawn at random, at a time drawn at random
    after the learning period, moved to just after the device's next lookup;
    a time when the device was not in use, or within :data:`GAP` of another
    attack on it, is drawn again. Place the longest attacks first.
    """
    devices = await _devices(engine, profile_ids, learning)
    busy: dict[tuple[str, str | None], list[tuple[datetime, datetime]]] = defaultdict(list)
    async with engine.connect() as connection:
        return [await _place(connection, devices, duration, busy, rng) for duration in durations]


def _lookups(
    kinds: Sequence[AttackKind], placed: Mapping[_Key, Placement]
) -> tuple[list[DnsEvent], dict[str, _Key]]:
    """Every placed attack's lookups as allowed queries from its device, and whose each is."""
    lookups: list[DnsEvent] = []
    owner: dict[str, _Key] = {}
    for (kind, session), spot in placed.items():
        for number, (fqdn, root, seconds) in enumerate(kinds[kind].sessions[session]):
            event_id = f"attack-{kind}-{session}-{number}"
            owner[event_id] = (kind, session)
            lookups.append(
                DnsEvent(
                    event_id=event_id,
                    profile_id=spot.profile_id,
                    ts=spot.start + timedelta(seconds=seconds),
                    fqdn=fqdn,
                    root=root,
                    status="default",
                    device_id=spot.device_id,
                    device_name=spot.device_name,
                    client_ip=spot.client_ip,
                    source="eval",
                )
            )
    return lookups, owner


@dataclass(slots=True)
class KindResult:
    """How one kind of attack fared in the owner's traffic, and alone."""

    attack: str
    sessions: int
    placed: int = 0
    detected: int = 0
    alerting: int = 0  # detected at high or critical
    alone: int = 0  # the same sessions, each on a device of its own
    by_rule: dict[str, int] = field(default_factory=dict)  # sessions each rule fired on
    minutes: list[float] = field(default_factory=list)  # first lookup to first finding

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready, with the rate, its 95% interval and the time to detect."""
        return {
            "attack": self.attack,
            "sessions": self.sessions,
            "placed": self.placed,
            "detected": self.detected,
            "alerting": self.alerting,
            "alone": self.alone,
            "by_rule": self.by_rule,
            "rate": self.detected / self.placed if self.placed else None,
            "ci": wilson(self.detected, self.placed),
            "p50_minutes": statistics.median(self.minutes) if self.minutes else None,
            "max_minutes": max(self.minutes, default=None),
        }


def _score(
    kind: AttackKind, index: int, placed: Mapping[_Key, Placement], hits: Mapping[_Key, list[Hit]]
) -> KindResult:
    result = KindResult(kind.name, len(kind.sessions))
    rules: Counter[str] = Counter()
    for session in range(len(kind.sessions)):
        spot = placed.get((index, session))
        if spot is None:
            continue
        result.placed += 1
        found = hits.get((index, session))
        if not found:
            continue
        result.detected += 1
        result.alerting += any(hit.severity.rank >= Severity.HIGH.rank for hit in found)
        rules.update({hit.rule for hit in found})
        first = min(hit.ts for hit in found)
        result.minutes.append((first - spot.start).total_seconds() / 60)
    result.by_rule = dict(sorted(rules.items()))
    return result


async def attacks_in_traffic(
    detector: Detector,
    store: Store,
    profile_ids: Sequence[str],
    *,
    allowlist: Sequence[AllowlistEntry],
    learning: timedelta,
    clean: ReplayResult,
    families: Mapping[str, Sequence[datasets.Name]],
    feeds: Sequence[datasets.Name],
    rng: random.Random | None = None,
) -> dict[str, Any]:
    """Blend every attack into the stored history, replay it once and score each kind.

    ``clean`` is the plain replay of the same history, to compare the owner's
    own findings with. Returns JSON-ready counts: per kind of attack, how many
    sessions were placed, detected and detected alone, which rules fired and
    how soon; and per rule, the owner's own findings with and without the
    attacks. With nowhere to put an attack, nothing is replayed again.
    """
    rng = rng or random.Random(datasets.SEED + 5)  # noqa: S311 - a fixed, repeatable draw
    kinds = attack_kinds(families, feeds)
    order = [
        (index, session)
        for index, kind in enumerate(kinds)
        for session in range(len(kind.sessions))
    ]
    rng.shuffle(order)
    order.sort(key=lambda key: _duration(kinds[key[0]].sessions[key[1]]), reverse=True)
    spots = await place(
        store.engine,
        profile_ids,
        [_duration(kinds[index].sessions[session]) for index, session in order],
        learning=learning,
        rng=rng,
    )
    placed = {key: spot for key, spot in zip(order, spots, strict=True) if spot is not None}
    lookups, owner = _lookups(kinds, placed)
    counted = detector.rule_ids - NOT_COUNTED
    replayed = clean
    if lookups:
        replayed = await detector.replay(
            store,
            profile_ids,
            allowlist=allowlist,
            learning=learning,
            blend=lookups,
            ages={root: days for kind in kinds for root, days in kind.ages.items()},
        )
    hits: dict[_Key, list[Hit]] = defaultdict(list)
    for hit in replayed.hits:
        if hit.rule in counted:
            hits[owner[hit.event_id]].append(hit)
    rows = []
    for index, kind in enumerate(kinds):
        row = _score(kind, index, placed, hits)
        alone = await detector.alone(kind.sessions, counted=counted, ages=kind.ages)
        row.alone = sum(1 for found in alone if found)
        rows.append(row.as_dict())
    rules = sorted(set(clean.findings) | set(replayed.findings))
    return {
        "sessions": len(order),
        "placed": len(placed),
        "lookups": len(lookups),
        "devices": len({(spot.profile_id, spot.device_id) for spot in placed.values()}),
        "learning_days": learning.total_seconds() / 86400,
        "kinds": rows,
        "own": [
            {
                "rule": rule,
                "replay": clean.findings.get(rule, 0),
                "blended": replayed.findings.get(rule, 0),
                "replay_alerting": clean.alerting.get(rule, 0),
                "blended_alerting": replayed.alerting.get(rule, 0),
            }
            for rule in rules
        ],
    }
