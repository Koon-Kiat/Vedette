"""What the owner's own records say around a finding, for the local model.

These are the facts the analyst sends next to a finding's evidence: the
device's history and usual volume, the domain's rank, age, feeds and spread
across devices, what else the device looked up and raised around the same
time, and how the owner handled earlier findings like it. Every query is
bounded by time and row count.
"""

import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vedette.storage.models import (
    domain_age,
    events,
    findings,
    first_seen,
    popularity,
    threat_intel,
)
from vedette.storage.store import StoredFinding
from vedette.storage.triage import DOMAIN_RULES

#: Lookups this close to a finding's first event count as around it.
NEARBY = timedelta(minutes=5)
#: Findings this close to a finding count as beside it.
BESIDE = timedelta(hours=1)
#: How far back a device's usual hourly volume is measured.
BASELINE = timedelta(days=7)
#: How far back the rule's other findings are counted.
RULE_HISTORY = timedelta(days=30)
MAX_NEARBY = 10
MAX_BESIDE = 5


@dataclass(frozen=True, slots=True)
class DeviceFacts:
    """A device's history, or the whole profile's when NextDNS reports no devices.

    Attributes:
        first_seen: When the device was first seen on the profile, if known.
        name: The latest name it reported (self-reported, untrusted).
        usual_per_hour: Median queries in the hours it was active over the
            week before the finding's hour; ``None`` without history.
        that_hour: Queries in the finding's hour.
    """

    first_seen: datetime | None
    name: str | None
    usual_per_hour: float | None
    that_hour: int


@dataclass(frozen=True, slots=True)
class DomainFacts:
    """What the local lists and history hold about a finding's domain.

    Attributes:
        rank: Top-sites rank, ``None`` when unranked.
        registered_at: Registration date from the registry cache, if found.
        feeds: Threat feeds listing the domain itself.
        devices: Devices on the profile that looked it up, up to the finding.
        first_seen: When the profile first looked it up, if recorded.
    """

    rank: int | None
    registered_at: datetime | None
    feeds: tuple[str, ...]
    devices: int
    first_seen: datetime | None


@dataclass(frozen=True, slots=True)
class FindingFacts:
    """The records around one finding.

    Attributes:
        device: The device's (or profile's) history.
        domain: Facts about the domain, for rules about a domain.
        nearby: Other roots the device looked up within five minutes, most
            looked up first.
        beside: Other findings on the same device within an hour, as
            (rule, target, status).
        earlier: Statuses of earlier findings by the same rule on the same target.
        rule_month: Statuses of the rule's other findings on the profile over
            the past 30 days.
    """

    device: DeviceFacts
    domain: DomainFacts | None
    nearby: tuple[str, ...]
    beside: tuple[tuple[str, str, str], ...]
    earlier: dict[str, int] = field(default_factory=dict)
    rule_month: dict[str, int] = field(default_factory=dict)


def _hour(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


class ContextStore:
    """Reads the records around findings."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Read from ``engine``."""
        self._engine = engine

    async def facts(self, found: Sequence[StoredFinding]) -> dict[int, FindingFacts]:
        """The records around each finding, by finding id."""
        result: dict[int, FindingFacts] = {}
        async with self._engine.connect() as connection:
            for finding in found:
                result[finding.id] = await self._facts(connection, finding)
        return result

    async def _facts(self, connection: AsyncConnection, finding: StoredFinding) -> FindingFacts:
        domain = (
            await self._domain(connection, finding) if finding.rule_id in DOMAIN_RULES else None
        )
        return FindingFacts(
            device=await self._device(connection, finding),
            domain=domain,
            nearby=await self._nearby(connection, finding),
            beside=await self._beside(connection, finding),
            earlier=await self._statuses(
                connection,
                finding,
                findings.c.target == finding.target,
                findings.c.first_ts < finding.first_ts,
            ),
            rule_month=await self._statuses(
                connection,
                finding,
                findings.c.target != finding.target,
                findings.c.first_ts.between(finding.first_ts - RULE_HISTORY, finding.first_ts),
            ),
        )

    @staticmethod
    def _same_source(finding: StoredFinding) -> ColumnElement[bool]:
        """Events from the finding's device, or from the whole profile without devices."""
        mine = events.c.profile_id == finding.profile_id
        if finding.device_mode and finding.subject is not None:
            return mine & (events.c.device_id == finding.subject)
        return mine

    async def _device(self, connection: AsyncConnection, finding: StoredFinding) -> DeviceFacts:
        source = self._same_source(finding)
        hour = _hour(finding.first_ts)
        bucket = func.strftime("%Y-%m-%d %H", events.c.ts)
        rows = await connection.execute(
            select(func.count())
            .where(source, events.c.ts >= hour - BASELINE, events.c.ts < hour)
            .group_by(bucket)
        )
        hourly = [int(count) for (count,) in rows]
        that_hour = (
            await connection.execute(
                select(func.count()).where(
                    source, events.c.ts >= hour, events.c.ts < hour + timedelta(hours=1)
                )
            )
        ).scalar_one()
        first = name = None
        if finding.device_mode and finding.subject is not None:
            first = (
                await connection.execute(
                    select(first_seen.c.first_ts).where(
                        first_seen.c.profile_id == finding.profile_id,
                        first_seen.c.kind == "device",
                        first_seen.c.subject == "",
                        first_seen.c.value == finding.subject,
                    )
                )
            ).scalar_one_or_none()
            name = (
                await connection.execute(
                    select(events.c.device_name)
                    .where(
                        source, events.c.device_name.is_not(None), events.c.ts <= finding.last_ts
                    )
                    .order_by(events.c.ts.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
        return DeviceFacts(
            first_seen=first,
            name=name,
            usual_per_hour=statistics.median(hourly) if hourly else None,
            that_hour=int(that_hour),
        )

    async def _domain(self, connection: AsyncConnection, finding: StoredFinding) -> DomainFacts:
        root = finding.target
        rank = (
            await connection.execute(select(popularity.c.rank).where(popularity.c.domain == root))
        ).scalar_one_or_none()
        registered = (
            await connection.execute(
                select(domain_age.c.registered_at).where(
                    domain_age.c.root == root, domain_age.c.status == "found"
                )
            )
        ).scalar_one_or_none()
        feeds = tuple(
            sorted(
                (
                    await connection.execute(
                        select(threat_intel.c.feed).where(threat_intel.c.domain == root)
                    )
                ).scalars()
            )
        )
        devices = (
            await connection.execute(
                select(func.count(func.distinct(events.c.device_id))).where(
                    events.c.profile_id == finding.profile_id,
                    events.c.root == root,
                    events.c.ts <= finding.last_ts,
                )
            )
        ).scalar_one()
        first = (
            await connection.execute(
                select(first_seen.c.first_ts).where(
                    first_seen.c.profile_id == finding.profile_id,
                    first_seen.c.kind == "root",
                    first_seen.c.subject == "",
                    first_seen.c.value == root,
                )
            )
        ).scalar_one_or_none()
        return DomainFacts(
            rank=rank,
            registered_at=registered,
            feeds=feeds,
            devices=int(devices),
            first_seen=first,
        )

    async def _nearby(self, connection: AsyncConnection, finding: StoredFinding) -> tuple[str, ...]:
        count = func.count().label("n")
        rows = await connection.execute(
            select(events.c.root, count)
            .where(
                self._same_source(finding),
                events.c.root.is_not(None),
                events.c.root != finding.target,
                events.c.ts.between(finding.first_ts - NEARBY, finding.first_ts + NEARBY),
            )
            .group_by(events.c.root)
            .order_by(count.desc(), events.c.root)
            .limit(MAX_NEARBY)
        )
        return tuple(str(row.root) for row in rows)

    async def _beside(
        self, connection: AsyncConnection, finding: StoredFinding
    ) -> tuple[tuple[str, str, str], ...]:
        same = (
            findings.c.subject == finding.subject
            if finding.subject is not None
            else findings.c.subject.is_(None)
        )
        rows = await connection.execute(
            select(findings.c.rule_id, findings.c.target, findings.c.status)
            .where(
                findings.c.profile_id == finding.profile_id,
                same,
                findings.c.id != finding.id,
                findings.c.first_ts.between(finding.first_ts - BESIDE, finding.first_ts + BESIDE),
            )
            .order_by(findings.c.first_ts)
            .limit(MAX_BESIDE)
        )
        return tuple((str(row.rule_id), str(row.target), str(row.status)) for row in rows)

    @staticmethod
    async def _statuses(
        connection: AsyncConnection, finding: StoredFinding, *conditions: ColumnElement[bool]
    ) -> dict[str, int]:
        rows = await connection.execute(
            select(findings.c.status, func.count())
            .where(
                findings.c.profile_id == finding.profile_id,
                findings.c.rule_id == finding.rule_id,
                findings.c.id != finding.id,
                *conditions,
            )
            .group_by(findings.c.status)
        )
        return {str(status): int(count) for status, count in rows}
