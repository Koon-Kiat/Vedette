"""Read-only queries behind the dashboard pages.

Nothing here contacts the network: popularity, registration age and threat
feed matches come from the local caches the enricher keeps.
"""

import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vedette.config import ProfileConfig
from vedette.shared.models import Analysis, Severity
from vedette.shared.names import LexicalFeatures, candidates, lexical_features
from vedette.sources.base import DnsEvent
from vedette.storage.analysis import AnalysisStore
from vedette.storage.health import HealthRow, HealthStore
from vedette.storage.models import (
    audit_log,
    domain_age,
    events,
    finding_analysis,
    findings,
    first_seen,
    llm_calls,
    notifications,
    popularity,
    threat_intel,
)
from vedette.storage.models import (
    digests as digest_table,
)
from vedette.storage.store import StoredFinding, finding_from_row, to_event
from vedette.storage.triage import DOMAIN_RULES, AuditEntry, TriageStore

DAY = timedelta(hours=24)
YOUNG_DAYS = 30
TOP = 20


@dataclass(frozen=True, slots=True)
class FindingFilter:
    """Filters for the findings list. ``None`` means "any"."""

    profile_id: str | None = None
    device: str | None = None
    rule_id: str | None = None
    min_severity: Severity | None = None
    status: str | None = "open"
    day: date | None = None


@dataclass(frozen=True, slots=True)
class FindingRow:
    """A finding with its analysis and its latest triage decision, if any."""

    finding: StoredFinding
    analysis: Analysis | None
    decision: AuditEntry | None = None
    revisions: int = 0  # decisions entered on it so far; the latest is lettered by this

    @property
    def priority(self) -> Severity:
        """The analysis's priority, never below the rule's floor."""
        if self.analysis is None or self.analysis.priority.rank < self.finding.severity.rank:
            return self.finding.severity
        return self.analysis.priority


@dataclass(frozen=True, slots=True)
class Shell:
    """What every page's navigation rail shows.

    ``open_by_profile`` maps each profile id to its open findings, for the
    profile switch: a problem on a profile not shown is never invisible.
    """

    open_findings: int
    checks_ok: int
    checks_total: int
    newest_event: datetime | None
    open_by_profile: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Enrichment:
    """What the local caches say about a finding's domain."""

    root: str
    rank: int | None
    platform_rank: int | None
    popularity_known: bool
    age_days: int | None
    age_status: str | None
    threat_feeds: list[str]
    first_seen: datetime | None
    lexical: LexicalFeatures | None


@dataclass(frozen=True, slots=True)
class HourBar:
    """Queries in one hour."""

    start: datetime
    allowed: int
    blocked: int


@dataclass(frozen=True, slots=True)
class DomainRow:
    """A root with how often it was queried and what the caches know about it."""

    root: str
    count: int
    rank: int | None
    age_days: int | None


@dataclass(frozen=True, slots=True)
class DomainsPage:
    """The four domain lists for a period."""

    top_allowed: list[DomainRow]
    top_blocked: list[DomainRow]
    newly_seen: list[DomainRow]
    young: list[DomainRow]


@dataclass(frozen=True, slots=True)
class DeviceRow:
    """One device of a profile."""

    device_id: str
    name: str | None
    first_seen: datetime
    last_seen: datetime
    queries_24h: int
    queries_7d: int
    findings: int


@dataclass(frozen=True, slots=True)
class ProfileDevices:
    """A profile's devices, or why there are none."""

    label: str
    attribution: bool
    devices: list[DeviceRow]
    client_ips: int
    queries_7d: int = 0  # with none, the missing devices say nothing about attribution


@dataclass(frozen=True, slots=True)
class ProfileLag:
    """How recent a profile's newest event is."""

    label: str
    last_event: datetime | None
    lag: timedelta | None


@dataclass(slots=True)
class HealthPage:
    """Everything the health page shows."""

    profiles: list[ProfileLag]
    unprocessed_events: int
    unanalysed_findings: int
    outbox_pending: int
    outbox_failed_7d: int
    checks: list[HealthRow]
    llm_calls_7d: int
    llm_outcomes: dict[str, int]
    p50_ms: float | None
    p95_ms: float | None
    analysis_sources: dict[str, int] = field(default_factory=dict)

    @property
    def cache_hit_rate(self) -> float | None:
        """Share of model explanations served from the cache in the last 7 days."""
        cache = self.analysis_sources.get("cache", 0)
        llm = self.analysis_sources.get("llm", 0)
        return cache / (cache + llm) if cache + llm else None


@dataclass(frozen=True, slots=True)
class DigestRow:
    """An archived digest and what happened to its delivery."""

    id: int
    period_end: datetime
    title: str
    body: str
    delivery: str | None


class DashboardQueries:
    """All reads the dashboard makes."""

    def __init__(self, engine: AsyncEngine, *, profiles: Sequence[ProfileConfig]) -> None:
        """Query the database behind ``engine`` for the given profiles."""
        self._engine = engine
        self._profiles = list(profiles)
        self._ids = [profile.id for profile in profiles]

    # --- findings ---------------------------------------------------------------------

    def _filtered(self, wanted: FindingFilter, tz: ZoneInfo) -> Select[Any]:
        effective = func.coalesce(finding_analysis.c.priority, findings.c.severity)
        statement = (
            select(findings)
            .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
            .where(findings.c.profile_id.in_(self._ids))
        )
        if wanted.profile_id:
            statement = statement.where(findings.c.profile_id == wanted.profile_id)
        if wanted.device:
            statement = statement.where(findings.c.subject == wanted.device)
        if wanted.rule_id:
            statement = statement.where(findings.c.rule_id == wanted.rule_id)
        if wanted.min_severity is not None:
            levels = [level.value for level in Severity if level.rank >= wanted.min_severity.rank]
            statement = statement.where(effective.in_(levels))
        if wanted.status:
            statement = statement.where(findings.c.status == wanted.status)
        if wanted.day is not None:
            start = datetime.combine(wanted.day, time(0), tzinfo=tz).astimezone(UTC)
            end = datetime.combine(wanted.day + timedelta(days=1), time(0), tzinfo=tz).astimezone(
                UTC
            )
            statement = statement.where(findings.c.last_ts >= start, findings.c.last_ts < end)
        return statement

    async def _with_analyses(self, found: list[StoredFinding]) -> list[FindingRow]:
        ids = [item.id for item in found]
        analyses = await AnalysisStore(self._engine).analyses_for(ids)
        entries = await TriageStore(self._engine).audit_for(ids) if ids else []
        latest: dict[int, AuditEntry] = {}
        count: dict[int, int] = {}
        for entry in entries:  # oldest first
            if entry.finding_id is not None:
                latest[entry.finding_id] = entry
                count[entry.finding_id] = count.get(entry.finding_id, 0) + 1
        return [
            FindingRow(item, analyses.get(item.id), latest.get(item.id), count.get(item.id, 0))
            for item in found
        ]

    async def revisions_since(self, moment: datetime) -> int:
        """Decisions entered on findings of these profiles since a moment."""
        statement = (
            select(func.count())
            .select_from(audit_log)
            .join(findings, findings.c.id == audit_log.c.finding_id)
            .where(findings.c.profile_id.in_(self._ids), audit_log.c.at >= moment)
        )
        async with self._engine.connect() as connection:
            return int((await connection.execute(statement)).scalar_one())

    async def findings(
        self, wanted: FindingFilter, *, tz: ZoneInfo, limit: int = 200
    ) -> list[FindingRow]:
        """The ``limit`` most recently seen findings matching the filter, in triage order.

        Highest priority first (the model's raise counts), then most recently seen.
        """
        statement = (
            self._filtered(wanted, tz)
            .order_by(findings.c.last_ts.desc(), findings.c.id.desc())
            .limit(limit)
        )
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        found = await self._with_analyses([finding_from_row(row) for row in rows])
        # Stable: within a priority the query's newest-first order stands.
        return sorted(found, key=lambda row: -row.priority.rank)

    async def finding(self, finding_id: int) -> FindingRow | None:
        """One finding with its analysis."""
        async with self._engine.connect() as connection:
            row = (
                await connection.execute(select(findings).where(findings.c.id == finding_id))
            ).one_or_none()
        if row is None or row.profile_id not in self._ids:
            return None
        (result,) = await self._with_analyses([finding_from_row(row)])
        return result

    async def devices_in_findings(self) -> list[str]:
        """Device ids that appear in findings, for the filter."""
        statement = (
            select(findings.c.subject)
            .where(findings.c.subject.is_not(None), findings.c.profile_id.in_(self._ids))
            .distinct()
            .order_by(findings.c.subject)
        )
        async with self._engine.connect() as connection:
            return [str(value) for value in (await connection.execute(statement)).scalars()]

    async def open_alerts(self, *, limit: int = 10) -> list[FindingRow]:
        """Open high and critical findings: critical first, then newest first."""
        rows = await self.findings(
            FindingFilter(min_severity=Severity.HIGH, status="open"),
            tz=ZoneInfo("UTC"),
            limit=limit,
        )
        return sorted(rows, key=lambda row: -row.priority.rank)

    async def shell(self) -> Shell:
        """Open findings, health check results and the newest event, for the rail."""
        async with self._engine.connect() as connection:
            by_profile = {pid: 0 for pid in self._ids}
            for profile_id, count in (
                await connection.execute(
                    select(findings.c.profile_id, func.count())
                    .where(findings.c.profile_id.in_(self._ids), findings.c.status == "open")
                    .group_by(findings.c.profile_id)
                )
            ).all():
                by_profile[str(profile_id)] = int(count)
            open_count = sum(by_profile.values())
            newest = (
                await connection.execute(
                    select(func.max(events.c.ts)).where(events.c.profile_id.in_(self._ids))
                )
            ).scalar_one_or_none()
        checks = await HealthStore(self._engine).read()
        return Shell(
            open_findings=open_count,
            checks_ok=sum(1 for check in checks if check.ok),
            checks_total=len(checks),
            newest_event=newest.replace(tzinfo=UTC) if newest is not None else None,
            open_by_profile=by_profile,
        )

    async def finding_days(self, *, tz: ZoneInfo, limit: int = 60) -> list[tuple[date, int]]:
        """Local days that have findings, newest first, with how many were last seen then."""
        statement = select(findings.c.last_ts).where(findings.c.profile_id.in_(self._ids))
        async with self._engine.connect() as connection:
            moments = (await connection.execute(statement)).scalars().all()
        days: dict[date, int] = {}
        for moment in moments:
            day = moment.replace(tzinfo=UTC).astimezone(tz).date()
            days[day] = days.get(day, 0) + 1
        return sorted(days.items(), reverse=True)[:limit]

    async def neighbours(self, finding_id: int) -> tuple[int | None, int | None]:
        """The open findings before and after this one, in the order triage takes them.

        That order is the Findings list's: highest priority first, then most
        recently seen. A finding that is not open has no place in it, so its
        neighbours are the first open findings.
        """
        rows = await self.findings(FindingFilter(status="open"), tz=ZoneInfo("UTC"), limit=500)
        ordered = [
            row.finding.id
            for row in sorted(
                rows, key=lambda row: (-row.priority.rank, -row.finding.last_ts.timestamp())
            )
        ]
        if finding_id not in ordered:
            return None, ordered[0] if ordered else None
        at = ordered.index(finding_id)
        return (ordered[at - 1] if at else None), (
            ordered[at + 1] if at + 1 < len(ordered) else None
        )

    async def enrichment(self, finding: StoredFinding, now: datetime) -> Enrichment | None:
        """Local cache facts about a domain finding's root; ``None`` for other findings."""
        if finding.rule_id not in DOMAIN_RULES:
            return None
        root = finding.target
        fqdn = finding.evidence.get("fqdn") or finding.evidence.get("sample_fqdn") or root
        parents = [".".join(root.split(".")[i:]) for i in range(1, root.count("."))]
        names = candidates(str(fqdn), root)
        async with self._engine.connect() as connection:
            ranks = dict(
                (
                    await connection.execute(
                        select(popularity.c.domain, popularity.c.rank).where(
                            popularity.c.domain.in_([root, *parents])
                        )
                    )
                ).all()
            )
            known = (
                await connection.execute(select(func.count()).select_from(popularity))
            ).scalar_one() > 0
            age = (
                await connection.execute(select(domain_age).where(domain_age.c.root == root))
            ).one_or_none()
            feeds = sorted(
                {
                    str(row.feed)
                    for row in await connection.execute(
                        select(threat_intel.c.feed).where(threat_intel.c.domain.in_(names))
                    )
                }
            )
            seen = (
                await connection.execute(
                    select(first_seen.c.first_ts).where(
                        first_seen.c.profile_id == finding.profile_id,
                        first_seen.c.kind == "root",
                        first_seen.c.subject == "",
                        first_seen.c.value == root,
                    )
                )
            ).scalar_one_or_none()
        age_days = None
        if age is not None and age.status == "found" and age.registered_at is not None:
            age_days = max((now - age.registered_at).days, 0)
        platform = [rank for name, rank in ranks.items() if name != root]
        return Enrichment(
            root=root,
            rank=ranks.get(root),
            platform_rank=min(platform) if platform else None,
            popularity_known=bool(known),
            age_days=age_days,
            age_status=None if age is None else str(age.status),
            threat_feeds=feeds,
            first_seen=seen,
            lexical=lexical_features(str(fqdn), root) if isinstance(fqdn, str) else None,
        )

    async def recent_queries(self, finding: StoredFinding, *, limit: int = 20) -> list[DnsEvent]:
        """Stored queries behind a finding: for its domain, or else for its device."""
        statement = select(events).where(events.c.profile_id == finding.profile_id)
        if finding.rule_id in DOMAIN_RULES:
            statement = statement.where(
                or_(events.c.root == finding.target, events.c.fqdn == finding.target)
            )
        elif finding.device_mode and finding.subject is not None:
            statement = statement.where(events.c.device_id == finding.subject)
        else:
            return []
        statement = statement.order_by(events.c.ts.desc()).limit(limit)
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [to_event(row) for row in rows]

    # --- overview ---------------------------------------------------------------------

    async def hourly_queries(self, now: datetime, *, hours: int = 24) -> list[HourBar]:
        """Allowed and blocked queries per hour, oldest hour first, current hour last."""
        current = now.replace(minute=0, second=0, microsecond=0)
        first = current - timedelta(hours=hours - 1)
        hour = func.strftime("%Y-%m-%d %H", events.c.ts).label("hour")
        blocked = func.sum(case((events.c.status == "blocked", 1), else_=0))
        statement = (
            select(hour, func.count(), blocked)
            .where(events.c.profile_id.in_(self._ids), events.c.ts >= first)
            .group_by(hour)
        )
        async with self._engine.connect() as connection:
            counts = {
                str(row[0]): (int(row[1]), int(row[2] or 0))
                for row in (await connection.execute(statement)).all()
            }
        bars = []
        for index in range(hours):
            start = first + timedelta(hours=index)
            total, blocked_count = counts.get(start.strftime("%Y-%m-%d %H"), (0, 0))
            bars.append(HourBar(start=start, allowed=total - blocked_count, blocked=blocked_count))
        return bars

    async def new_devices_per_day(self, now: datetime) -> float | None:
        """Average new-device findings per day over the 7 days before the last 24 hours."""
        start = now - DAY
        statement = (
            select(func.count())
            .select_from(findings)
            .where(
                findings.c.rule_id == "new-device",
                findings.c.profile_id.in_(self._ids),
                findings.c.first_ts >= start - 7 * DAY,
                findings.c.first_ts < start,
            )
        )
        history = (
            select(func.count())
            .select_from(events)
            .where(
                events.c.profile_id.in_(self._ids),
                events.c.ts >= start - 7 * DAY,
                events.c.ts < start,
            )
        )
        async with self._engine.connect() as connection:
            count = int((await connection.execute(statement)).scalar_one())
            has_history = int((await connection.execute(history)).scalar_one()) > 0
        return count / 7 if has_history else None

    # --- domains ----------------------------------------------------------------------

    async def _facts(
        self, connection: AsyncConnection, roots: Sequence[str], now: datetime
    ) -> tuple[dict[str, int], dict[str, int]]:
        ranks = dict(
            (
                await connection.execute(
                    select(popularity.c.domain, popularity.c.rank).where(
                        popularity.c.domain.in_(list(roots))
                    )
                )
            ).all()
        )
        ages: dict[str, int] = {}
        for row in await connection.execute(
            select(domain_age).where(
                domain_age.c.root.in_(list(roots)), domain_age.c.status == "found"
            )
        ):
            if row.registered_at is not None:
                ages[row.root] = max((now - row.registered_at).days, 0)
        return ranks, ages

    async def _root_counts(
        self,
        connection: AsyncConnection,
        start: datetime,
        *,
        blocked: bool | None,
        roots: Sequence[str] | None = None,
        limit: int | None = TOP,
    ) -> list[tuple[str, int]]:
        name = func.coalesce(events.c.root, events.c.fqdn).label("name")
        count = func.count().label("n")
        statement = select(name, count).where(
            events.c.profile_id.in_(self._ids), events.c.ts >= start
        )
        if blocked is True:
            statement = statement.where(events.c.status == "blocked")
        elif blocked is False:
            statement = statement.where(events.c.status != "blocked")
        if roots is not None:
            statement = statement.where(name.in_(list(roots)))
        statement = statement.group_by(name).order_by(count.desc(), name)
        if limit is not None:
            statement = statement.limit(limit)
        return [(str(row.name), int(row.n)) for row in (await connection.execute(statement)).all()]

    async def domains(self, now: datetime, period: timedelta) -> DomainsPage:
        """Top allowed and blocked roots, newly seen roots and young roots in the period."""
        start = now - period
        async with self._engine.connect() as connection:
            allowed = await self._root_counts(connection, start, blocked=False)
            blocked = await self._root_counts(connection, start, blocked=True)
            new_roots = [
                str(value)
                for value in (
                    await connection.execute(
                        select(first_seen.c.value)
                        .where(
                            first_seen.c.profile_id.in_(self._ids),
                            first_seen.c.kind == "root",
                            first_seen.c.subject == "",
                            first_seen.c.first_ts >= start,
                        )
                        .order_by(first_seen.c.first_ts.desc())
                        .limit(TOP)
                    )
                ).scalars()
            ]
            young_roots = [
                str(value)
                for value in (
                    await connection.execute(
                        select(domain_age.c.root).where(
                            domain_age.c.status == "found",
                            domain_age.c.registered_at >= now - timedelta(days=YOUNG_DAYS),
                        )
                    )
                ).scalars()
            ]
            new_counts = dict(
                await self._root_counts(
                    connection, start, blocked=None, roots=new_roots, limit=None
                )
            )
            young_counts = await self._root_counts(
                connection, start, blocked=None, roots=young_roots
            )
            listed = {root for root, _ in [*allowed, *blocked, *young_counts]} | set(new_roots)
            ranks, ages = await self._facts(connection, sorted(listed), now)

        def rows(pairs: Sequence[tuple[str, int]]) -> list[DomainRow]:
            return [
                DomainRow(root, count, ranks.get(root), ages.get(root)) for root, count in pairs
            ]

        return DomainsPage(
            top_allowed=rows(allowed),
            top_blocked=rows(blocked),
            newly_seen=rows([(root, new_counts.get(root, 0)) for root in new_roots]),
            young=rows(young_counts),
        )

    # --- devices ----------------------------------------------------------------------

    async def devices(self, now: datetime) -> list[ProfileDevices]:
        """Each profile's devices over the last 7 days."""
        result: list[ProfileDevices] = []
        recent = case((events.c.ts >= now - DAY, 1), else_=0)
        async with self._engine.connect() as connection:
            for profile in self._profiles:
                rows = (
                    await connection.execute(
                        select(
                            events.c.device_id,
                            func.max(events.c.device_name),
                            func.min(events.c.ts),
                            func.max(events.c.ts),
                            func.sum(recent),
                            func.count(),
                        )
                        .where(
                            events.c.profile_id == profile.id,
                            events.c.ts >= now - 7 * DAY,
                            events.c.device_id.is_not(None),
                        )
                        .group_by(events.c.device_id)
                        .order_by(func.max(events.c.ts).desc())
                    )
                ).all()
                firsts = dict(
                    (
                        await connection.execute(
                            select(first_seen.c.value, first_seen.c.first_ts).where(
                                first_seen.c.profile_id == profile.id,
                                first_seen.c.kind == "device",
                            )
                        )
                    ).all()
                )
                counts: dict[str, int] = dict(
                    (
                        await connection.execute(
                            select(findings.c.subject, func.count())
                            .where(
                                findings.c.profile_id == profile.id,
                                findings.c.subject.is_not(None),
                            )
                            .group_by(findings.c.subject)
                        )
                    ).all()
                )
                ips, queries_7d = (
                    await connection.execute(
                        select(func.count(func.distinct(events.c.client_ip)), func.count()).where(
                            events.c.profile_id == profile.id, events.c.ts >= now - 7 * DAY
                        )
                    )
                ).one()
                devices = [
                    DeviceRow(
                        device_id=str(row[0]),
                        name=row[1],
                        first_seen=firsts.get(row[0]) or row[2],
                        last_seen=row[3],
                        queries_24h=int(row[4] or 0),
                        queries_7d=int(row[5]),
                        findings=int(counts.get(row[0], 0)),
                    )
                    for row in rows
                ]
                result.append(
                    ProfileDevices(
                        label=profile.label,
                        attribution=bool(devices),
                        devices=devices,
                        client_ips=int(ips),
                        queries_7d=int(queries_7d),
                    )
                )
        return result

    # --- digests and health ----------------------------------------------------------------

    async def digests(self, *, limit: int = 60) -> list[DigestRow]:
        """Archived digests, newest first, with their delivery status."""
        return await self._digest_rows(None, limit)

    async def digest(self, digest_id: int) -> DigestRow | None:
        """One archived digest."""
        found = await self._digest_rows(digest_id, 1)
        return found[0] if found else None

    async def _digest_rows(self, digest_id: int | None, limit: int) -> list[DigestRow]:
        statement = (
            select(digest_table, notifications.c.status.label("delivery"))
            .outerjoin(notifications, notifications.c.id == digest_table.c.notification_id)
            .order_by(digest_table.c.period_end.desc())
            .limit(limit)
        )
        if digest_id is not None:
            statement = statement.where(digest_table.c.id == digest_id)
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [
            DigestRow(
                id=row.id,
                period_end=row.period_end,
                title=row.title,
                body=row.body,
                delivery=row.delivery,
            )
            for row in rows
        ]

    async def health(self, now: datetime) -> HealthPage:
        """Everything the health page shows."""
        week = now - 7 * DAY
        async with self._engine.connect() as connection:
            lags: list[ProfileLag] = []
            for profile in self._profiles:
                last = (
                    await connection.execute(
                        select(func.max(events.c.ts)).where(events.c.profile_id == profile.id)
                    )
                ).scalar_one_or_none()
                lags.append(ProfileLag(profile.label, last, now - last if last else None))
            unprocessed = int(
                (
                    await connection.execute(
                        select(func.count())
                        .select_from(events)
                        .where(events.c.profile_id.in_(self._ids), events.c.processed_at.is_(None))
                    )
                ).scalar_one()
            )
            unanalysed = int(
                (
                    await connection.execute(
                        select(func.count())
                        .select_from(findings)
                        .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
                        .where(finding_analysis.c.finding_id.is_(None))
                    )
                ).scalar_one()
            )
            pending = int(
                (
                    await connection.execute(
                        select(func.count())
                        .select_from(notifications)
                        .where(notifications.c.status == "pending")
                    )
                ).scalar_one()
            )
            failed = int(
                (
                    await connection.execute(
                        select(func.count())
                        .select_from(notifications)
                        .where(
                            notifications.c.status == "failed", notifications.c.created_at >= week
                        )
                    )
                ).scalar_one()
            )
            calls = (
                await connection.execute(
                    select(llm_calls.c.outcome, llm_calls.c.duration_ms).where(
                        llm_calls.c.started_at >= week
                    )
                )
            ).all()
            sources: dict[str, int] = dict(
                (
                    await connection.execute(
                        select(finding_analysis.c.source, func.count())
                        .where(finding_analysis.c.created_at >= week)
                        .group_by(finding_analysis.c.source)
                    )
                ).all()
            )
        durations = sorted(float(row.duration_ms) for row in calls if row.outcome == "ok")
        outcomes: dict[str, int] = {}
        for row in calls:
            outcomes[row.outcome] = outcomes.get(row.outcome, 0) + 1
        p50 = p95 = None
        if len(durations) == 1:
            p50 = p95 = durations[0]
        elif durations:
            cuts = statistics.quantiles(durations, n=20, method="inclusive")
            p50, p95 = cuts[9], cuts[18]
        return HealthPage(
            profiles=lags,
            unprocessed_events=unprocessed,
            unanalysed_findings=unanalysed,
            outbox_pending=pending,
            outbox_failed_7d=failed,
            checks=await HealthStore(self._engine).read(),
            llm_calls_7d=len(calls),
            llm_outcomes=outcomes,
            p50_ms=p50,
            p95_ms=p95,
            analysis_sources={str(key): int(value) for key, value in sources.items()},
        )
