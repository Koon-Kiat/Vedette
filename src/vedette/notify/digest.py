"""The daily digest: what happened in the last 24 hours, compared with the week before.

:class:`DigestBuilder` gathers the numbers into a :class:`Digest` (kept as JSON
in the archive), and :func:`render_digest` turns it into plain text. Raw names
are kept in the structured data; the text defangs them.
"""

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import AwareDatetime, BaseModel
from sqlalchemy import bindparam, case, func, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vedette.config import ProfileConfig
from vedette.notify.defang import clean_text
from vedette.notify.render import local_time, prose, reason_name, rule_name, safe
from vedette.rules.loader import load_rules
from vedette.rules.model import RuleSpec, Severity
from vedette.storage.health import HealthStore
from vedette.storage.models import UtcDateTime, events, finding_analysis, findings

DAY = timedelta(hours=24)
HISTORY_DAYS = 7
TOP_GROUPS = 10
TOP_COUNTS = 5
_LEVELS = [level.value for level in sorted(Severity, key=lambda s: -s.rank)]


class FindingGroup(BaseModel):
    """Related findings shown as one entry, described by the most serious one."""

    priority: Severity
    rule_id: str
    #: The rule's plain name; empty in digests stored before rules had names.
    rule_name: str = ""
    profile_id: str
    profile: str
    target: str
    device_mode: bool
    subject: str | None
    findings: int
    events: int
    last_ts: AwareDatetime
    summary: str
    action: str | None
    explained_by: str | None
    other_targets: list[str]
    #: NextDNS's name for a category finding's reason, when recorded.
    target_name: str | None = None


class VolumeLine(BaseModel):
    """One profile's queries and blocking in the period and the week before."""

    profile: str
    queries: int
    blocked: int
    avg_queries: float | None
    avg_blocked_pct: float | None
    device_attribution: bool


class CountLine(BaseModel):
    """A name and how often it occurred."""

    name: str
    count: int


class NewDevice(BaseModel):
    """A device (or, without device data, an address) first seen in the period."""

    profile: str
    device: str
    name: str | None
    is_address: bool
    first_seen: AwareDatetime


class HealthLine(BaseModel):
    """One health check as last recorded."""

    label: str
    ok: bool
    detail: str
    since: AwareDatetime


class Digest(BaseModel):
    """Everything the daily digest reports."""

    period_start: AwareDatetime
    period_end: AwareDatetime
    timezone: str
    counts: dict[str, int]
    counts_avg: dict[str, float | None]
    groups: list[FindingGroup]
    groups_total: int
    new_devices: list[NewDevice]
    volumes: list[VolumeLine]
    top_blocked: list[CountLine]
    top_blocklists: list[CountLine]
    health: list[HealthLine] | None


_BLOCKLISTS = text(
    "SELECT json_extract(r.value, '$.name') AS name, count(*) AS n "
    "FROM events JOIN json_each(events.reasons) AS r "
    "WHERE events.status = 'blocked' AND events.ts >= :start AND events.ts < :end "
    "AND events.profile_id IN :profiles AND json_extract(r.value, '$.name') IS NOT NULL "
    "GROUP BY name ORDER BY n DESC, name LIMIT :limit"
).bindparams(
    bindparam("start", type_=UtcDateTime()),
    bindparam("end", type_=UtcDateTime()),
    bindparam("profiles", expanding=True),
)


class DigestBuilder:
    """Collects the digest's numbers from the database."""

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        profiles: Sequence[ProfileConfig],
        tz: ZoneInfo,
        specs: Sequence[RuleSpec] | None = None,
    ) -> None:
        """Create a builder for the given profiles, reporting times in ``tz``."""
        self._engine = engine
        self._profiles = list(profiles)
        self._labels = {profile.id: profile.label for profile in profiles}
        self._tz = tz
        self._specs = {spec.id: spec for spec in (specs if specs is not None else load_rules())}

    async def build(self, period_end: datetime) -> Digest:
        """Build the digest for the 24 hours ending at ``period_end``."""
        start = period_end - DAY
        history = [(start - DAY * k, start - DAY * (k - 1)) for k in range(1, HISTORY_DAYS + 1)]
        async with self._engine.connect() as connection:
            volumes, days_with_data = await self._volumes(connection, start, period_end, history)
            counts, counts_avg = await self._counts(
                connection, start, period_end, history, days_with_data
            )
            groups, total = await self._groups(connection, start, period_end)
            new_devices = await self._new_devices(connection, start, period_end)
            top_blocked = await self._top_blocked(connection, start, period_end)
            top_blocklists = await self._top_blocklists(connection, start, period_end)
        health_rows = await HealthStore(self._engine).read()
        return Digest(
            period_start=start,
            period_end=period_end,
            timezone=self._tz.key,
            counts=counts,
            counts_avg=counts_avg,
            groups=groups,
            groups_total=total,
            new_devices=new_devices,
            volumes=volumes,
            top_blocked=top_blocked,
            top_blocklists=top_blocklists,
            health=[
                HealthLine(label=row.label, ok=row.ok, detail=row.detail, since=row.since)
                for row in health_rows
            ]
            or None,
        )

    async def _volume(
        self, connection: AsyncConnection, profile_id: str, start: datetime, end: datetime
    ) -> tuple[int, int, int]:
        statement = select(
            func.count(),
            func.coalesce(func.sum(case((events.c.status == "blocked", 1), else_=0)), 0),
            func.count(events.c.device_id),
        ).where(events.c.profile_id == profile_id, events.c.ts >= start, events.c.ts < end)
        queries, blocked, with_device = (await connection.execute(statement)).one()
        return int(queries), int(blocked), int(with_device)

    async def _volumes(
        self,
        connection: AsyncConnection,
        start: datetime,
        end: datetime,
        history: list[tuple[datetime, datetime]],
    ) -> tuple[list[VolumeLine], int]:
        lines: list[VolumeLine] = []
        windows_with_data: set[int] = set()
        for profile in self._profiles:
            queries, blocked, with_device = await self._volume(connection, profile.id, start, end)
            past_queries = past_blocked = past_days = 0
            for index, (window_start, window_end) in enumerate(history):
                q, b, _ = await self._volume(connection, profile.id, window_start, window_end)
                if q:
                    windows_with_data.add(index)
                    past_queries, past_blocked, past_days = (
                        past_queries + q,
                        past_blocked + b,
                        past_days + 1,
                    )
            lines.append(
                VolumeLine(
                    profile=profile.label,
                    queries=queries,
                    blocked=blocked,
                    avg_queries=past_queries / past_days if past_days else None,
                    avg_blocked_pct=100.0 * past_blocked / past_queries if past_queries else None,
                    device_attribution=with_device > 0,
                )
            )
        return lines, len(windows_with_data)

    async def _effective_levels(
        self, connection: AsyncConnection, start: datetime, end: datetime
    ) -> list[str]:
        effective = func.coalesce(finding_analysis.c.priority, findings.c.severity)
        statement = (
            select(effective)
            .select_from(findings)
            .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
            .where(
                findings.c.profile_id.in_(list(self._labels)),
                findings.c.last_ts >= start,
                findings.c.last_ts < end,
            )
        )
        return [str(level) for level in (await connection.execute(statement)).scalars()]

    async def _counts(
        self,
        connection: AsyncConnection,
        start: datetime,
        end: datetime,
        history: list[tuple[datetime, datetime]],
        days_with_data: int,
    ) -> tuple[dict[str, int], dict[str, float | None]]:
        levels = await self._effective_levels(connection, start, end)
        counts = {level: levels.count(level) for level in _LEVELS}
        past: dict[str, int] = dict.fromkeys(_LEVELS, 0)
        for window_start, window_end in history:
            for level in await self._effective_levels(connection, window_start, window_end):
                past[level] = past.get(level, 0) + 1
        averages: dict[str, float | None] = {
            level: (past[level] / days_with_data if days_with_data else None) for level in _LEVELS
        }
        return counts, averages

    async def _groups(
        self, connection: AsyncConnection, start: datetime, end: datetime
    ) -> tuple[list[FindingGroup], int]:
        statement = (
            select(
                findings,
                finding_analysis.c.priority.label("a_priority"),
                finding_analysis.c.summary.label("a_summary"),
                finding_analysis.c.recommended_action.label("a_action"),
                finding_analysis.c.group_key.label("a_group"),
                finding_analysis.c.model.label("a_model"),
                finding_analysis.c.source.label("a_source"),
            )
            .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
            .where(
                findings.c.profile_id.in_(list(self._labels)),
                findings.c.last_ts >= start,
                findings.c.last_ts < end,
            )
        )
        rows = (await connection.execute(statement)).all()
        grouped: dict[str, list[Any]] = defaultdict(list)
        for row in rows:
            key = f"g|{row.a_group}" if row.a_group else f"r|{row.rule_id}|{row.target}"
            grouped[key].append(row)

        def rank(row: Any) -> tuple[int, int, datetime]:
            priority = Severity(row.a_priority or row.severity)
            return (priority.rank, row.event_count, row.last_ts)

        result: list[FindingGroup] = []
        for members in grouped.values():
            top = max(members, key=rank)
            spec = self._specs.get(top.rule_id)
            explained = top.a_summary is not None and top.a_source != "template"
            summary = top.a_summary or (spec.description if spec is not None else top.rule_id)
            result.append(
                FindingGroup(
                    priority=Severity(top.a_priority or top.severity),
                    rule_id=top.rule_id,
                    rule_name=rule_name(top.rule_id, spec),
                    target_name=reason_name(top.rule_id, top.evidence or {}),
                    profile_id=top.profile_id,
                    profile=self._labels.get(top.profile_id, top.profile_id),
                    target=top.target,
                    device_mode=top.device_mode,
                    subject=top.subject,
                    findings=len(members),
                    events=sum(member.event_count for member in members),
                    last_ts=max(member.last_ts for member in members),
                    summary=summary,
                    action=top.a_action,
                    explained_by=top.a_model if explained else None,
                    other_targets=sorted({m.target for m in members} - {top.target})[:3],
                )
            )
        result.sort(key=lambda g: (g.priority.rank, g.events, g.last_ts), reverse=True)
        return result[:TOP_GROUPS], len(result)

    async def _new_devices(
        self, connection: AsyncConnection, start: datetime, end: datetime
    ) -> list[NewDevice]:
        statement = (
            select(findings)
            .where(
                findings.c.rule_id == "new-device",
                findings.c.profile_id.in_(list(self._labels)),
                findings.c.first_ts >= start,
                findings.c.first_ts < end,
            )
            .order_by(findings.c.first_ts)
        )
        found: list[NewDevice] = []
        for row in (await connection.execute(statement)).all():
            name = row.evidence.get("device_name")
            found.append(
                NewDevice(
                    profile=self._labels.get(row.profile_id, row.profile_id),
                    device=row.target,
                    name=name if isinstance(name, str) and name else None,
                    is_address=not row.device_mode,
                    first_seen=row.first_ts,
                )
            )
        return found

    async def _top_blocked(
        self, connection: AsyncConnection, start: datetime, end: datetime
    ) -> list[CountLine]:
        name = func.coalesce(events.c.root, events.c.fqdn).label("name")
        count = func.count().label("n")
        statement = (
            select(name, count)
            .where(
                events.c.profile_id.in_(list(self._labels)),
                events.c.status == "blocked",
                events.c.ts >= start,
                events.c.ts < end,
            )
            .group_by(name)
            .order_by(count.desc(), name)
            .limit(TOP_COUNTS)
        )
        return [
            CountLine(name=row.name, count=row.n)
            for row in (await connection.execute(statement)).all()
        ]

    async def _top_blocklists(
        self, connection: AsyncConnection, start: datetime, end: datetime
    ) -> list[CountLine]:
        rows = await connection.execute(
            _BLOCKLISTS,
            {"start": start, "end": end, "profiles": list(self._labels), "limit": TOP_COUNTS},
        )
        return [CountLine(name=str(row.name), count=int(row.n)) for row in rows.all()]


def _number(value: float) -> str:
    """``0`` for 0.0, ``0.1`` for 0.14, ``100`` for 100.0."""
    return f"{value:.1f}".removesuffix(".0")


def _findings_line(digest: Digest) -> list[str]:
    counts = ", ".join(f"{digest.counts[level]} {level}" for level in _LEVELS)
    if all(digest.counts_avg[level] is None for level in _LEVELS):
        return [f"{counts} (no earlier days to compare with)"]
    average = ", ".join(f"{_number(digest.counts_avg[level] or 0.0)} {level}" for level in _LEVELS)
    return [counts, f"7-day average: {average}"]


def _group_lines(index: int, group: FindingGroup, tz: ZoneInfo) -> list[str]:
    target = (
        group.profile
        if group.target == group.profile_id
        else safe(group.target_name or group.target, limit=120)
    )
    where = (
        f"{group.profile}, device {safe(group.subject or '', limit=64)}"
        if group.device_mode
        else f"{group.profile}, device attribution unavailable"
    )
    plural = "" if group.findings == 1 else "s"
    event_plural = "" if group.events == 1 else "s"
    lines = [
        f"{index}. {group.priority.value.upper()} {group.rule_name or group.rule_id}: "
        f"{target} ({where})",
        f"   {group.findings} finding{plural}, {group.events} event{event_plural}, "
        f"last {local_time(group.last_ts, tz)}",
        f"   {prose(group.summary)}",
    ]
    if group.action:
        lines.append(f"   Do: {prose(group.action, limit=300)}")
    if group.other_targets:
        lines.append(f"   Also: {safe(group.other_targets, limit=120)}")
    explained = (
        f"Explained by {clean_text(group.explained_by, limit=64)}."
        if group.explained_by
        else "Not explained by the local model."
    )
    # The id is what `vedette findings --rule` and the dashboard's Rule field show.
    lines.append(f"   {explained} Rule: {group.rule_id}.")
    return lines


def render_digest(digest: Digest) -> tuple[str, str]:
    """Render a digest as a title and a plain-text body."""
    tz = ZoneInfo(digest.timezone)
    end_local = digest.period_end.astimezone(tz)
    critical, high = digest.counts["critical"], digest.counts["high"]
    title = f"Vedette digest {end_local:%Y-%m-%d}: " + (
        f"{critical} critical, {high} high" if critical or high else "no high or critical findings"
    )
    lines = [
        "Vedette daily digest",
        f"Covers {digest.period_start.astimezone(tz):%Y-%m-%d %H:%M} to "
        f"{end_local:%Y-%m-%d %H:%M} ({digest.timezone})",
        "",
        "FINDINGS",
        *_findings_line(digest),
        "",
    ]
    if digest.groups:
        for index, group in enumerate(digest.groups, start=1):
            lines += [*_group_lines(index, group, tz), ""]
        if digest.groups_total > len(digest.groups):
            lines += [f"… and {digest.groups_total - len(digest.groups)} more.", ""]
    else:
        lines += ["No findings in this period.", ""]

    lines.append("NEW DEVICES")
    if digest.new_devices:
        for device in digest.new_devices:
            what = (
                f"new address {safe(device.device, limit=64)}"
                if device.is_address
                else safe(device.device, limit=64)
                + (f" ({safe(device.name, limit=64)})" if device.name else "")
            )
            lines.append(
                f"- {clean_text(device.profile, limit=64)}: {what}, "
                f"first seen {local_time(device.first_seen, tz)}"
            )
    else:
        lines.append("None.")
    lines += ["", "QUERIES AND BLOCKING"]
    for volume in digest.volumes:
        share = 100.0 * volume.blocked / volume.queries if volume.queries else 0.0
        line = (
            f"- {clean_text(volume.profile, limit=64)}: {volume.queries:,} queries, "
            f"{volume.blocked:,} blocked ({share:.1f}%)"
        )
        if volume.avg_queries is not None and volume.avg_blocked_pct is not None:
            line += (
                f"; 7-day average {volume.avg_queries:,.0f} queries, "
                f"{volume.avg_blocked_pct:.1f}% blocked"
            )
        if volume.queries and not volume.device_attribution:
            line += "; device attribution unavailable"
        lines.append(line)
    if digest.top_blocked:
        lines.append(
            "Most blocked: "
            + ", ".join(f"{safe(c.name, limit=120)} ({c.count:,})" for c in digest.top_blocked)
        )
    if digest.top_blocklists:
        lines.append(
            "Top blocklists: "
            + ", ".join(
                f"{clean_text(c.name, limit=80)} ({c.count:,})" for c in digest.top_blocklists
            )
        )
    lines += ["", "HEALTH"]
    if digest.health is None:
        lines.append("No health checks have run yet.")
    else:
        problems = [check for check in digest.health if not check.ok]
        for check in problems:
            lines.append(
                f"- PROBLEM since {check.since.astimezone(tz):%Y-%m-%d %H:%M}: "
                f"{clean_text(check.detail, limit=200)}"
            )
        healthy = len(digest.health) - len(problems)
        lines.append(
            f"All other checks OK ({healthy})." if problems else f"All checks OK ({healthy})."
        )
    lines += ["", "Details: vedette findings"]
    return title, "\n".join(lines)
