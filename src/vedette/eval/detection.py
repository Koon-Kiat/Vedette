"""Runs evaluation names through the real enrichment and rules, offline.

Reference data (top-sites ranks, threat feeds, cached registration dates)
comes from the local database and is only read. Nothing is looked up on the
network: registration dates come from the cache alone, so the young-domain
rule only fires for roots whose age was already known. First sightings go to
a scratch database, so the evaluation leaves the real one untouched.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import httpx
from sqlalchemy.ext.asyncio import AsyncEngine

from vedette.enrich.enricher import Enricher
from vedette.enrich.first_seen import FirstSeenTracker
from vedette.enrich.model import EnrichedEvent
from vedette.enrich.popularity import PopularityList
from vedette.enrich.public_suffix import PublicSuffixList
from vedette.enrich.rdap import DomainAges
from vedette.enrich.threat_intel import ThreatIntel
from vedette.eval.datasets import BurstSession, Name, TunnelSession, root_of
from vedette.rules.allowlist import Allowlist, AllowlistEntry
from vedette.rules.engine import RuleEngine
from vedette.rules.model import RuleSpec, Severity
from vedette.sources.base import DnsEvent
from vedette.storage.reference import DomainAgeRecord, ReferenceStore
from vedette.storage.store import Store
from vedette.storage.triage import DOMAIN_RULES

PROFILE = "eval"
DEVICE = "eval-device"
_BATCH = 500


@dataclass(slots=True)
class DetectionResult:
    """How many items of one dataset the domain rules flagged."""

    dataset: str
    kind: str  # "malicious" or "benign"
    items: int
    flagged: int = 0
    alerting: int = 0  # flagged at high or critical
    by_rule: dict[str, int] = field(default_factory=dict)
    note: str = ""
    #: Why this result could not have come out otherwise, if it could not.
    construction: str = ""
    #: Flagged names with the rules that fired, kept only for public lists.
    examples: list[dict[str, str]] = field(default_factory=list)

    @property
    def rate(self) -> float | None:
        """Flagged items as a share of all items; ``None`` for an empty set."""
        return self.flagged / self.items if self.items else None


@dataclass(slots=True)
class ReplayResult:
    """What the current rules raise when the stored history is run through them again."""

    events: int = 0
    days: float = 0.0
    findings: dict[str, int] = field(default_factory=dict)  # per rule
    alerting: dict[str, int] = field(default_factory=dict)  # per rule, high or critical

    def per_day(self, count: int) -> float | None:
        """A count spread over the days replayed; ``None`` without a day of history."""
        return count / self.days if self.days >= 1 else None


class Detector:
    """Evaluates names and tunnel sessions with fresh rule state for each dataset."""

    def __init__(
        self, reference: AsyncEngine, scratch: AsyncEngine, specs: Sequence[RuleSpec], now: datetime
    ) -> None:
        """Read reference data from ``reference``; write first sightings to ``scratch``."""
        self._reference = ReferenceStore(reference)
        self._scratch = ReferenceStore(scratch)
        self._specs = list(specs)
        self._now = now
        # Never used to download anything: the lists are only read from the database.
        self._unused_client = httpx.AsyncClient()
        self._popularity = PopularityList(
            self._reference, self._unused_client, url="https://unused.invalid/", refresh_days=36500
        )
        self._suffixes = PublicSuffixList(
            self._reference, self._unused_client, url="https://unused.invalid/", refresh_days=36500
        )
        self._threats = ThreatIntel(
            self._reference, self._unused_client, feeds=(), refresh_hours=24 * 36500
        )

    async def __aenter__(self) -> Detector:
        """Load the top-sites list state."""
        await self._popularity.load()
        await self._suffixes.load()
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close the unused HTTP client."""
        await self._unused_client.aclose()

    @property
    def popularity_known(self) -> bool:
        """Whether a top-sites list is available locally."""
        return self._popularity.known

    @property
    def suffixes_known(self) -> bool:
        """Whether a Public Suffix List is available locally."""
        return self._suffixes.known

    def root_of(self, name: str) -> str | None:
        """The registered domain ``name`` belongs to, as NextDNS would report its root.

        From the Public Suffix List when one is stored (``None`` for a name that
        is itself a public suffix), otherwise the last two labels.
        """
        if self._suffixes.known:
            return self._suffixes.registered(name)
        return root_of(name)

    def _enricher(self, ages: ReferenceStore | None = None) -> Enricher:
        return Enricher(
            popularity=self._popularity,
            threat_intel=self._threats,
            ages=DomainAges(ages or self._reference, None),
            first_seen=FirstSeenTracker(self._scratch, {}),
            rdap_max_event_age=timedelta(0),
            rdap_max_lookups_per_batch=0,
            suffixes=self._suffixes,
        )

    def _engine(self, *, prefilter: bool) -> RuleEngine:
        return RuleEngine(
            self._specs,
            allowlist=Allowlist((), labels={PROFILE: PROFILE}),
            learning=timedelta(0),
            instruction_prefilter=prefilter,
        )

    async def _evaluate(
        self,
        items: Sequence[Sequence[tuple[str, str, float]]],
        *,
        feeds: bool,
        prefilter: bool,
        ranks: bool = True,
        counted: frozenset[str] = DOMAIN_RULES,
        ages: ReferenceStore | None = None,
    ) -> list[list[tuple[str, Severity]]]:
        """Findings (rule, severity) of the ``counted`` rules, per item.

        Each item is a list of (fqdn, root, seconds after the item's start), from
        a device of its own, so items never add up to a burst between them.
        With ``ranks`` off, the top-sites rank is removed after enrichment, so
        the rules judge each name as if it were not on the list.
        """
        enricher = self._enricher(ages)
        engine = self._engine(prefilter=prefilter)
        start = self._now - timedelta(hours=6)
        owner: dict[str, int] = {}
        stream: list[DnsEvent] = []
        offset = 0.0
        for index, item in enumerate(items):
            for number, (fqdn, root, seconds) in enumerate(item):
                event_id = f"eval-{index}-{number}"
                owner[event_id] = index
                stream.append(
                    DnsEvent(
                        event_id=event_id,
                        profile_id=PROFILE,
                        ts=start + timedelta(seconds=offset + seconds),
                        fqdn=fqdn,
                        root=root,
                        status="default",
                        device_id=f"{DEVICE}-{index}",
                        source="eval",
                    )
                )
            offset += max((seconds for _, _, seconds in item), default=0.0) + 1.0
        results: list[list[tuple[str, Severity]]] = [[] for _ in items]
        for chunk_start in range(0, len(stream), _BATCH):
            chunk = stream[chunk_start : chunk_start + _BATCH]
            enriched: list[EnrichedEvent] = await enricher.enrich_batch(chunk, self._now)
            for seen in enriched:
                if not feeds:
                    seen = seen.model_copy(update={"threat_feeds": (), "threat_match": None})
                if not ranks:
                    seen = seen.model_copy(update={"popularity_rank": None, "platform_rank": None})
                for finding in engine.evaluate(seen):
                    if finding.rule_id in counted:
                        results[owner[finding.event_id]].append((finding.rule_id, finding.severity))
        return results

    @staticmethod
    def _summarise(
        dataset: str,
        kind: str,
        found: list[list[tuple[str, Severity]]],
        note: str,
        construction: str = "",
    ) -> DetectionResult:
        result = DetectionResult(
            dataset=dataset, kind=kind, items=len(found), note=note, construction=construction
        )
        rules: Counter[str] = Counter()
        for findings in found:
            if not findings:
                continue
            result.flagged += 1
            if max(severity.rank for _, severity in findings) >= Severity.HIGH.rank:
                result.alerting += 1
            rules.update({rule for rule, _ in findings})
        result.by_rule = dict(sorted(rules.items()))
        return result

    async def names(
        self,
        dataset: str,
        kind: str,
        names: Sequence[Name],
        *,
        feeds: bool = True,
        prefilter: bool = True,
        ranks: bool = True,
        note: str = "",
        construction: str = "",
        examples: int = 0,
    ) -> DetectionResult:
        """One lookup per name.

        Args:
            dataset: The set's name in the report.
            kind: ``benign`` or ``malicious``.
            names: The names, one lookup each, each from a device of its own.
            feeds: Match the threat feeds; off shows what the other rules catch.
            prefilter: Apply the instruction-word pre-filter.
            ranks: Use top-sites ranks; off judges every name as if unlisted.
            note: Shown beside the dataset's name.
            construction: Why the result could not have come out otherwise, if so.
            examples: Keep up to this many flagged names, in dataset order. Only
                for public lists: names from the owner's history or the feeds
                are never kept.
        """
        found = await self._evaluate(
            [[(name.fqdn, name.root, 0.0)] for name in names],
            feeds=feeds,
            prefilter=prefilter,
            ranks=ranks,
        )
        result = self._summarise(dataset, kind, found, note, construction)
        for name, findings in zip(names, found, strict=True):
            if len(result.examples) >= examples:
                break
            if findings:
                rules = ", ".join(sorted({rule for rule, _ in findings}))
                result.examples.append({"name": name.fqdn, "rules": rules})
        return result

    async def sessions(
        self, dataset: str, sessions: Sequence[TunnelSession], *, note: str = ""
    ) -> DetectionResult:
        """Each session's lookups spread evenly over its duration."""
        items = [
            [
                (fqdn, session.root, session.minutes * 60 * number / max(len(session.fqdns), 1))
                for number, fqdn in enumerate(session.fqdns)
            ]
            for session in sessions
        ]
        found = await self._evaluate(items, feeds=True, prefilter=True)
        return self._summarise(dataset, "malicious", found, note)

    async def bursts(self, dataset: str, bursts: Sequence[BurstSession]) -> DetectionResult:
        """Each burst's lookups spread evenly over its duration, from one device."""
        items = [
            [
                (name.fqdn, name.root, burst.minutes * 60 * number / max(len(burst.names), 1))
                for number, name in enumerate(burst.names)
            ]
            for burst in bursts
        ]
        found = await self._evaluate(
            items, feeds=True, prefilter=True, counted=DOMAIN_RULES | {"dga-burst"}
        )
        return self._summarise(dataset, "malicious", found, "")

    async def replay(
        self,
        store: Store,
        profile_ids: Sequence[str],
        *,
        allowlist: Sequence[AllowlistEntry],
        learning: timedelta,
    ) -> ReplayResult:
        """Run every stored event through the current rules again, counting what fires.

        Each profile is replayed in order with fresh rule state and fresh first
        sightings, after the same learning period as the running service.
        Names are only counted.
        """
        result = ReplayResult()
        findings: Counter[str] = Counter()
        alerting: Counter[str] = Counter()
        span = timedelta(0)
        for profile_id in profile_ids:
            enricher = self._enricher()
            engine = RuleEngine(
                self._specs,
                allowlist=Allowlist(allowlist, labels={profile_id: profile_id}),
                learning=learning,
            )
            first: datetime | None = None
            last: datetime | None = None
            async for chunk in store.iter_events(profile_id):
                first = first or chunk[0].ts
                last = chunk[-1].ts
                result.events += len(chunk)
                for seen in await enricher.enrich_batch(chunk, self._now):
                    for finding in engine.evaluate(seen):
                        findings[finding.rule_id] += 1
                        if finding.severity.rank >= Severity.HIGH.rank:
                            alerting[finding.rule_id] += 1
            if first is not None and last is not None:
                span = max(span, last - first)
        result.days = span.total_seconds() / 86400
        result.findings = dict(sorted(findings.items()))
        result.alerting = dict(sorted(alerting.items()))
        return result

    async def dated(
        self, dataset: str, kind: str, names: Sequence[tuple[Name, int]], *, note: str = ""
    ) -> DetectionResult:
        """One lookup per name, with each root's registration age given in days.

        The ages go into the scratch database's cache, so the young-domain rule
        is judged on dates it would have learned from the registry.
        """
        await self._scratch.save_domain_ages(
            [
                DomainAgeRecord(
                    root=name.root,
                    status="found",
                    registered_at=self._now - timedelta(days=age),
                    fetched_at=self._now,
                )
                for name, age in names
            ]
        )
        found = await self._evaluate(
            [[(name.fqdn, name.root, 0.0)] for name, _ in names],
            feeds=True,
            prefilter=True,
            ages=self._scratch,
        )
        return self._summarise(dataset, kind, found, note)
