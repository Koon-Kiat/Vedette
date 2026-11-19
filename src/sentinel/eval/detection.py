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

from sentinel.enrich.enricher import Enricher
from sentinel.enrich.first_seen import FirstSeenTracker
from sentinel.enrich.model import EnrichedEvent
from sentinel.enrich.popularity import PopularityList
from sentinel.enrich.rdap import DomainAges
from sentinel.enrich.threat_intel import ThreatIntel
from sentinel.eval.datasets import Name, TunnelSession
from sentinel.rules.allowlist import Allowlist
from sentinel.rules.engine import RuleEngine
from sentinel.rules.model import RuleSpec, Severity
from sentinel.sources.base import DnsEvent
from sentinel.storage.reference import ReferenceStore
from sentinel.storage.triage import DOMAIN_RULES

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

    @property
    def rate(self) -> float | None:
        """Flagged items as a share of all items; ``None`` for an empty set."""
        return self.flagged / self.items if self.items else None


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
        self._threats = ThreatIntel(
            self._reference, self._unused_client, feeds=(), refresh_hours=24 * 36500
        )

    async def __aenter__(self) -> Detector:
        """Load the top-sites list state."""
        await self._popularity.load()
        return self

    async def __aexit__(self, *_: object) -> None:
        """Close the unused HTTP client."""
        await self._unused_client.aclose()

    @property
    def popularity_known(self) -> bool:
        """Whether a top-sites list is available locally."""
        return self._popularity.known

    def _enricher(self) -> Enricher:
        return Enricher(
            popularity=self._popularity,
            threat_intel=self._threats,
            ages=DomainAges(self._reference, None),
            first_seen=FirstSeenTracker(self._scratch, {}),
            rdap_max_event_age=timedelta(0),
            rdap_max_lookups_per_batch=0,
        )

    def _engine(self, *, prefilter: bool) -> RuleEngine:
        return RuleEngine(
            self._specs,
            allowlist=Allowlist((), labels={PROFILE: PROFILE}),
            learning=timedelta(0),
            instruction_prefilter=prefilter,
        )

    async def _evaluate(
        self, items: Sequence[Sequence[tuple[str, str, float]]], *, feeds: bool, prefilter: bool
    ) -> list[list[tuple[str, Severity]]]:
        """Findings (rule, severity) of the domain rules, per item.

        Each item is a list of (fqdn, root, seconds after the item's start).
        """
        enricher = self._enricher()
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
                        device_id=DEVICE,
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
                for finding in engine.evaluate(seen):
                    if finding.rule_id in DOMAIN_RULES:
                        results[owner[finding.event_id]].append((finding.rule_id, finding.severity))
        return results

    @staticmethod
    def _summarise(
        dataset: str, kind: str, found: list[list[tuple[str, Severity]]], note: str
    ) -> DetectionResult:
        result = DetectionResult(dataset=dataset, kind=kind, items=len(found), note=note)
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
        note: str = "",
    ) -> DetectionResult:
        """One lookup per name."""
        found = await self._evaluate(
            [[(name.fqdn, name.root, 0.0)] for name in names], feeds=feeds, prefilter=prefilter
        )
        return self._summarise(dataset, kind, found, note)

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
