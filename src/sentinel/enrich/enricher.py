"""Adds local, cached context to DNS events. No LLM is involved."""

from collections.abc import Sequence
from datetime import datetime, timedelta

from sentinel.enrich.first_seen import FirstSeenTracker
from sentinel.enrich.lexical import lexical_features
from sentinel.enrich.model import EnrichedEvent
from sentinel.enrich.popularity import PopularityList
from sentinel.enrich.rdap import DomainAges
from sentinel.enrich.threat_intel import ThreatIntel
from sentinel.sources.base import DnsEvent

_BLOCKED = "blocked"


def _parents(root: str) -> list[str]:
    """Parent domains of a root with at least two labels, nearest first."""
    labels = root.split(".")
    return [".".join(labels[start:]) for start in range(1, len(labels) - 1)]


class Enricher:
    """Turns a batch of events into enriched events."""

    def __init__(
        self,
        *,
        popularity: PopularityList,
        threat_intel: ThreatIntel,
        ages: DomainAges,
        first_seen: FirstSeenTracker,
        rdap_max_event_age: timedelta,
        rdap_max_lookups_per_batch: int,
    ) -> None:
        """Create an enricher.

        Args:
            popularity: Top-sites ranks.
            threat_intel: Threat-feed matcher.
            ages: Domain registration ages.
            first_seen: First-seen tracker.
            rdap_max_event_age: Events older than this never trigger an RDAP
                lookup (cached ages are still used), so reading a week of
                history does not send thousands of domains to registries.
            rdap_max_lookups_per_batch: Upper bound on RDAP lookups per batch.
        """
        self._popularity = popularity
        self._threat_intel = threat_intel
        self._ages = ages
        self._first_seen = first_seen
        self._rdap_max_event_age = rdap_max_event_age
        self._rdap_max_lookups = rdap_max_lookups_per_batch

    async def enrich_batch(self, events: Sequence[DnsEvent], now: datetime) -> list[EnrichedEvent]:
        """Enrich events in order.

        A registration-age lookup is made only for a root that is allowed, not
        on the top-sites list, not a customer name on a popular platform, and
        seen in a recent event; every other root gets its cached age or "unknown".
        """
        roots = {event.root or event.fqdn for event in events}
        parents = {root: _parents(root) for root in roots}
        ranks = await self._popularity.ranks(roots.union(*parents.values()) if parents else roots)
        known = self._popularity.known
        platform = {
            root: min((rank for name in names if (rank := ranks[name]) is not None), default=None)
            for root, names in parents.items()
        }
        threats = await self._threat_intel.match_many((event.fqdn, event.root) for event in events)

        unpopular = [
            root for root in roots if known and ranks[root] is None and platform[root] is None
        ]
        lookup: list[str] = []
        for event in events:
            root = event.root
            if (
                root is not None
                and known
                and ranks[root] is None
                and platform[root] is None
                and event.status != _BLOCKED
                and now - event.ts <= self._rdap_max_event_age
                and root not in lookup
                and len(lookup) < self._rdap_max_lookups
            ):
                lookup.append(root)
        ages = await self._ages.cached(unpopular, now)
        ages.update(await self._ages.resolve(lookup, now))

        enriched: list[EnrichedEvent] = []
        for event in events:
            root = event.root or event.fqdn
            flags = self._first_seen.observe(event)
            feeds, match = threats.get(event.fqdn, ((), None))
            enriched.append(
                EnrichedEvent(
                    event=event,
                    lexical=lexical_features(event.fqdn, event.root),
                    popularity_rank=ranks[root],
                    platform_rank=platform[root],
                    popularity_known=known,
                    domain_age_days=ages.get(root),
                    threat_feeds=feeds,
                    threat_match=match,
                    new_device=flags.new_device,
                    new_client_ip=flags.new_client_ip,
                    new_root_for_profile=flags.new_root_for_profile,
                    new_root_for_device=flags.new_root_for_device,
                    new_categories=flags.new_categories,
                )
            )
        await self._first_seen.flush()
        return enriched
