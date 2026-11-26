"""Adds local, cached context to DNS events. No LLM is involved."""

from collections.abc import Sequence
from datetime import datetime, timedelta

from vedette.enrich.first_seen import FirstSeenTracker
from vedette.enrich.model import EnrichedEvent
from vedette.enrich.popularity import PopularityList
from vedette.enrich.public_suffix import PublicSuffixList
from vedette.enrich.rdap import DomainAges
from vedette.enrich.threat_intel import ThreatIntel
from vedette.shared.names import lexical_features
from vedette.sources.base import DnsEvent

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
        suffixes: PublicSuffixList | None = None,
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
            suffixes: The Public Suffix List, which tells platform customer names
                from registered domains. Without it, or before it is downloaded,
                a root with a ranked parent domain counts as a platform name.
        """
        self._popularity = popularity
        self._threat_intel = threat_intel
        self._ages = ages
        self._first_seen = first_seen
        self._rdap_max_event_age = rdap_max_event_age
        self._rdap_max_lookups = rdap_max_lookups_per_batch
        self._suffixes = suffixes

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
        exact = self._suffixes if self._suffixes is not None and self._suffixes.known else None
        hosted = {
            root: (
                exact.is_platform_name(root) if exact is not None else platform[root] is not None
            )
            for root in roots
        }
        threats = await self._threat_intel.match_many((event.fqdn, event.root) for event in events)

        unpopular = [root for root in roots if known and ranks[root] is None and not hosted[root]]
        lookup: list[str] = []
        for event in events:
            root = event.root
            if (
                root is not None
                and known
                and ranks[root] is None
                and not hosted[root]
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
                    platform=hosted[root] if exact is not None else None,
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
