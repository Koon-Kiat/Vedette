"""Deterministic rule engine: turns enriched events into findings.

The engine alone decides whether a finding exists and what its severity floor
is; no later stage may lower or suppress it.

Some rules need recent history (sliding windows, hourly baselines). That state
lives in memory and is rebuilt after a restart by feeding stored events through
:meth:`RuleEngine.observe`, which updates state without producing findings.

Device attribution: when an event carries no device id (typical for a router
profile), per-device rules key on the profile instead and the finding says so
(``subject`` is ``None`` and ``device_mode`` is ``False``).
"""

from collections import Counter, defaultdict, deque
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from sentinel.enrich.lexical import lexical_features
from sentinel.enrich.model import EnrichedEvent
from sentinel.rules import prefilter
from sentinel.rules.allowlist import Allowlist
from sentinel.rules.model import Finding, RuleSpec, bucket
from sentinel.sources.base import DnsEvent

_BLOCKED = "blocked"
_PRUNE_EVERY = 20_000

type _Subject = tuple[str, str | None]


class RuleEngine:
    """Evaluates every enabled rule against each enriched event."""

    def __init__(
        self,
        specs: Sequence[RuleSpec],
        *,
        allowlist: Allowlist,
        learning: timedelta,
        instruction_prefilter: bool = True,
    ) -> None:
        """Create an engine.

        Args:
            specs: Rule definitions; disabled ones are ignored.
            allowlist: Roots the domain rules must not flag.
            learning: Time after a profile's first event during which rules that
                compare against history (new device, new category) stay quiet.
            instruction_prefilter: Raise findings about domain names that contain
                instruction-like words (see :mod:`sentinel.rules.prefilter`).
                Only the evaluation suite turns this off, to measure its effect.
        """
        self._specs = {spec.id: spec for spec in specs if spec.enabled}
        self._allowlist = allowlist
        self._learning = learning
        self._prefilter = instruction_prefilter
        self._profile_start: dict[str, datetime] = {}
        self._hourly: dict[_Subject, Counter[datetime]] = defaultdict(Counter)
        self._baseline_cache: dict[tuple[_Subject, datetime], float | None] = {}
        self._blocked: dict[_Subject, deque[datetime]] = defaultdict(deque)
        self._tunnel: dict[tuple[_Subject, str], deque[tuple[datetime, str]]] = defaultdict(deque)
        self._tunnel_names: dict[tuple[_Subject, str], Counter[str]] = defaultdict(Counter)
        self._emitted: dict[str, datetime] = {}
        self._observed = 0

    # --- state ----------------------------------------------------------------

    def set_profile_start(self, profile_id: str, first_event: datetime) -> None:
        """Tell the engine when a profile's history begins (start of learning)."""
        self._profile_start[profile_id] = first_event

    def observe(self, event: DnsEvent) -> None:
        """Update windows and baselines from an event without producing findings."""
        self.observe_fields(
            event.profile_id, event.device_id, event.ts, event.fqdn, event.root, event.status
        )

    def observe_fields(
        self,
        profile_id: str,
        device_id: str | None,
        ts: datetime,
        fqdn: str,
        root: str | None,
        status: str,
    ) -> None:
        """Same as :meth:`observe`, from bare fields (used to warm up from storage)."""
        subject: _Subject = (profile_id, device_id)
        self._profile_start.setdefault(profile_id, ts)
        self._hourly[subject][_hour(ts)] += 1

        burst = self._specs.get("blocked-burst")
        if burst is not None and status == _BLOCKED:
            window = self._blocked[subject]
            window.append(ts)
            cutoff = ts - timedelta(minutes=burst.params["window_minutes"])
            while window and window[0] < cutoff:
                window.popleft()

        tunnel = self._specs.get("tunnel-like")
        if tunnel is not None and root:
            features = lexical_features(fqdn, root)
            if features.subdomain_length >= tunnel.params["min_subdomain_length"]:
                key = (subject, root)
                self._tunnel[key].append((ts, fqdn))
                self._tunnel_names[key][fqdn] += 1
                self._trim_tunnel(key, ts - timedelta(minutes=tunnel.params["window_minutes"]))

        self._observed += 1
        if self._observed % _PRUNE_EVERY == 0:
            self._prune(ts)

    def _trim_tunnel(self, key: tuple[_Subject, str], cutoff: datetime) -> None:
        window = self._tunnel[key]
        names = self._tunnel_names[key]
        while window and window[0][0] < cutoff:
            _, name = window.popleft()
            names[name] -= 1
            if names[name] <= 0:
                del names[name]

    def _prune(self, now: datetime) -> None:
        """Drop state too old to matter, so memory stays bounded."""
        horizon = now - timedelta(hours=1)
        for key in [
            k for k, window in self._tunnel.items() if not window or window[-1][0] < horizon
        ]:
            del self._tunnel[key]
            self._tunnel_names.pop(key, None)
        for subject in [
            s for s, window in self._blocked.items() if not window or window[-1] < horizon
        ]:
            del self._blocked[subject]
        spike = self._specs.get("volume-spike")
        keep_hours = spike.params["baseline_hours"] + 2 if spike is not None else 2
        oldest = _hour(now) - timedelta(hours=keep_hours)
        for counts in self._hourly.values():
            for hour in [h for h in counts if h < oldest]:
                del counts[hour]
        self._baseline_cache = {
            key: value for key, value in self._baseline_cache.items() if key[1] >= _hour(now)
        }
        day_ago = now - timedelta(days=2)
        self._emitted = {key: ts for key, ts in self._emitted.items() if ts >= day_ago}

    def _learning_now(self, profile_id: str, ts: datetime) -> bool:
        start = self._profile_start.get(profile_id, ts)
        return ts < start + self._learning

    # --- evaluation -------------------------------------------------------------

    def evaluate(self, item: EnrichedEvent) -> list[Finding]:
        """Record the event and return the findings it triggers."""
        self.observe(item.event)
        findings: list[Finding] = []
        for check in (
            self._new_device,
            self._young_domain,
            self._threat_intel,
            self._dga_like,
            self._tunnel_like,
            self._volume_spike,
            self._blocked_burst,
            self._new_category,
        ):
            findings.extend(check(item))
        if self._prefilter:
            return [prefilter.apply(finding) for finding in findings]
        return findings

    def _finding(
        self, spec: RuleSpec, item: EnrichedEvent, target: str, evidence: dict[str, Any]
    ) -> Finding:
        event = item.event
        key = "|".join(
            [
                spec.id,
                event.profile_id,
                event.device_id or "-",
                target,
                bucket(spec.dedupe, event.ts),
            ]
        )
        return Finding(
            rule_id=spec.id,
            severity=spec.severity,
            profile_id=event.profile_id,
            subject=event.device_id,
            device_mode=event.device_id is not None,
            target=target,
            ts=event.ts,
            dedupe_key=key,
            evidence={name: value for name, value in evidence.items() if name in spec.evidence},
            event_id=event.event_id,
        )

    def _once(self, finding: Finding) -> list[Finding]:
        """Emit a windowed finding only the first time its bucket fills."""
        if finding.dedupe_key in self._emitted:
            return []
        self._emitted[finding.dedupe_key] = finding.ts
        return [finding]

    def _allowed(self, item: EnrichedEvent) -> bool:
        event = item.event
        return self._allowlist.allows(event.profile_id, event.device_id, event.fqdn, event.root)

    def _new_device(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("new-device")
        event = item.event
        if spec is None or self._learning_now(event.profile_id, event.ts):
            return []
        if event.device_id is not None:
            if not item.new_device:
                return []
            target, attribution = event.device_id, "device"
        else:
            if not item.new_client_ip or event.client_ip is None:
                return []
            target, attribution = event.client_ip, "unavailable"
        evidence = {
            "device_id": event.device_id,
            "device_name": event.device_name,
            "client_ip": event.client_ip,
            "attribution": attribution,
        }
        return [self._finding(spec, item, target, evidence)]

    def _young_domain(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("young-domain")
        event = item.event
        if (
            spec is None
            or event.status == _BLOCKED
            or item.domain_age_days is None
            or item.domain_age_days >= spec.params["max_age_days"]
            or not item.popularity_known
            or item.popularity_rank is not None
            or item.platform_rank is not None
            or self._allowed(item)
        ):
            return []
        evidence = {
            "fqdn": event.fqdn,
            "root": event.root,
            "status": event.status,
            "domain_age_days": item.domain_age_days,
            "popularity_rank": item.popularity_rank,
        }
        return [self._finding(spec, item, event.root or event.fqdn, evidence)]

    def _threat_intel(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("threat-intel-allowed")
        event = item.event
        if spec is None or event.status == _BLOCKED or not item.threat_feeds:
            return []
        rank = item.popularity_rank
        if rank is not None and rank <= spec.params["trusted_rank"]:
            return []
        if self._allowed(item):
            return []
        evidence = {
            "fqdn": event.fqdn,
            "root": event.root,
            "status": event.status,
            "threat_feeds": list(item.threat_feeds),
            "threat_match": item.threat_match,
            "popularity_rank": rank,
        }
        return [self._finding(spec, item, event.root or event.fqdn, evidence)]

    def _dga_like(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("dga-like")
        event = item.event
        lexical = item.lexical
        if (
            spec is None
            or event.status == _BLOCKED
            or lexical.label_length < spec.params["min_label_length"]
            or lexical.entropy < spec.params["min_entropy"]
            or not item.popularity_known
            or item.popularity_rank is not None
            or item.platform_rank is not None
            or self._allowed(item)
        ):
            return []
        evidence = {
            "fqdn": event.fqdn,
            "root": event.root,
            "status": event.status,
            "label": lexical.label,
            "label_length": lexical.label_length,
            "entropy": round(lexical.entropy, 3),
            "digit_ratio": round(lexical.digit_ratio, 3),
        }
        return [self._finding(spec, item, event.root or event.fqdn, evidence)]

    def _tunnel_like(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("tunnel-like")
        event = item.event
        if spec is None or not event.root:
            return []
        key = ((event.profile_id, event.device_id), event.root)
        unique = len(self._tunnel_names.get(key, ()))
        if unique <= spec.params["min_unique_subdomains"]:
            return []
        ignore_below = spec.params.get("ignore_rank_below")
        ranks = [r for r in (item.popularity_rank, item.platform_rank) if r is not None]
        rank = min(ranks, default=None)
        if ignore_below is not None and rank is not None and rank <= ignore_below:
            return []
        if self._allowed(item):
            return []
        evidence = {
            "root": event.root,
            "unique_subdomains": unique,
            "window_minutes": spec.params["window_minutes"],
            "sample_fqdn": event.fqdn,
        }
        return self._once(self._finding(spec, item, event.root, evidence))

    def _baseline(self, spec: RuleSpec, subject: _Subject, hour: datetime) -> float | None:
        cached = self._baseline_cache.get((subject, hour), ...)
        if cached is not ...:
            return cached
        counts = self._hourly[subject]
        start = hour - timedelta(hours=spec.params["baseline_hours"])
        past = [count for when, count in counts.items() if start <= when < hour and count > 0]
        value = sum(past) / len(past) if len(past) >= spec.params["min_baseline_hours"] else None
        self._baseline_cache[(subject, hour)] = value
        return value

    def _volume_spike(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("volume-spike")
        event = item.event
        if spec is None or self._learning_now(event.profile_id, event.ts):
            return []
        subject: _Subject = (event.profile_id, event.device_id)
        hour = _hour(event.ts)
        count = self._hourly[subject][hour]
        if count < spec.params["min_queries"]:
            return []
        baseline = self._baseline(spec, subject, hour)
        if baseline is None or count < spec.params["factor"] * baseline:
            return []
        evidence = {
            "queries_this_hour": count,
            "baseline_per_hour": round(baseline, 1),
            "factor": spec.params["factor"],
        }
        target = event.device_id or event.profile_id
        return self._once(self._finding(spec, item, target, evidence))

    def _blocked_burst(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("blocked-burst")
        event = item.event
        if spec is None or event.status != _BLOCKED:
            return []
        subject: _Subject = (event.profile_id, event.device_id)
        count = len(self._blocked.get(subject, ()))
        threshold = spec.params[
            "min_blocked" if event.device_id is not None else "min_blocked_profile_mode"
        ]
        if count < threshold:
            return []
        evidence = {
            "blocked_in_window": count,
            "window_minutes": spec.params["window_minutes"],
            "sample_fqdn": event.fqdn,
        }
        target = event.device_id or event.profile_id
        return self._once(self._finding(spec, item, target, evidence))

    def _new_category(self, item: EnrichedEvent) -> list[Finding]:
        spec = self._specs.get("new-destination-category")
        event = item.event
        if (
            spec is None
            or not item.new_categories
            or self._learning_now(event.profile_id, event.ts)
        ):
            return []
        names = {reason.id: reason.name for reason in event.reasons}
        return [
            self._finding(
                spec,
                item,
                category,
                {"category": category, "category_name": names.get(category), "fqdn": event.fqdn},
            )
            for category in item.new_categories
        ]


def _hour(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)
