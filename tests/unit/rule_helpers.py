"""Builders shared by the rule tests."""

from datetime import UTC, datetime, timedelta
from typing import Any

from vedette.enrich.model import EnrichedEvent
from vedette.rules.allowlist import Allowlist
from vedette.rules.engine import RuleEngine
from vedette.rules.loader import load_rules
from vedette.shared.models import AllowlistEntry, Finding
from vedette.shared.names import lexical_features
from vedette.sources.base import DnsEvent, Reason

T0 = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
PROFILE = "abc123"
HOME_IP = "198.51.100.7"


def event(
    *,
    fqdn: str = "www.example.org",
    root: str | None = "example.org",
    status: str = "default",
    device: str | None = "D1",
    at: timedelta = timedelta(0),
    client_ip: str = HOME_IP,
    reasons: tuple[tuple[str, str], ...] = (),
    n: int = 0,
) -> DnsEvent:
    return DnsEvent(
        event_id=f"{fqdn}|{device}|{at.total_seconds()}|{n}",
        profile_id=PROFILE,
        ts=T0 + at,
        fqdn=fqdn,
        root=root,
        status=status,
        reasons=tuple(Reason(id=rid, name=name) for rid, name in reasons),
        device_id=device,
        device_name=f"Device {device}" if device else None,
        client_ip=client_ip,
        protocol="DNS-over-HTTPS",
        encrypted=True,
        source="nextdns",
    )


def enriched(source: DnsEvent | None = None, **overrides: Any) -> EnrichedEvent:
    """An enriched event that triggers nothing unless ``overrides`` say so."""
    source = source or event()
    values: dict[str, Any] = {
        "event": source,
        "lexical": lexical_features(source.fqdn, source.root),
        "popularity_rank": 100,
        "popularity_known": True,
        "domain_age_days": None,
        "threat_feeds": (),
        "threat_match": None,
        "new_device": False,
        "new_client_ip": False,
        "new_root_for_profile": False,
        "new_root_for_device": False,
        "new_categories": (),
    }
    values.update(overrides)
    return EnrichedEvent(**values)


def engine(
    *,
    learning: timedelta = timedelta(0),
    allow: tuple[AllowlistEntry, ...] = (),
    params: dict[str, dict[str, Any]] | None = None,
    disabled: tuple[str, ...] = (),
) -> RuleEngine:
    specs = []
    for spec in load_rules():
        merged = {**spec.params, **(params or {}).get(spec.id, {})}
        specs.append(spec.model_copy(update={"params": merged, "enabled": spec.id not in disabled}))
    return RuleEngine(
        specs, allowlist=Allowlist(allow, labels={PROFILE: "router"}), learning=learning
    )


def fired(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.rule_id == rule_id]
