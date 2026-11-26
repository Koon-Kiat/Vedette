"""Synthetic data for digest tests and for docs/example-digest.txt.

Two profiles over eight days: a router that reports no devices and a laptop
profile that does. Every name is a reserved ``.example`` domain.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from vedette.config import ProfileConfig
from vedette.shared.models import Analysis, Finding, Severity
from vedette.sources.base import DnsEvent
from vedette.sources.nextdns import parse_log_entry
from vedette.storage.analysis import AnalysisStore
from vedette.storage.health import HealthCheck, HealthStore
from vedette.storage.store import Store

TZ = ZoneInfo("Asia/Singapore")
PERIOD_END = datetime(2026, 3, 15, 0, 0, tzinfo=UTC)  # 08:00 in Singapore
PERIOD_START = PERIOD_END - timedelta(hours=24)
PROFILES = [
    ProfileConfig(id="abc123", label="router"),
    ProfileConfig(id="def456", label="pc"),
]
HAGEZI = {"id": "blocklist:hagezi-multi", "name": "HaGeZi Multi"}
WINDOWS = {"id": "native:windows", "name": "Native Tracking (Windows)"}


def _event(
    profile: str,
    at: datetime,
    domain: str,
    *,
    blocked: bool = False,
    reason: dict[str, str] | None = None,
    device: tuple[str, str] | None = None,
) -> DnsEvent:
    entry: dict[str, Any] = {
        "timestamp": at.isoformat(),
        "domain": domain,
        "root": domain.split(".", 1)[1] if domain.count(".") > 1 else domain,
        "status": "blocked" if blocked else "default",
        "protocol": "DNS-over-HTTPS",
        "clientIp": "198.51.100.7",
        "reasons": [reason] if reason else [],
    }
    if device is not None:
        entry["device"] = {"id": device[0], "name": device[1]}
    return parse_log_entry(profile, entry)


def _events() -> list[DnsEvent]:
    items: list[DnsEvent] = []
    for days_back in range(1, 8):
        start = PERIOD_START - timedelta(days=days_back)
        for n in range(100):
            blocked = n < 10
            items.append(
                _event(
                    "abc123",
                    start + timedelta(minutes=n),
                    "x.ads.example" if blocked else f"www.site{n % 5}.example",
                    blocked=blocked,
                    reason=HAGEZI if blocked else None,
                )
            )
        if days_back >= 3:
            for n in range(40):
                blocked = n < 2
                items.append(
                    _event(
                        "def456",
                        start + timedelta(minutes=n, seconds=30),
                        "x.ads.example" if blocked else f"www.work{n % 3}.example",
                        blocked=blocked,
                        reason=HAGEZI if blocked else None,
                        device=("D1", "Laptop"),
                    )
                )
    for n in range(150):
        at = PERIOD_START + timedelta(minutes=n * 9)
        if n < 20:
            items.append(_event("abc123", at, "x.ads.example", blocked=True, reason=HAGEZI))
        elif n < 30:
            items.append(_event("abc123", at, "t.tracker.example", blocked=True, reason=WINDOWS))
        else:
            items.append(_event("abc123", at, f"www.site{n % 5}.example"))
    for n in range(60):
        items.append(
            _event(
                "def456",
                PERIOD_START + timedelta(minutes=n * 20, seconds=15),
                f"www.work{n % 3}.example",
                device=("D1", "Laptop"),
            )
        )
    for n in range(5):
        items.append(
            _event(
                "def456",
                PERIOD_START + timedelta(hours=20, minutes=n),
                "www.recipes.example",
                device=("D2", "Kitchen tablet"),
            )
        )
    return items


def _finding(
    n: int,
    rule: str,
    severity: Severity,
    profile: str,
    target: str,
    at: datetime,
    evidence: dict[str, Any],
    subject: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule,
        severity=severity,
        profile_id=profile,
        subject=subject,
        device_mode=subject is not None,
        target=target,
        ts=at,
        dedupe_key=f"{rule}|{profile}|{target}|{at:%Y-%m-%d}",
        evidence=evidence,
        event_id=f"{n:064d}",
    )


def _findings() -> list[Finding]:
    s = PERIOD_START
    return [
        *(
            _finding(
                n,
                "threat-intel-allowed",
                Severity.CRITICAL,
                "abc123",
                "bad.example",
                s + timedelta(hours=2, minutes=n),
                {"fqdn": "pay.bad.example", "threat_feeds": ["phishing_army"], "status": "default"},
            )
            for n in range(3)
        ),
        _finding(
            10,
            "young-domain",
            Severity.HIGH,
            "def456",
            "fresh-site.example",
            s + timedelta(hours=5),
            {"fqdn": "login.fresh-site.example", "domain_age_days": 5, "status": "default"},
            subject="D1",
        ),
        _finding(
            11,
            "dga-like",
            Severity.MEDIUM,
            "def456",
            "c2-site.example",
            s + timedelta(hours=8),
            {"fqdn": "xkq7vbn2mtrp9zlw.c2-site.example", "entropy": 3.75, "label_length": 16},
            subject="D1",
        ),
        _finding(
            12,
            "volume-spike",
            Severity.LOW,
            "abc123",
            "abc123",
            s + timedelta(hours=10),
            {"queries_this_hour": 4854, "baseline_per_hour": 970.6, "factor": 5.0},
        ),
        _finding(
            13,
            "new-device",
            Severity.MEDIUM,
            "def456",
            "D2",
            s + timedelta(hours=20),
            {"device_id": "D2", "device_name": "Kitchen tablet", "attribution": "device"},
            subject="D2",
        ),
        _finding(
            14,
            "young-domain",
            Severity.HIGH,
            "def456",
            "older.example",
            s - timedelta(days=3),
            {"fqdn": "older.example", "domain_age_days": 9, "status": "default"},
            subject="D1",
        ),
    ]


def _analysis(
    finding_id: int, priority: Severity, summary: str, action: str, group: str
) -> Analysis:
    return Analysis(
        finding_id=finding_id,
        summary=summary,
        likely_cause="See the summary.",
        recommended_action=action,
        priority=priority,
        group_key=group,
        confidence=0.8,
        source="llm",
        model="qwen3:8b",
    )


async def build_fixture(store: Store) -> None:
    """Fill a migrated, empty database with the synthetic data."""
    await store.save_events(_events())
    await store.commit_processed([], _findings())
    by_target = {f.target: f.id for f in await store.list_findings(limit=100)}
    await AnalysisStore(store.engine).save_analyses(
        [
            _analysis(
                by_target["bad.example"],
                Severity.CRITICAL,
                "A device on the router profile reached bad[.]example, "
                "which a phishing feed lists.",
                "Find the device that made the query and scan it for malware.",
                "phishing",
            ),
            _analysis(
                by_target["fresh-site.example"],
                Severity.HIGH,
                "The laptop visited fresh-site[.]example, registered five days ago.",
                "Check whether the laptop's user meant to visit this site.",
                "new-domains",
            ),
            _analysis(
                by_target["abc123"],
                Severity.HIGH,
                "The router made five times its usual number of lookups in one hour.",
                "Check which device was busy at that time.",
                "volume",
            ),
        ],
        now=PERIOD_END,
    )
    await HealthStore(store.engine).save(
        [
            HealthCheck("api:abc123", "NextDNS API (router)", True, "OK"),
            HealthCheck("stale:def456", "Events from pc", False, "No events from pc for 3 h 0 min"),
            HealthCheck("ollama", "Local model", True, "OK"),
        ],
        now=PERIOD_END - timedelta(hours=3),
    )
