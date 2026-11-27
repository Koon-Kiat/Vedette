"""Measures how good the analyst's explanations are, on a gold set of findings.

Each gold item is a synthetic finding with the records around it (the device's
other lookups, its other findings, earlier triage) and what a good explanation
says: the right cause, an actionable step, and claims it must not make. The
records are seeded into a scratch database, so the analyst reads them exactly
as it reads the owner's.

Answers are scored with word patterns, like the injection test, and every
invented fact is listed with the sentence it came from so it can be checked by
eye. An answer invents a fact when it names a domain the model was not given,
names an owner, a malware family or a reputation service that is not in the
data, or states a registration date when none was given.
"""

import hashlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from importlib import resources
from itertools import batched
from statistics import mean
from typing import Any

import yaml
from sqlalchemy.ext.asyncio import AsyncEngine

from vedette.eval.injection import BATCH, RecordingClient, settle
from vedette.llm.analyst import Analyst
from vedette.llm.context import ContextPacker
from vedette.llm.fallback import template_analysis
from vedette.rules.model import RuleSpec
from vedette.shared.models import Analysis, Severity
from vedette.shared.names import lexical_features
from vedette.storage.analysis import AnalysisStore
from vedette.storage.context import ContextStore
from vedette.storage.models import (
    domain_age,
    events,
    findings,
    first_seen,
    popularity,
    threat_intel,
)
from vedette.storage.store import StoredFinding, finding_from_row

GOLD_FILE = "analyst_gold.yaml"
KINDS = ("benign", "suspicious", "uncertain")
#: How long before ``now`` each gold finding happened.
_AGO = timedelta(days=3)
_BACKGROUND = "background.invalid"
_NAME = re.compile(r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])")
_OWNER = re.compile(
    r"\b(?:owned|operated|run|registered|maintained|controlled|hosted|used|belongs?) "
    r"(?:by|to) ((?:[A-Z][\w&-]*)(?: [A-Z][\w&-]*)?)"
)
#: Words that start a phrase after "owned by" without naming anyone.
_NOT_OWNERS = frozenset(
    (
        "The", "A", "An", "Your", "This", "That", "Its", "Their", "Someone", "Attackers",
        "Malware", "Cybercriminals", "Criminals", "Scammers", "Hackers", "Another", "Many",
        "Some", "Users",
    )
)  # fmt: skip
_FAMILIES = re.compile(
    r"\b(Emotet|TrickBot|Qakbot|QakBot|Qbot|Mirai|Cobalt Strike|Conficker|Necurs|ZeuS|Zeus|"
    r"Dridex|IcedID|Ryuk|LockBit|Gafgyt|Mozi|Glupteba|Ursnif|Gozi|Lazarus|Agent ?Tesla|"
    r"RedLine|Raccoon|Vidar|SmokeLoader|Pushdo|Tinba|Banjori|Simda|Ramnit|Locky|"
    r"CryptoLocker|WannaCry|XMRig)\b"
)
_SOURCES = re.compile(
    r"\b(?:listed|flagged|reported|known|marked|rated|classified|blacklisted|blocklisted)"
    r"(?: as [\w-]+)? (?:on|by|in|to|at) (VirusTotal|URLhaus|AbuseIPDB|PhishTank|"
    r"(?:Google )?Safe Browsing|Talos|Spamhaus|AlienVault|ThreatFox|OpenPhish)\b"
    r"|\baccording to (VirusTotal|URLhaus|AbuseIPDB|PhishTank|(?:Google )?Safe Browsing|"
    r"Talos|Spamhaus|AlienVault|ThreatFox|OpenPhish|WHOIS)\b",
    re.IGNORECASE,
)
_AGE = re.compile(
    r"\b(?:registered|created) (?:in|on|since|back in) (?:\d{4}|[A-Z][a-z]+ \d{4})"
    r"|\b\d+ years? old\b",
    re.IGNORECASE,
)
_KNOWN_AGE = re.compile(r'"(?:domain_)?age_days": \d')
#: A target that is an identifier (a device id, an address, "blocklist:oisd"),
#: not a plain word such as the category "gambling" an answer should name.
_IDENTIFIER = re.compile(r"[^A-Za-z ]")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


# --- the gold set -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Expect:
    """What a good explanation of one gold finding says, and must not say."""

    cause: tuple[str, ...]
    action: tuple[str, ...]
    forbidden: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GoldItem:
    """One synthetic finding, the records around it, and what a good answer says."""

    id: str
    rule: str
    kind: str
    scenario: str
    target: str
    evidence: dict[str, Any]
    expect: Expect
    device: dict[str, Any] | None = None
    nearby: tuple[str, ...] = ()
    domain: dict[str, Any] | None = None
    earlier: dict[str, int] = field(default_factory=dict)
    history: dict[str, int] = field(default_factory=dict)
    others: tuple[tuple[str, str], ...] = ()
    events: int = 1
    at_hour: int = 14

    @property
    def profile(self) -> str:
        """Each item lives in a profile of its own, so worlds never mix."""
        return f"gold-{self.id}"


def _patterns(ident: str, values: Iterable[str]) -> tuple[str, ...]:
    found = tuple(str(value) for value in values)
    for pattern in found:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"{ident}: bad pattern {pattern!r} ({exc})") from None
    return found


def _item(entry: dict[str, Any], specs: Mapping[str, RuleSpec]) -> GoldItem:
    """One validated gold item; raises ``ValueError`` naming the item on any problem."""
    ident = str(entry.get("id", "?"))
    try:
        rule = str(entry["rule"])
        expect = entry["expect"]
        item = GoldItem(
            id=ident,
            rule=rule,
            kind=str(entry["kind"]),
            scenario=str(entry["scenario"]),
            target=str(entry["target"]),
            evidence=dict(entry["evidence"]),
            expect=Expect(
                cause=_patterns(ident, expect["cause"]),
                action=_patterns(ident, expect["action"]),
                forbidden=_patterns(ident, expect.get("forbidden") or ()),
            ),
            device=entry.get("device"),
            nearby=tuple(entry.get("nearby") or ()),
            domain=entry.get("domain"),
            earlier=dict(entry.get("earlier") or {}),
            history=dict(entry.get("history") or {}),
            others=tuple((str(rule), str(target)) for rule, target in entry.get("others") or ()),
            events=int(entry.get("events", 1)),
            at_hour=int(entry.get("at_hour", 14)),
        )
    except (KeyError, TypeError) as exc:
        raise ValueError(f"{ident}: missing or malformed {exc}") from None
    if item.rule not in specs:
        raise ValueError(f"{ident}: unknown rule {item.rule}")
    if item.kind not in KINDS:
        raise ValueError(f"{ident}: kind must be one of {', '.join(KINDS)}")
    if not item.expect.cause or not item.expect.action:
        raise ValueError(f"{ident}: give at least one cause and one action pattern")
    if item.rule == "dga-like":
        item = _with_lexical(item)
    unknown = set(item.evidence) - set(specs[item.rule].evidence)
    if unknown:
        raise ValueError(f"{ident}: evidence the rule does not record: {sorted(unknown)}")
    return item


def _with_lexical(item: GoldItem) -> GoldItem:
    """Fill in the lexical evidence dga-like records, from the name itself."""
    features = lexical_features(item.evidence["fqdn"], item.evidence.get("root"))
    evidence = {
        **item.evidence,
        "label": features.label,
        "label_length": features.label_length,
        "randomness": round(features.randomness, 1),
        "digit_ratio": round(features.digit_ratio, 3),
    }
    return GoldItem(**{**_fields(item), "evidence": evidence})


def _fields(item: GoldItem) -> dict[str, Any]:
    return {name: getattr(item, name) for name in GoldItem.__slots__}


def load_gold(specs: Sequence[RuleSpec], text: str | None = None) -> list[GoldItem]:
    """The gold set, in file order. ``text`` replaces the packaged file, for tests."""
    if text is None:
        text = resources.files("vedette.eval").joinpath("data", GOLD_FILE).read_text("utf-8")
    by_id = {spec.id: spec for spec in specs}
    items = [_item(entry, by_id) for entry in yaml.safe_load(text)["names"]]
    seen: set[str] = set()
    for item in items:
        if item.id in seen:
            raise ValueError(f"{item.id}: listed twice")
        seen.add(item.id)
    return items


# --- seeding the records around each finding ------------------------------------------------


def _root(name: str) -> str:
    """A registered domain for a seeded name: the last two labels, or three under co.uk."""
    labels = name.split(".")
    keep = 3 if len(labels) > 2 and labels[-2] in {"co", "com", "org", "net", "ac"} else 2
    return ".".join(labels[-keep:])


def _when(item: GoldItem, now: datetime) -> datetime:
    day = now - _AGO
    return day.replace(hour=item.at_hour, minute=20, second=0, microsecond=0)


def _event(item: GoldItem, number: int, ts: datetime, fqdn: str, **extra: Any) -> dict[str, Any]:
    device = item.device or {}
    row: dict[str, Any] = {
        "event_id": f"{item.profile}-{number}",
        "profile_id": item.profile,
        "ts": ts,
        "fqdn": fqdn,
        "root": _root(fqdn),
        "status": "default",
        "reasons": [],
        "device_id": device.get("id"),
        "device_name": device.get("name"),
        "client_ip": None,
        "protocol": None,
        "encrypted": None,
        "tracker": None,
        "source": "eval",
        "ingested_at": ts,
        "processed_at": ts,
    }
    row.update(extra)
    return row


def _trigger(item: GoldItem) -> str:
    """The looked-up name behind a finding, from its evidence."""
    for key in ("fqdn", "sample_fqdn"):
        value = item.evidence.get(key)
        if isinstance(value, str):
            return value
    return item.nearby[0] if item.nearby else _BACKGROUND


def _world_events(item: GoldItem, t0: datetime) -> list[dict[str, Any]]:
    rows = [_event(item, 0, t0, _trigger(item))]
    for index, name in enumerate(item.nearby):
        offset = timedelta(seconds=20 * (index + 1) * (1 if index % 2 == 0 else -1))
        rows.append(_event(item, len(rows), t0 + offset, name))
    device = item.device or {}
    per_hour = int(device.get("per_hour", 0))
    for hour in range(1, 25):
        start = t0 - timedelta(hours=hour, minutes=15)
        for number in range(per_hour):
            ts = start + timedelta(seconds=number * 3600 / max(per_hour, 1) / 2)
            rows.append(_event(item, len(rows), ts, _BACKGROUND))
    domain = item.domain or {}
    for other in range(int(domain.get("devices", 0))):
        ts = t0 - timedelta(days=float(domain.get("since_days", 0)), minutes=other + 1)
        rows.append(
            _event(item, len(rows), ts, item.target, device_id=f"other-{other}", device_name=None)
        )
    return rows


def _first_seen_rows(item: GoldItem, t0: datetime) -> list[dict[str, Any]]:
    rows = []
    device = item.device
    if device is not None:
        rows.append(
            {
                "profile_id": item.profile,
                "kind": "device",
                "subject": "",
                "value": device["id"],
                "first_ts": t0 - timedelta(days=float(device.get("days", 0))),
                "first_event_id": f"{item.profile}-device",
            }
        )
    domain = item.domain
    if domain is not None:
        rows.append(
            {
                "profile_id": item.profile,
                "kind": "root",
                "subject": "",
                "value": item.target,
                "first_ts": t0 - timedelta(days=float(domain.get("since_days", 0))),
                "first_event_id": f"{item.profile}-root",
            }
        )
    return rows


def _finding_row(
    item: GoldItem,
    *,
    key: str,
    rule: str,
    target: str,
    severity: Severity,
    evidence: dict[str, Any],
    first: datetime,
    last: datetime,
    count: int,
    status: str,
) -> dict[str, Any]:
    device = item.device
    return {
        "dedupe_key": f"{item.profile}|{key}",
        "rule_id": rule,
        "severity": severity.value,
        "profile_id": item.profile,
        "subject": device["id"] if device is not None else None,
        "device_mode": device is not None,
        "target": target,
        "first_ts": first,
        "last_ts": last,
        "event_count": count,
        "evidence": evidence,
        "event_id": f"{item.profile}-0",
        "status": status,
        "created_at": first,
        "updated_at": last,
    }


def _finding_rows(
    item: GoldItem, t0: datetime, now: datetime, floors: Mapping[str, Severity]
) -> list[dict[str, Any]]:
    """Earlier findings on the same rule and target, the rule's recent history, and others."""
    rows = []
    number = 0
    for status, count in sorted(item.earlier.items()):
        for _ in range(count):
            number += 1
            ts = t0 - timedelta(days=number + 1)
            rows.append(
                _finding_row(
                    item,
                    key=f"earlier-{number}",
                    rule=item.rule,
                    target=item.target,
                    severity=floors[item.rule],
                    evidence=dict(item.evidence),
                    first=ts,
                    last=ts,
                    count=1,
                    status=status,
                )
            )
    for status, count in sorted(item.history.items()):
        for _ in range(count):
            number += 1
            ts = t0 - timedelta(days=number + 1)
            rows.append(
                _finding_row(
                    item,
                    key=f"history-{number}",
                    rule=item.rule,
                    target=f"192.168.1.{100 + number}",
                    severity=floors[item.rule],
                    evidence={},
                    first=ts,
                    last=ts,
                    count=1,
                    status=status,
                )
            )
    for index, (rule, target) in enumerate(item.others):
        ts = t0 - timedelta(minutes=10 * (index + 1))
        rows.append(
            _finding_row(
                item,
                key=f"other-{index}",
                rule=rule,
                target=target,
                severity=floors[rule],
                evidence={},
                first=ts,
                last=ts,
                count=1,
                status="open",
            )
        )
    last = min(t0 + timedelta(minutes=30 * (item.events - 1)), now)
    rows.append(
        _finding_row(
            item,
            key="finding",
            rule=item.rule,
            target=item.target,
            severity=floors[item.rule],
            evidence=dict(item.evidence),
            first=t0,
            last=last,
            count=item.events,
            status="open",
        )
    )
    return rows


def _reference_rows(
    items: Sequence[GoldItem], now: datetime
) -> tuple[dict[str, int], dict[str, int], set[tuple[str, str]]]:
    """Ranks, ages and feed entries for every target, the first value given winning."""
    ranks: dict[str, int] = {}
    ages: dict[str, int] = {}
    feeds: set[tuple[str, str]] = set()
    for item in items:
        domain = item.domain or {}
        if domain.get("rank") is not None:
            ranks.setdefault(item.target, int(domain["rank"]))
        if domain.get("age_days") is not None:
            ages.setdefault(item.target, int(domain["age_days"]))
        feeds.update((item.target, str(feed)) for feed in domain.get("feeds") or ())
    return ranks, ages, feeds


async def seed(
    engine: AsyncEngine, items: Sequence[GoldItem], specs: Sequence[RuleSpec], now: datetime
) -> list[StoredFinding]:
    """Write every item's records and finding; return the findings in item order."""
    floors = {spec.id: spec.severity for spec in specs}
    ranks, ages, feeds = _reference_rows(items, now)
    async with engine.begin() as connection:
        if ranks:
            await connection.execute(
                popularity.insert(), [{"domain": d, "rank": r} for d, r in ranks.items()]
            )
        if ages:
            await connection.execute(
                domain_age.insert(),
                [
                    {
                        "root": root,
                        "status": "found",
                        "registered_at": now - timedelta(days=age),
                        "fetched_at": now,
                    }
                    for root, age in ages.items()
                ],
            )
        if feeds:
            await connection.execute(
                threat_intel.insert(), [{"domain": d, "feed": f} for d, f in sorted(feeds)]
            )
        for item in items:
            t0 = _when(item, now)
            for chunk in batched(_world_events(item, t0), 1000, strict=False):
                await connection.execute(events.insert(), list(chunk))
            rows = _first_seen_rows(item, t0)
            if rows:
                await connection.execute(first_seen.insert(), rows)
            await connection.execute(findings.insert(), _finding_rows(item, t0, now, floors))
        result = []
        for item in items:
            row = (
                await connection.execute(
                    findings.select().where(findings.c.dedupe_key == f"{item.profile}|finding")
                )
            ).one()
            result.append(finding_from_row(row))
    return result


# --- scoring --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Invented:
    """One fact an answer states that the data it was given does not support."""

    kind: str  # name, owner, family, source, age, forbidden
    text: str
    sentence: str


@dataclass(frozen=True, slots=True)
class Score:
    """How one answer did against its gold item."""

    cause: bool
    action: bool
    invented: tuple[Invented, ...]

    @property
    def correct(self) -> bool:
        """Right cause, an actionable step, and nothing invented."""
        return self.cause and self.action and not self.invented


def _readable(text: str) -> str:
    """Model text as written: defanged dots and schemes put back."""
    return text.replace("[.]", ".").replace("hxxp", "http")


def _sentence(text: str, start: int) -> str:
    for part in _SENTENCE.split(text):
        offset = text.find(part)
        if offset <= start < offset + len(part):
            return part.strip()
    return text.strip()


def _any(patterns: Sequence[str], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _claims(text: str) -> Iterator[tuple[str, str, int]]:
    """Every checkable claim in ``text``: its kind, what it names, and where."""
    for match in _NAME.finditer(text.lower()):
        yield "name", match.group(1), match.start()
    for match in _OWNER.finditer(text):
        if match.group(1).split()[0] not in _NOT_OWNERS:
            yield "owner", match.group(1), match.start()
    for match in _FAMILIES.finditer(text):
        yield "family", match.group(1), match.start()
    for match in _SOURCES.finditer(text):
        yield "source", match.group(1) or match.group(2), match.start()
    for match in _AGE.finditer(text):
        yield "age", match.group(0), match.start()


def _supported(kind: str, value: str, known: str) -> bool:
    """Whether what the model was given backs one claim."""
    if kind == "age":
        return bool(_KNOWN_AGE.search(known))
    if kind == "owner":
        return value.split()[0].lower() in known
    return value.lower().replace(" ", "") in known.replace(" ", "")


def invented_facts(text: str, known: str, forbidden: Sequence[str] = ()) -> list[Invented]:
    """Facts in ``text`` that ``known`` (what the model was given) does not support."""
    text = _readable(text)
    known = known.lower()
    found = [
        Invented(kind, value, _sentence(text, start))
        for kind, value, start in _claims(text)
        if not _supported(kind, value, known)
    ]
    found.extend(
        Invented("forbidden", match.group(0), _sentence(text, match.start()))
        for pattern in forbidden
        for match in re.finditer(pattern, text, re.IGNORECASE)
    )
    return found


def _words(text: str, target: str = "") -> str:
    """Text with every domain name and an identifier-like target taken out.

    A cause then has to be stated in words. Without this, repeating a name such
    as homelab-metrics.net, or a target such as the device id dev-esp-3a7f,
    would match a cause pattern by itself. A plain-word target such as the
    category "gambling" stays: naming it is the right answer.
    """
    text = _readable(text).lower()
    if _IDENTIFIER.search(target):
        text = text.replace(target.lower(), " ")
    return _NAME.sub(" ", text)


def score(item: GoldItem, analysis: Analysis, known: str) -> Score:
    """Score one answer: cause, action, and any invented fact."""
    explained = _words(f"{analysis.summary} {analysis.likely_cause}", item.target)
    action = _words(analysis.recommended_action, item.target)
    every = f"{analysis.summary} {analysis.likely_cause} {analysis.recommended_action}"
    return Score(
        cause=_any(item.expect.cause, explained),
        action=_any(item.expect.action, action),
        invented=tuple(invented_facts(every, known, item.expect.forbidden)),
    )


# --- running ------------------------------------------------------------------------------


@dataclass(slots=True)
class RuleQuality:
    """Scores for one rule's gold items."""

    items: int = 0
    cause: int = 0
    action: int = 0
    invented: int = 0
    correct: int = 0


@dataclass(slots=True)
class QualityResult:
    """How one source of explanations did on the gold set."""

    source: str  # "template", or the model's name
    think: bool = False
    items: int = 0
    cause: int = 0
    action: int = 0
    invented: int = 0
    correct: int = 0
    by_rule: dict[str, RuleQuality] = field(default_factory=dict)
    by_kind: dict[str, list[int]] = field(default_factory=dict)  # kind: [items, correct]
    template_answers: int = 0  # the model's answer was unusable and the template stood in
    runs: int = 1
    #: Answers fully right in each run, to show how much runs vary.
    correct_by_run: list[int] = field(default_factory=list)
    durations_ms: list[float] = field(default_factory=list)
    #: For checking by eye: every miss of the first run, and every answer of any
    #: run that invented a fact.
    cases: list[dict[str, str]] = field(default_factory=list)

    def merge(self, other: QualityResult) -> None:
        """Add another run of the same model, keeping its answers that invented a fact."""
        run = str(self.runs + 1)
        self.cases += [{**case, "run": run} for case in other.cases if case["invented"]]
        for name in ("items", "cause", "action", "invented", "correct", "template_answers"):
            setattr(self, name, getattr(self, name) + getattr(other, name))
        for rule, scores in other.by_rule.items():
            mine = self.by_rule.setdefault(rule, RuleQuality())
            for name in ("items", "cause", "action", "invented", "correct"):
                setattr(mine, name, getattr(mine, name) + getattr(scores, name))
        for kind, (count, right) in other.by_kind.items():
            mine_kind = self.by_kind.setdefault(kind, [0, 0])
            mine_kind[0] += count
            mine_kind[1] += right
        self.runs += other.runs
        self.correct_by_run += other.correct_by_run
        self.durations_ms += other.durations_ms

    def add(self, item: GoldItem, analysis: Analysis, result: Score) -> None:
        """Count one scored answer."""
        rule = self.by_rule.setdefault(item.rule, RuleQuality())
        kind = self.by_kind.setdefault(item.kind, [0, 0])
        for target in (self, rule):
            target.items += 1
            target.cause += result.cause
            target.action += result.action
            target.invented += bool(result.invented)
            target.correct += result.correct
        kind[0] += 1
        kind[1] += result.correct
        if result.correct:
            return
        missing = [
            name for name, ok in (("cause", result.cause), ("action", result.action)) if not ok
        ]
        self.cases.append(
            {
                "id": item.id,
                "rule": item.rule,
                "missing": ", ".join(missing),
                "invented": "; ".join(
                    f"{fact.kind} {fact.text!r} in: {fact.sentence}" for fact in result.invented
                ),
                "cause": analysis.likely_cause,
                "action": analysis.recommended_action,
            }
        )

    @property
    def mean_ms(self) -> float | None:
        """Average time per model call, in milliseconds."""
        return mean(self.durations_ms) if self.durations_ms else None


def _shuffled(ident: str) -> str:
    """A sort key that mixes items the same way on every run."""
    return hashlib.sha256(ident.encode()).hexdigest()


def _payload_items(requests: Iterable[str]) -> dict[int, str]:
    """What the model was given about each finding, from the recorded requests."""
    given: dict[int, str] = {}
    for request in requests:
        try:
            body = json.loads(request)
        except ValueError:
            continue
        for entry in body.get("findings", []):
            given.setdefault(int(entry["finding_id"]), json.dumps(entry))
    return given


def template_quality(
    items: Sequence[GoldItem], found: Sequence[StoredFinding], specs: Sequence[RuleSpec]
) -> QualityResult:
    """Score the template the analyst falls back to, on every gold item."""
    by_id = {spec.id: spec for spec in specs}
    result = QualityResult(source="template")
    for item, finding in zip(items, found, strict=True):
        analysis = template_analysis(finding, by_id.get(finding.rule_id))
        known = json.dumps(finding.evidence) + finding.target
        result.add(item, analysis, score(item, analysis, known))
    return result


async def model_quality(
    client: RecordingClient,
    analyst: Analyst,
    items: Sequence[GoldItem],
    found: Sequence[StoredFinding],
    *,
    think: bool,
) -> QualityResult:
    """Ask the production analyst, cache off, about every gold item, and score the answers.

    The findings go ten at a time in a fixed order shuffled by item id, so each
    request mixes rules as the service's do. Sent in file order, a request would
    hold one rule's findings only, and a model tends to copy one verdict across
    them.
    """
    order = sorted(range(len(found)), key=lambda index: _shuffled(items[index].id))
    mixed = [found[index] for index in order]
    asked = await settle(analyst.analyse(batch) for batch in batched(mixed, BATCH, strict=False))
    analyses = {analysis.finding_id: analysis for batch in asked for analysis in batch}
    given = _payload_items(client.requests)
    result = QualityResult(source=client.model, think=think, durations_ms=client.durations_ms)
    for item, finding in zip(items, found, strict=True):
        analysis = analyses[finding.id]
        result.template_answers += analysis.source == "template"
        result.add(item, analysis, score(item, analysis, given.get(finding.id, "")))
    result.correct_by_run = [result.correct]
    return result


def production_analyst(
    client: RecordingClient,
    specs: Sequence[RuleSpec],
    scratch: AsyncEngine,
    *,
    context_tokens: int | None = None,
) -> Analyst:
    """The analyst as the service builds it, with its cache off, reading ``scratch``.

    ``context_tokens`` is the model's window: requests are then sized to fit
    it, as the service's are, so none is cut short.
    """
    return Analyst(
        client,
        AnalysisStore(scratch),
        specs,
        max_batch=BATCH,
        cache_ttl=timedelta(0),
        context_tokens=context_tokens,
        context=ContextPacker(ContextStore(scratch)),
    )
