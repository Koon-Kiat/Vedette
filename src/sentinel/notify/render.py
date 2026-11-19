"""Turns findings and health events into plain-text messages.

Everything that came from DNS traffic or the model is untrusted: names are
defanged, control characters are stripped and lengths are capped here, before
any channel sees the text.
"""

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from sentinel.llm.schema import Analysis
from sentinel.notify.channels import OutgoingMessage
from sentinel.notify.defang import clean_text, defang, defang_text
from sentinel.rules.model import RuleSpec, Severity
from sentinel.storage.store import StoredFinding

TITLE_LIMIT = 200

_TAGS = {
    Severity.CRITICAL: ("rotating_light",),
    Severity.HIGH: ("warning",),
}


def safe(value: Any, *, limit: int = 300) -> str:
    """Render an untrusted value on one line: defanged, no control characters."""
    if isinstance(value, (list, tuple)):
        return ", ".join(safe(item, limit=limit) for item in value)
    if isinstance(value, str):
        return defang(clean_text(value, limit=limit))
    return clean_text(str(value), limit=limit)


def prose(value: str, *, limit: int = 400) -> str:
    """Render untrusted sentences: names defanged, punctuation kept."""
    return defang_text(clean_text(value, limit=limit))


def local_time(moment: datetime, tz: ZoneInfo) -> str:
    """``2026-03-15 12:30 (Asia/Singapore)``."""
    return f"{moment.astimezone(tz):%Y-%m-%d %H:%M} ({tz.key})"


def alert_key(finding: StoredFinding) -> str:
    """Key shared by alerts about the same thing, used for the cooldown."""
    return "|".join(
        ["alert", finding.rule_id, finding.profile_id, finding.subject or "-", finding.target]
    )


def effective_priority(finding: StoredFinding, analysis: Analysis | None) -> Severity:
    """The analysis's priority if any, never below the rule's floor."""
    if analysis is None or analysis.priority.rank < finding.severity.rank:
        return finding.severity
    return analysis.priority


def render_alert(
    finding: StoredFinding,
    analysis: Analysis | None,
    *,
    spec: RuleSpec | None,
    profile_label: str,
    tz: ZoneInfo,
) -> OutgoingMessage:
    """Build the instant alert for a finding."""
    priority = effective_priority(finding, analysis)
    label = clean_text(profile_label, limit=64)
    target = label if finding.target == finding.profile_id else safe(finding.target, limit=120)
    title = f"{priority.value.upper()}: {finding.rule_id}, {target} ({label})"[:TITLE_LIMIT]

    if finding.device_mode and finding.subject is not None:
        device = f"Device: {safe(finding.subject, limit=64)}"
        name = finding.evidence.get("device_name")
        if isinstance(name, str) and name:
            device += f" ({safe(name, limit=64)})"
    else:
        device = "Device: attribution unavailable on this profile"
    events = f"{finding.event_count} event" + ("" if finding.event_count == 1 else "s")
    lines = [
        f"Rule: {finding.rule_id} (severity floor {finding.severity.value})",
        f"Profile: {label}",
        device,
        f"Last seen: {local_time(finding.last_ts, tz)}, {events}",
    ]
    if priority is not finding.severity:
        lines.append(
            f"Priority: {priority.value.upper()} "
            f"(raised from {finding.severity.value.upper()} by the local model)"
        )
    lines.append("")
    if analysis is not None:
        lines += [
            prose(analysis.summary),
            f"Likely cause: {prose(analysis.likely_cause, limit=300)}",
            f"Do: {prose(analysis.recommended_action, limit=300)}",
        ]
        if analysis.source == "template":
            lines.append("(standard explanation; the local model was not used)")
    else:
        if spec is not None:
            lines.append(prose(spec.description))
        lines.append("(not explained yet; the local model's view will be in the digest)")
    lines += ["", "Evidence:"]
    lines += [
        f"  {clean_text(str(key), limit=64)}: {safe(value)}"
        for key, value in sorted(finding.evidence.items())
        if value is not None
    ]
    lines += ["", f"Finding #{finding.id}. More: sentinel findings --rule {finding.rule_id}"]
    return OutgoingMessage(
        title=title, body="\n".join(lines), priority=priority, tags=_TAGS.get(priority, ())
    )


def render_health(text: str, *, resolved: bool, since: datetime, tz: ZoneInfo) -> OutgoingMessage:
    """Build a health problem or recovery message. ``text`` is our own wording."""
    detail = clean_text(text, limit=160)
    if resolved:
        return OutgoingMessage(
            title=f"Resolved: {detail}"[:TITLE_LIMIT],
            body=f"Resolved: {detail}\nThe problem had started {local_time(since, tz)}.",
            priority=Severity.LOW,
            tags=("white_check_mark",),
        )
    return OutgoingMessage(
        title=f"Health problem: {detail}"[:TITLE_LIMIT],
        body=(
            f"{detail}\n\nProblem since {local_time(since, tz)}.\n"
            "Details: docker compose logs sentinel"
        ),
        priority=Severity.HIGH,
        tags=("stethoscope",),
    )


def render_test(now: datetime, tz: ZoneInfo) -> OutgoingMessage:
    """Build the message sent by ``sentinel notify --test``."""
    return OutgoingMessage(
        title="NextDNS Sentinel test notification",
        body=(
            "If you can read this, alerts and the daily digest will reach you here.\n"
            f"Sent {local_time(now, tz)}."
        ),
        priority=Severity.MEDIUM,
        tags=("test_tube",),
    )
