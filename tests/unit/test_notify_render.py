"""What alert, health and test messages say. All untrusted text is made safe."""

from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from vedette.llm.schema import Analysis
from vedette.notify.render import alert_key, render_alert, render_health, render_test
from vedette.rules.loader import load_rules
from vedette.rules.model import Severity
from vedette.storage.store import StoredFinding

SGT = ZoneInfo("Asia/Singapore")
WHEN = datetime(2026, 3, 15, 4, 30, tzinfo=UTC)  # 12:30 in Singapore
SPECS = {spec.id: spec for spec in load_rules()}


def finding(**overrides: Any) -> StoredFinding:
    values: dict[str, Any] = {
        "id": 42,
        "rule_id": "threat-intel-allowed",
        "severity": Severity.CRITICAL,
        "profile_id": "abc123",
        "subject": None,
        "device_mode": False,
        "target": "bad.example",
        "first_ts": WHEN,
        "last_ts": WHEN,
        "event_count": 3,
        "evidence": {"fqdn": "pay.bad.example", "threat_feeds": ["phish"], "status": "default"},
        "status": "open",
    }
    values.update(overrides)
    return StoredFinding(**values)


def analysis(**overrides: Any) -> Analysis:
    values: dict[str, Any] = {
        "finding_id": 42,
        "summary": "A device reached a listed phishing domain, bad[.]example.",
        "likely_cause": "A phishing link was opened.",
        "recommended_action": "Scan the device and change passwords.",
        "priority": Severity.CRITICAL,
        "group_key": "phishing",
        "confidence": 0.8,
        "source": "llm",
        "model": "qwen3:8b",
    }
    values.update(overrides)
    return Analysis(**values)


def render(item: StoredFinding, explained: Analysis | None = None) -> Any:
    return render_alert(
        item, explained, spec=SPECS.get(item.rule_id), profile_label="router", tz=SGT
    )


def test_alert_title_names_priority_rule_and_defanged_target() -> None:
    sent = render(finding(), analysis())

    assert sent.title == "CRITICAL: Threat-feed domain allowed, bad[.]example (router)"
    assert "Rule: Threat-feed domain allowed (threat-intel-allowed), severity floor critical" in (
        sent.body
    )
    assert sent.body.endswith("More: vedette findings --rule threat-intel-allowed")
    assert sent.priority is Severity.CRITICAL


def test_an_alert_names_a_nextdns_reason_by_its_name() -> None:
    sent = render(
        finding(
            rule_id="new-destination-category",
            severity=Severity.LOW,
            target="ads",
            evidence={"category": "ads", "category_name": "Ads and trackers"},
        )
    )

    assert sent.title.startswith("LOW: New category or blocklist, Ads and trackers (")
    assert "Rule: New category or blocklist (new-destination-category)" in sent.body


def test_alert_body_carries_the_explanation_time_and_evidence() -> None:
    body = render(finding(), analysis()).body

    assert "2026-03-15 12:30 (Asia/Singapore)" in body
    assert "3 events" in body
    assert "Device: attribution unavailable on this profile" in body
    assert "A device reached a listed phishing domain, bad[.]example." in body
    assert "Likely cause: A phishing link was opened." in body
    assert "Do: Scan the device and change passwords." in body
    assert "fqdn: pay[.]bad[.]example" in body
    assert "threat_feeds: phish" in body
    assert "Finding #42" in body


def test_alert_names_the_device_when_there_is_one() -> None:
    item = finding(subject="D1", device_mode=True, evidence={"device_name": "Kitchen tablet"})

    assert "Device: D1" in render(item).body


def test_alert_without_an_analysis_falls_back_to_the_rule_description() -> None:
    body = render(finding()).body

    assert SPECS["threat-intel-allowed"].description[:40] in body
    assert "not explained yet" in body


def test_alert_uses_the_raised_priority_and_says_so() -> None:
    item = finding(rule_id="volume-spike", severity=Severity.LOW, target="abc123")

    sent = render(item, analysis(priority=Severity.HIGH))

    assert sent.priority is Severity.HIGH
    assert sent.title.startswith("HIGH: Query volume spike")
    assert "raised from LOW" in sent.body


def test_profile_wide_target_shows_the_profile_label() -> None:
    item = finding(rule_id="volume-spike", severity=Severity.LOW, target="abc123")

    assert "abc123" not in render(item).title


def test_hostile_text_is_neutralised_everywhere() -> None:
    item = finding(
        target="evil.example",
        evidence={
            "fqdn": "https://evil.example/\x1b[2J",
            "device_name": "<script>alert(1)</script>\r\nFAKE: line",
        },
    )

    sent = render(item, analysis(summary="Visit https://evil.example now"))

    for text in (sent.title, sent.body):
        assert "evil.example" not in text
        assert "http" not in text.lower()
        assert "\x1b" not in text
        assert "\r" not in text
    assert "\nFAKE: line" not in sent.body


def test_alert_title_is_capped() -> None:
    sent = render(finding(target="a" * 400 + ".example"))

    assert len(sent.title) <= 200


def test_alert_key_is_shared_by_rows_for_the_same_thing() -> None:
    first = finding(id=1)
    next_day = finding(id=2, first_ts=WHEN.replace(day=16), last_ts=WHEN.replace(day=16))

    assert alert_key(first) == alert_key(next_day)
    assert alert_key(first) != alert_key(finding(target="other.example"))
    assert alert_key(first) != alert_key(finding(subject="D1", device_mode=True))


def test_health_problem_and_recovery_messages() -> None:
    problem = render_health(
        "No events from router for 2 h 15 min", resolved=False, since=WHEN, tz=SGT
    )
    fixed = render_health("No events from router for 2 h 15 min", resolved=True, since=WHEN, tz=SGT)

    assert problem.title == "Health problem: No events from router for 2 h 15 min"
    assert problem.priority is Severity.HIGH
    assert "since 2026-03-15 12:30 (Asia/Singapore)" in problem.body
    assert fixed.title.startswith("Resolved: ")
    assert fixed.priority is Severity.LOW


def test_test_message_explains_itself() -> None:
    sent = render_test(WHEN, SGT)

    assert "test" in sent.title.lower()
    assert "2026-03-15 12:30" in sent.body
    assert sent.priority is Severity.MEDIUM
