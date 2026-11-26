import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from vedette.cli import app
from vedette.shared.models import Finding, Severity
from vedette.storage.migrate import run_migrations
from vedette.storage.store import Store

runner = CliRunner()
WHEN = datetime(2026, 3, 15, 4, 30, 0, tzinfo=UTC)  # 12:30 in Asia/Singapore


def finding(
    rule: str, severity: str, target: str, evidence: dict[str, Any], *, minute: int = 0
) -> Finding:
    return Finding(
        rule_id=rule,
        severity=Severity(severity),
        profile_id="abc123",
        subject="D1",
        device_mode=True,
        target=target,
        ts=WHEN.replace(minute=30 + minute),
        dedupe_key=f"{rule}|{target}",
        evidence=evidence,
        event_id="e" * 64,
    )


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv("VEDETTE_TIMEZONE", "Asia/Singapore")
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')
    return url


def seed(url: str, items: list[Finding]) -> None:
    async def write() -> None:
        store = Store.open(url)
        try:
            await store.commit_processed([], items)
        finally:
            await store.close()

    run_migrations(url)
    asyncio.run(write())


SAMPLE = [
    finding(
        "young-domain",
        "high",
        "fresh-site.example",
        {"fqdn": "login.fresh-site.example", "root": "fresh-site.example", "domain_age_days": 5},
        minute=2,
    ),
    finding(
        "volume-spike", "low", "D1", {"queries_this_hour": 900, "baseline_per_hour": 50.0}, minute=1
    ),
    finding(
        "threat-intel-allowed",
        "critical",
        "bad.example",
        {"fqdn": "pay.bad.example", "threat_feeds": ["phish"]},
        minute=3,
    ),
]


def test_findings_are_listed_newest_first_with_their_evidence(database: str) -> None:
    seed(database, SAMPLE)

    result = runner.invoke(app, ["findings"])

    assert result.exit_code == 0, result.output
    out = result.output
    assert out.index("threat-intel-allowed") < out.index("young-domain") < out.index("volume-spike")
    assert "CRITICAL" in out
    assert "HIGH" in out
    assert "domain_age_days: 5" in out
    assert "threat_feeds: phish" in out
    assert "2026-03-15 12:32" in out, "times are shown in the configured time zone"
    assert "router" in out


def test_domains_are_defanged_everywhere(database: str) -> None:
    seed(database, SAMPLE)

    out = runner.invoke(app, ["findings"]).output

    assert "fresh-site[.]example" in out
    assert "login[.]fresh-site[.]example" in out
    assert "fresh-site.example" not in out
    assert "bad.example" not in out


def test_hostile_text_in_evidence_cannot_control_the_terminal(database: str) -> None:
    seed(
        database,
        [
            finding(
                "new-device",
                "medium",
                "D\x1b[2J9",
                {"device_name": "TV\x1b]0;owned\x07\r\nFAKE LINE", "client_ip": "198.51.100.7"},
            )
        ],
    )

    out = runner.invoke(app, ["findings"]).output

    assert "\x1b" not in out
    assert "\x07" not in out
    assert "\r" not in out
    assert "\nFAKE LINE" not in out
    assert "198[.]51[.]100[.]7" in out


def test_findings_can_be_filtered(database: str) -> None:
    seed(database, SAMPLE)

    serious = runner.invoke(app, ["findings", "--min-severity", "high"]).output
    one_rule = runner.invoke(app, ["findings", "--rule", "volume-spike"]).output
    limited = runner.invoke(app, ["findings", "--limit", "1"]).output
    by_label = runner.invoke(app, ["findings", "--profile", "router"]).output
    other = runner.invoke(app, ["findings", "--profile", "phone"])

    assert "volume-spike" not in serious
    assert "young-domain" in serious
    assert "young-domain" not in one_rule
    assert "young-domain" not in limited
    assert "threat-intel-allowed" in limited
    assert "young-domain" in by_label
    assert other.exit_code == 2
    assert "phone" in other.output


def test_json_output_is_machine_readable(database: str) -> None:
    seed(database, SAMPLE)

    result = runner.invoke(app, ["findings", "--json", "--rule", "young-domain"])

    (item,) = json.loads(result.output)
    assert item["rule_id"] == "young-domain"
    assert item["severity"] == "high"
    assert item["target"] == "fresh-site.example"
    assert item["evidence"]["domain_age_days"] == 5
    assert item["event_count"] == 1
    assert item["device_mode"] is True


def test_an_unknown_severity_is_a_usage_error(database: str) -> None:
    seed(database, SAMPLE)

    result = runner.invoke(app, ["findings", "--min-severity", "scary"])

    assert result.exit_code == 2


def test_no_findings_is_reported_plainly(database: str) -> None:
    seed(database, [])

    result = runner.invoke(app, ["findings"])

    assert result.exit_code == 0
    assert "No findings" in result.output


def test_a_missing_database_is_explained_instead_of_crashing(database: str) -> None:
    result = runner.invoke(app, ["findings"])

    assert result.exit_code == 0
    assert "no database yet" in result.output.lower()
    assert "Traceback" not in result.output


def test_profile_wide_findings_show_the_profile_label_not_its_id(database: str) -> None:
    item = finding("volume-spike", "low", "abc123", {"queries_this_hour": 900})
    seed(database, [item.model_copy(update={"subject": None, "device_mode": False})])

    out = runner.invoke(app, ["findings"]).output

    assert "volume-spike  router  [router, device attribution unavailable]" in out
    assert "abc123" not in out


def seed_analysis(url: str, **overrides: Any) -> None:
    from vedette.shared.models import Analysis
    from vedette.storage.analysis import AnalysisStore

    async def write() -> None:
        store = Store.open(url)
        try:
            (item,) = await store.list_findings(rule_id="volume-spike")
            values: dict[str, Any] = {
                "finding_id": item.id,
                "summary": "The laptop made five times its usual number of lookups.",
                "likely_cause": "A large software update.",
                "recommended_action": "Check what was running on evil[.]example at the time.",
                "priority": Severity.HIGH,
                "group_key": "volume",
                "confidence": 0.62,
                "source": "llm",
                "model": "qwen3:8b",
            }
            values.update(overrides)
            await AnalysisStore(store.engine).save_analyses([Analysis(**values)], now=WHEN)
        finally:
            await store.close()

    asyncio.run(write())


def test_the_explanation_is_shown_with_each_finding_that_has_one(database: str) -> None:
    seed(database, SAMPLE)
    seed_analysis(database)

    out = runner.invoke(app, ["findings", "--rule", "volume-spike"]).output

    assert "The laptop made five times its usual number of lookups." in out
    assert "A large software update." in out
    assert "Check what was running on evil[.]example at the time." in out
    assert "qwen3:8b" in out


def test_a_raised_priority_is_shown_next_to_the_rule_floor(database: str) -> None:
    seed(database, SAMPLE)
    seed_analysis(database)

    out = runner.invoke(app, ["findings", "--rule", "volume-spike"]).output

    assert "HIGH" in out
    assert "raised from LOW" in out


def test_findings_without_an_explanation_say_so(database: str) -> None:
    seed(database, SAMPLE)

    out = runner.invoke(app, ["findings", "--rule", "young-domain"]).output

    assert "not analysed yet" in out


def test_a_template_explanation_is_labelled_as_such(database: str) -> None:
    seed(database, SAMPLE)
    seed_analysis(database, source="template", model=None, priority=Severity.LOW, confidence=0.0)

    out = runner.invoke(app, ["findings", "--rule", "volume-spike"]).output

    assert "standard explanation" in out
    assert "qwen3:8b" not in out


def test_min_severity_uses_the_raised_priority(database: str) -> None:
    seed(database, SAMPLE)
    seed_analysis(database)

    out = runner.invoke(app, ["findings", "--min-severity", "high"]).output

    assert "volume-spike" in out, "raised to high by the analysis, so it is listed"


def test_json_output_includes_the_analysis(database: str) -> None:
    seed(database, SAMPLE)
    seed_analysis(database)

    result = runner.invoke(app, ["findings", "--json", "--rule", "volume-spike"])

    (item,) = json.loads(result.output)
    assert item["severity"] == "low"
    assert item["analysis"]["priority"] == "high"
    assert item["analysis"]["source"] == "llm"
    assert item["analysis"]["confidence"] == 0.62


def test_benign_marks_a_finding_and_allowlists_its_domain(database: str) -> None:
    seed(database, SAMPLE)

    async def target_id() -> int:
        store = Store.open(database)
        try:
            (item,) = await store.list_findings(rule_id="young-domain")
            return item.id
        finally:
            await store.close()

    fid = asyncio.run(target_id())

    declined = runner.invoke(app, ["benign", str(fid)], input="n\n")
    accepted = runner.invoke(app, ["benign", str(fid)], input="y\n")

    assert declined.exit_code == 1
    assert "fresh-site[.]example" in declined.output
    assert "fresh-site.example" not in declined.output
    assert accepted.exit_code == 0, accepted.output
    assert "Marked benign" in accepted.output

    async def status() -> str:
        store = Store.open(database)
        try:
            (item,) = await store.list_findings(rule_id="young-domain")
            return item.status
        finally:
            await store.close()

    assert asyncio.run(status()) == "benign"


def test_benign_with_yes_skips_the_question(database: str) -> None:
    seed(database, SAMPLE)

    result = runner.invoke(app, ["benign", "1", "--yes"])

    assert result.exit_code == 0, result.output


def test_benign_on_an_unknown_finding_is_an_error(database: str) -> None:
    seed(database, SAMPLE)

    result = runner.invoke(app, ["benign", "99999", "--yes"])

    assert result.exit_code == 2
    assert "No finding 99999" in result.output
