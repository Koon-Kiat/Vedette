"""An explanation's leaning, lists and cited fields: stored, shown, and compared with triage."""

from typing import Any

import pytest
from sqlalchemy import text, update

from tests.digest_fixture import PERIOD_END, PROFILES, TZ
from tests.integration.web_helpers import logged_in
from tests.web_fixture import build_web_fixture
from vedette.notify.digest import DigestBuilder, render_digest
from vedette.notify.render import render_alert
from vedette.rules.loader import load_rules
from vedette.shared.models import Analysis, Severity
from vedette.storage.analysis import CALIBRATION_MINIMUM, AnalysisStore, leaning_outcomes
from vedette.storage.models import findings
from vedette.storage.store import Store

SPECS = {spec.id: spec for spec in load_rules()}


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    return store


async def finding_id(store: Store, rule: str, target: str) -> int:
    found = await store.list_findings(rule_id=rule, limit=100)
    return next(f.id for f in found if f.target == target)


def analysis(finding_id: int, **overrides: Any) -> Analysis:
    values: dict[str, Any] = {
        "finding_id": finding_id,
        "summary": "The laptop opened a sign-in page on a five-day-old domain.",
        "likely_cause": "A phishing link.",
        "recommended_action": "Do not enter a password there.",
        "priority": Severity.HIGH,
        "group_key": "new-domains",
        "confidence": 0.62,
        "source": "llm",
        "model": "qwen3:8b",
        "assessment": "threat",
        "harmless": ("A shop the owner just signed up to",),
        "malicious": ("A fake sign-in page", "A link from a phishing email"),
        "checks": ("Ask who opened the link.", "Look for the email that carried it."),
        "evidence_used": ("domain_age_days", "lookups_within_5_minutes"),
        "removed_names": ("contoso[.]example",),
    }
    values.update(overrides)
    return Analysis(**values)


async def save(store: Store, *items: Analysis) -> None:
    await AnalysisStore(store.engine).save_analyses(list(items), now=PERIOD_END)


# --- storage -----------------------------------------------------------------------------


async def test_the_leaning_and_lists_are_stored_and_read_back(filled: Store) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    written = analysis(fid)
    await save(filled, written)

    read = await AnalysisStore(filled.engine).analyses_for([fid])

    assert read[fid] == written


async def test_an_analysis_stored_before_the_lists_still_reads(filled: Store) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    await save(filled, analysis(fid))
    async with filled.engine.begin() as connection:
        await connection.execute(
            text("update finding_analysis set assessment = null, details = null")
        )

    (read,) = (await AnalysisStore(filled.engine).analyses_for([fid])).values()

    assert read.summary == "The laptop opened a sign-in page on a five-day-old domain."
    assert read.assessment is None
    assert read.harmless == read.malicious == read.checks == read.evidence_used == ()


# --- the finding page --------------------------------------------------------------------


async def test_the_finding_page_shows_both_sides_the_checks_and_what_it_rests_on(
    filled: Store,
) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    await save(filled, analysis(fid))

    async with logged_in(filled) as (client, _):
        html = (await client.get(f"/findings/{fid}")).text

    assert '<h3 id="harmless-title">Could be harmless</h3>' in html
    assert "<li>A shop the owner just signed up to</li>" in html
    assert '<h3 id="malicious-title">Could be a threat</h3>' in html
    assert "<li>A fake sign-in page</li><li>A link from a phishing email</li>" in html
    assert (
        "<ol><li>Ask who opened the link.</li><li>Look for the email that carried it.</li></ol>"
    ) in html
    assert "<dt>Leaning</dt><dd><strong>a threat</strong></dd>" in html
    assert "<dt>Based on</dt><dd>Domain age, days, Lookups within 5 minutes</dd>" in html
    assert "1 domain that is not in the records" in html
    assert '<span class="name">contoso[.]example</span>' in html
    assert "contoso.example" not in html


async def test_confidence_is_shown_as_a_band_not_a_number(filled: Store) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    await save(filled, analysis(fid, confidence=0.62))

    async with logged_in(filled) as (client, _):
        html = (await client.get(f"/findings/{fid}")).text

    assert "<dt>Confidence</dt><dd><strong>medium</strong>" in html
    assert "not calibrated" in html
    assert "0.62" not in html
    assert "meter" not in html


async def test_an_older_analysis_shows_without_the_new_parts(filled: Store) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")

    async with logged_in(filled) as (client, _):
        html = (await client.get(f"/findings/{fid}")).text

    assert "The laptop visited fresh-site[.]example" in html
    assert "<dt>Confidence</dt><dd><strong>high</strong>" in html  # the fixture's 0.8
    for absent in ("harmless-title", "checks-title", "<dt>Leaning</dt>", "<dt>Based on</dt>"):
        assert absent not in html


async def test_a_template_shows_the_rule_s_look_alikes_and_checks_with_no_confidence(
    filled: Store,
) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    notes = SPECS["young-domain"].analyst_notes
    assert notes is not None
    await save(
        filled,
        analysis(
            fid,
            source="template",
            model=None,
            confidence=0.0,
            assessment=None,
            harmless=tuple(notes.look_alikes),
            malicious=(),
            checks=tuple(notes.checks),
            evidence_used=(),
            removed_names=(),
        ),
    )

    async with logged_in(filled) as (client, _):
        html = (await client.get(f"/findings/{fid}")).text

    assert "Harmless activity that trips this rule" in html
    assert "Checks this rule suggests" in html
    assert "<dt>Confidence</dt>" not in html
    assert "<dt>Leaning</dt>" not in html


# --- the digest and alerts ---------------------------------------------------------------


async def test_the_digest_lists_both_sides_and_the_checks_in_order(filled: Store) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    await save(filled, analysis(fid))

    _, body = render_digest(
        await DigestBuilder(filled.engine, profiles=PROFILES, tz=TZ).build(PERIOD_END)
    )

    assert "   Could be harmless: A shop the owner just signed up to" in body
    assert "   Could be a threat: A fake sign-in page; A link from a phishing email" in body
    assert "   Check 1: Ask who opened the link.\n   Check 2: Look for the email" in body


async def test_the_digest_leaves_out_a_template_s_look_alikes_but_keeps_its_checks(
    filled: Store,
) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    await save(
        filled,
        analysis(fid, source="template", model=None, confidence=0.0, assessment=None, malicious=()),
    )

    _, body = render_digest(
        await DigestBuilder(filled.engine, profiles=PROFILES, tz=TZ).build(PERIOD_END)
    )

    assert "Could be harmless" not in body
    assert "   Check 1: Ask who opened the link." in body


async def test_an_alert_lists_the_checks(filled: Store) -> None:
    fid = await finding_id(filled, "young-domain", "fresh-site.example")
    (finding,) = [f for f in await filled.list_findings(limit=100) if f.id == fid]

    message = render_alert(
        finding, analysis(fid), spec=SPECS["young-domain"], profile_label="pc", tz=TZ
    )

    assert "Check 1: Ask who opened the link.\nCheck 2: Look for the email" in message.body


# --- leanings against triage -------------------------------------------------------------


async def decided(store: Store, *cases: tuple[str | None, float, str, str]) -> None:
    """Store one analysis per case on fresh findings: (leaning, confidence, source, status)."""
    found = await store.list_findings(limit=100)
    assert len(found) >= len(cases)
    for item, (leaning, confidence, source, status) in zip(found, cases, strict=False):
        await save(
            store,
            analysis(item.id, assessment=leaning, confidence=confidence, source=source),
        )
        async with store.engine.begin() as connection:
            await connection.execute(
                update(findings).where(findings.c.id == item.id).values(status=status)
            )


async def test_leanings_are_compared_with_decisions_in_each_band(filled: Store) -> None:
    await decided(
        filled,
        ("harmless", 0.9, "llm", "benign"),  # high, agreed
        ("threat", 0.6, "cache", "acknowledged"),  # medium, agreed
        ("harmless", 0.2, "llm", "acknowledged"),  # low, disagreed
        ("unclear", 0.9, "llm", "benign"),  # no leaning: left out
        ("threat", 0.9, "llm", "open"),  # not decided: left out
        (None, 0.0, "template", "benign"),  # a template: left out
    )

    async with filled.engine.connect() as connection:
        bands, total = await leaning_outcomes(connection)

    assert total == 3
    assert [(b.band, b.decided, b.agreed) for b in bands] == [
        ("low", 1, 0),
        ("medium", 1, 1),
        ("high", 1, 1),
    ]


async def test_the_evaluation_page_waits_for_enough_decisions(filled: Store) -> None:
    await decided(filled, ("harmless", 0.9, "llm", "benign"))

    async with logged_in(filled) as (client, _):
        html = (await client.get("/evaluation")).text

    assert f"1 of the {CALIBRATION_MINIMUM} decided findings needed" in html
    assert 'id="t-decided"' not in html


async def test_the_evaluation_page_compares_leanings_with_decisions_once_there_are_enough(
    filled: Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vedette.web.routes.pages.CALIBRATION_MINIMUM", 2)
    await decided(
        filled, ("harmless", 0.9, "llm", "benign"), ("harmless", 0.9, "llm", "acknowledged")
    )

    async with logged_in(filled) as (client, _):
        html = (await client.get("/evaluation")).text

    assert 'id="t-decided"' in html
    assert '<td>high</td><td class="num">2</td><td class="num">1 (50%)</td>' in html
