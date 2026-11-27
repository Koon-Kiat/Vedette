"""The explanation-quality test against a database: the seeded records and both arms."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import respx
from sqlalchemy import func, select

from tests.integration.test_eval import OLLAMA, FakeModel, client
from vedette.eval import quality
from vedette.rules.loader import load_rules
from vedette.storage.models import domain_age, events, findings, first_seen, popularity
from vedette.storage.store import Store

NOW = datetime(2026, 11, 27, 12, tzinfo=UTC)
SPECS = load_rules()


def items(*ids: str) -> list[quality.GoldItem]:
    by_id = {item.id: item for item in quality.load_gold(SPECS)}
    return [by_id[ident] for ident in ids]


async def test_each_item_s_records_are_seeded_in_a_profile_of_its_own(store: Store) -> None:
    chosen = items("tl-acked", "nd-churn", "dl-goz")

    found = await quality.seed(store.engine, chosen, SPECS, NOW)

    assert [(f.rule_id, f.profile_id, f.target) for f in found] == [
        ("tunnel-like", "gold-tl-acked", "homelab-metrics.net"),
        ("new-device", "gold-nd-churn", "192.168.1.73"),
        ("dga-like", "gold-dl-goz", "1t9mwr11wwnkx7138mc1timys7l.com"),
    ]
    acked, churn, goz = found
    assert acked.first_ts == datetime(2026, 11, 24, 14, 20, tzinfo=UTC)
    assert (churn.subject, churn.device_mode) == (None, False)
    async with store.engine.connect() as connection:
        statuses: dict[str, int] = dict(
            (
                await connection.execute(
                    select(findings.c.status, func.count())
                    .where(findings.c.profile_id == "gold-tl-acked")
                    .group_by(findings.c.status)
                )
            ).all()
        )
        others = (
            await connection.execute(
                select(findings.c.rule_id).where(
                    findings.c.profile_id == "gold-dl-goz", findings.c.id != goz.id
                )
            )
        ).scalars()
        nearby = (
            await connection.execute(
                select(events.c.root).where(
                    events.c.profile_id == "gold-tl-acked",
                    events.c.ts.between(
                        acked.first_ts - timedelta(minutes=5), acked.first_ts + timedelta(minutes=5)
                    ),
                )
            )
        ).scalars()
        background = (
            await connection.execute(
                select(func.count()).where(
                    events.c.profile_id == "gold-tl-acked", events.c.root == "background.invalid"
                )
            )
        ).scalar_one()
        device = (
            await connection.execute(
                select(first_seen.c.first_ts).where(
                    first_seen.c.profile_id == "gold-tl-acked", first_seen.c.kind == "device"
                )
            )
        ).scalar_one()
        churn_history = (
            await connection.execute(
                select(func.count()).where(
                    findings.c.profile_id == "gold-nd-churn", findings.c.status == "benign"
                )
            )
        ).scalar_one()
        age = (
            await connection.execute(
                select(domain_age.c.registered_at).where(domain_age.c.root == "homelab-metrics.net")
            )
        ).scalar_one()
        ranked = (await connection.execute(select(func.count()).select_from(popularity))).scalar()
    assert statuses == {"acknowledged": 3, "open": 1}
    assert list(others) == ["dga-burst"]
    assert sorted(set(nearby)) == ["github.com", "grafana.com", "homelab-metrics.net"]
    assert background == 24 * 100
    assert device == acked.first_ts - timedelta(days=700)
    assert churn_history == 6
    assert age == NOW - timedelta(days=1200)
    assert ranked == 0


async def test_the_template_is_scored_on_every_item(store: Store) -> None:
    gold = quality.load_gold(SPECS)
    found = await quality.seed(store.engine, gold, SPECS, NOW)

    result = quality.template_quality(gold, found, SPECS)

    assert result.items == 60
    assert result.invented == 0
    assert 0 < result.correct < result.items
    assert result.by_kind["benign"][1] == 0, "the template never names a harmless cause"


async def test_the_model_s_answers_are_scored_against_what_it_was_given(
    store: Store, router: respx.MockRouter
) -> None:
    FakeModel(router)
    chosen = items("vs-update", "dl-malware")
    found = await quality.seed(store.engine, chosen, SPECS, NOW)
    recording = client()
    try:
        analyst = quality.production_analyst(recording, SPECS, store.engine)
        result = await quality.model_quality(recording, analyst, chosen, found, think=False)
    finally:
        await recording.aclose()

    # The fake model says "An update check." and "No action is needed, this is safe."
    assert (result.items, result.cause, result.action, result.correct) == (2, 1, 1, 1)
    assert [case["id"] for case in result.cases] == ["dl-malware"]
    assert result.source == "fake:1b"
    sent = json.loads(recording.requests[0])["findings"]
    assert {entry["finding_id"] for entry in sent} == {finding.id for finding in found}


async def test_an_unusable_answer_is_scored_as_the_template_that_stood_in(
    store: Store, router: respx.MockRouter
) -> None:
    router.post(f"{OLLAMA}/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"role": "assistant", "content": "{}"}})
    )
    chosen = items("vs-update")
    found = await quality.seed(store.engine, chosen, SPECS, NOW)
    recording = client()
    try:
        analyst = quality.production_analyst(recording, SPECS, store.engine)
        result = await quality.model_quality(recording, analyst, chosen, found, think=False)
    finally:
        await recording.aclose()

    assert result.template_answers == 1
    assert result.correct == 0
