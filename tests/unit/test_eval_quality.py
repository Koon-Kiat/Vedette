"""The explanation-quality test: its gold set, and how answers are scored."""

import json
from collections import Counter

import pytest

from vedette.eval import quality
from vedette.rules.loader import load_rules
from vedette.shared.models import Analysis, Severity

SPECS = load_rules()

ITEM = """\
names:
  - id: t-1
    rule: volume-spike
    kind: benign
    scenario: An update.
    target: dev-mac
    device: {id: dev-mac, name: MacBook, days: 10, per_hour: 5}
    evidence: {queries_this_hour: 900, baseline_per_hour: 50.0, factor: 5.0}
    nearby: [swcdn.apple.com]
    expect:
      cause: ['update|upgrade']
      action: ['nothing|no action']
"""


def gold(text: str = ITEM) -> list[quality.GoldItem]:
    return quality.load_gold(SPECS, text)


def answer(summary: str, cause: str, action: str) -> Analysis:
    return Analysis(
        finding_id=1,
        summary=summary,
        likely_cause=cause,
        recommended_action=action,
        priority=Severity.LOW,
        group_key="g",
        confidence=0.5,
        source="llm",
        model="m",
    )


def test_the_packaged_gold_set_covers_every_rule_six_times() -> None:
    items = quality.load_gold(SPECS)

    counts = Counter(item.rule for item in items)
    assert set(counts) == {spec.id for spec in SPECS}
    assert set(counts.values()) == {6}
    assert {item.kind for item in items} == set(quality.KINDS)


def test_a_dga_like_item_carries_the_lexical_evidence_the_rule_records() -> None:
    item = next(item for item in quality.load_gold(SPECS) if item.id == "dl-malware")

    assert item.evidence["label"] == "kq7vb2mtrpzlw"
    assert item.evidence["randomness"] > 20


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("rule: volume-spike", "rule: no-such-rule", "unknown rule"),
        ("kind: benign", "kind: friendly", "kind must be one of"),
        ("cause: ['update|upgrade']", "cause: ['(unclosed']", "bad pattern"),
        ("cause: ['update|upgrade']", "cause: []", "at least one cause"),
        ("factor: 5.0}", "factor: 5.0, fqdn: x.example}", "evidence the rule does not record"),
        ("    target: dev-mac\n", "", "missing or malformed"),
    ],
)
def test_a_bad_gold_item_is_refused_with_its_id(old: str, new: str, message: str) -> None:
    with pytest.raises(ValueError, match=message) as excinfo:
        gold(ITEM.replace(old, new))

    assert str(excinfo.value).startswith("t-1")


def test_an_id_listed_twice_is_refused() -> None:
    twice = ITEM + ITEM.split("names:\n", 1)[1]

    with pytest.raises(ValueError, match="listed twice"):
        gold(twice)


def test_a_cause_must_be_said_in_words_not_by_repeating_a_name() -> None:
    (item,) = gold(ITEM.replace("target: dev-mac", "target: dev-update-box"))

    named = quality.score(
        item,
        answer("Lookups to update[.]apple[.]com from dev-update-box.", "Unknown.", "No action."),
        "",
    )
    said = quality.score(item, answer("A spike.", "A system update.", "No action needed."), "")

    assert (named.cause, named.action) == (False, True)
    assert said.correct


def test_invented_facts_are_names_owners_families_sources_and_dates() -> None:
    given = json.dumps({"root": "sophosxl.net", "sample_fqdn": "a1.sxl.sophosxl.net"})
    text = (
        "Lookups to sophosxl[.]net and update.sophos-cdn.com. The domain is owned by Microsoft. "
        "It behaves like Emotet. It is listed on VirusTotal. It was registered in 2019."
    )

    found = quality.invented_facts(text, given)

    assert [(fact.kind, fact.text) for fact in found] == [
        ("name", "update.sophos-cdn.com"),
        ("owner", "Microsoft"),
        ("family", "Emotet"),
        ("source", "VirusTotal"),
        ("age", "registered in 2019"),
    ]
    assert found[1].sentence == "The domain is owned by Microsoft."


def test_what_the_data_holds_is_not_invented() -> None:
    given = json.dumps({"root": "sophosxl.net", "context": {"domain": {"age_days": 7300}}})
    text = (
        "The domain sophosxl.net is operated by Sophos and was registered in 2006. "
        "Look it up on VirusTotal if unsure; it is owned by the vendor."
    )

    assert quality.invented_facts(text, given) == []


def test_an_item_s_forbidden_claims_count_as_invented() -> None:
    found = quality.invented_facts("This is your phone.", "{}", [r"\bis your\b"])

    assert [(fact.kind, fact.text) for fact in found] == [("forbidden", "is your")]


def test_scores_are_counted_per_rule_and_kind_and_every_miss_is_kept() -> None:
    (item,) = gold()
    result = quality.QualityResult(source="m")

    result.add(item, answer("A spike.", "An update.", "No action."), quality.Score(True, True, ()))
    result.add(item, answer("A spike.", "Malware.", "Scan it."), quality.Score(False, False, ()))

    assert (result.items, result.cause, result.correct) == (2, 1, 1)
    assert result.by_rule["volume-spike"].items == 2
    assert result.by_kind == {"benign": [2, 1]}
    assert [case["missing"] for case in result.cases] == ["cause, action"]
    assert result.cases[0]["cause"] == "Malware."
