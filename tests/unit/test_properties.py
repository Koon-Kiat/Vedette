"""Properties that must hold for every input, checked on generated ones.

Each test states a promise from a docstring (idempotent defanging, no line
breaks after cleaning, a severity never lowered, a feed match never looked up
under a bare suffix) and lets Hypothesis search for an input that breaks it.
"""

import math
import re
import unicodedata
from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from vedette.enrich.public_suffix import SuffixRules, parse_public_suffix_list
from vedette.rules import prefilter
from vedette.shared.defang import clean_text, defang, defang_names, defang_text
from vedette.shared.models import Finding, Severity
from vedette.shared.names import candidates, lexical_features

LABEL = st.from_regex(r"[a-z0-9](?:[a-z0-9-]{0,14}[a-z0-9])?", fullmatch=True)
WORD_LABEL = st.from_regex(r"[a-z](?:[a-z0-9-]{0,14}[a-z])?", fullmatch=True)
LABELS = st.lists(LABEL, min_size=1, max_size=6)
NAME = LABELS.map(".".join)
FRAGMENTS = st.sampled_from(
    [
        ".",
        "..",
        "[",
        "]",
        "[.]",
        ":",
        "/",
        "http://",
        "HTTPS://",
        "hxxp",
        "example.com",
        " ",
        "  ",
        "\t",
        "\n",
        "\r\n",
        "\x00",
        "\x1b[2J",
        "\u200b",
        "\u202e",
        "\u2028",
        "\xa0",
        "a",
        "Z",
        "7",
        "-",
        "é",
        "例",
    ]
)
TEXT = st.one_of(
    st.text(max_size=200), st.lists(FRAGMENTS | st.text(max_size=3), max_size=40).map("".join)
)

RULES = SuffixRules(
    parse_public_suffix_list(
        "com\norg\nuk\nco.uk\n*.ck\n!www.ck\n"
        "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n"
        "*.compute.example-cloud.com\n!metadata.compute.example-cloud.com\n"
    )
)
SUFFIXES = st.sampled_from(
    ["com", "org", "co.uk", "uk", "ck", "github.io", "compute.example-cloud.com", "test"]
)
SUFFIXED_NAME = st.builds(lambda labels, suffix: ".".join([*labels, suffix]), LABELS, SUFFIXES)


def _has_control(text: str) -> bool:
    return any(unicodedata.category(ch)[0] == "C" for ch in text)


@given(TEXT)
def test_defanging_twice_is_the_same_as_once(text: str) -> None:
    assert defang(defang(text)) == defang(text)
    assert defang_text(defang_text(text)) == defang_text(text)
    assert defang_names(defang_names(text)) == defang_names(text)


@given(TEXT)
def test_defanged_text_has_no_bare_dot_no_link_scheme_and_no_control(text: str) -> None:
    out = defang(text)
    assert "." not in out.replace("[.]", "")
    assert re.search(r"https?://", out, re.IGNORECASE) is None
    assert not _has_control(out)


@given(NAME)
def test_a_name_in_a_sentence_has_every_inner_dot_bracketed(name: str) -> None:
    bracketed = name.replace(".", "[.]")
    assert defang_text(f"Visit {name}. Then stop.") == f"Visit {bracketed}. Then stop."


@given(st.lists(WORD_LABEL, min_size=2, max_size=5), st.integers(0, 999), st.integers(0, 99))
def test_dotted_numbers_stay_numbers_while_names_are_bracketed(
    labels: list[str], whole: int, part: int
) -> None:
    name = ".".join(labels)
    out = defang_names(f"{whole}.{part} GB free on {name}.")
    assert out == f"{whole}.{part} GB free on {name.replace('.', '[.]')}."


@given(TEXT, st.integers(0, 120))
def test_cleaned_text_fits_its_limit_on_one_line(text: str, limit: int) -> None:
    out = clean_text(text, limit=limit)
    assert len(out) <= limit
    assert not _has_control(out)
    assert all(ch == " " for ch in out if ch.isspace())
    assert "  " not in out


@given(st.lists(st.from_regex(r"[!-~]{1,12}", fullmatch=True), max_size=8))
def test_ordinary_one_line_text_is_kept_as_it_is(words: list[str]) -> None:
    text = " ".join(words)
    assert clean_text(text, limit=len(text)) == text


@given(st.lists(LABEL, max_size=4), st.lists(LABEL, min_size=1, max_size=3))
def test_what_stands_in_front_of_the_root_never_changes_the_label_judged(
    front: list[str], root_labels: list[str]
) -> None:
    root = ".".join(root_labels)
    fqdn = ".".join([*front, root])
    features = lexical_features(fqdn, root)
    assert features == lexical_features(root, root).model_copy(
        update={"subdomain_depth": len(front), "subdomain_length": len(".".join(front))}
    )
    assert features.label == root_labels[0]
    assert features.label_length == len(features.label)
    assert 0.0 <= features.digit_ratio <= 1.0
    assert math.isfinite(features.randomness)
    assert features.subdomain_depth == len(front)
    assert features.subdomain_length == len(".".join(front))


@given(st.lists(LABEL, max_size=4), st.lists(LABEL, min_size=1, max_size=3))
def test_candidates_run_from_the_name_to_its_root_one_label_at_a_time(
    front: list[str], root_labels: list[str]
) -> None:
    root = ".".join(root_labels)
    fqdn = ".".join([*front, root])
    found = candidates(fqdn, root)
    assert found[0] == fqdn
    assert found[-1] == root
    assert all(name == root or name.endswith("." + root) for name in found)
    sizes = [name.count(".") for name in found]
    assert sizes == list(range(sizes[0], sizes[0] - len(found), -1))


@given(NAME)
def test_without_a_root_candidates_stop_at_two_labels(fqdn: str) -> None:
    found = candidates(fqdn, None)
    assert found[0] == fqdn
    assert found[-1].count(".") == min(1, fqdn.count("."))


@given(SUFFIXED_NAME)
def test_the_registered_domain_is_a_suffix_of_the_name_and_its_own(name: str) -> None:
    registered = RULES.registered(name)
    if registered is None:
        return
    assert name == registered or name.endswith("." + registered)
    assert RULES.registered(registered) == registered


@given(SUFFIXED_NAME)
def test_case_and_a_trailing_dot_do_not_change_the_suffix_answers(name: str) -> None:
    shouted = name.upper() + "."
    assert RULES.registered(shouted) == RULES.registered(name)
    assert RULES.platform_suffix(shouted) == RULES.platform_suffix(name)
    assert RULES.under_private_rule(shouted) == RULES.under_private_rule(name)


@given(SUFFIXED_NAME)
def test_a_platform_suffix_is_a_private_rule_the_name_sits_under(name: str) -> None:
    suffix = RULES.platform_suffix(name)
    if suffix is None:
        return
    assert name.endswith("." + suffix)
    assert RULES.under_private_rule(name)


@given(st.sampled_from(list(Severity)))
def test_the_prefilter_raises_one_step_and_never_lowers(severity: Severity) -> None:
    assert prefilter.raised(severity).rank == min(severity.rank + 1, Severity.CRITICAL.rank)


def _finding(fqdn: str, severity: Severity, device: str | None) -> Finding:
    evidence: dict[str, object] = {"fqdn": fqdn}
    if device is not None:
        evidence["device_name"] = device
    return Finding(
        rule_id="dga-like",
        severity=severity,
        profile_id="abc123",
        subject="D1",
        device_mode=True,
        target=fqdn,
        ts=datetime(2026, 11, 1, tzinfo=UTC),
        dedupe_key="k",
        evidence=evidence,
        event_id="e1",
    )


@given(NAME, st.sampled_from(list(Severity)), st.none() | st.text(max_size=30))
def test_the_prefilter_only_adds_to_a_finding(
    fqdn: str, severity: Severity, device: str | None
) -> None:
    finding = _finding(fqdn, severity, device)
    result = prefilter.apply(finding)
    assert result.severity.rank >= finding.severity.rank
    kept = {key: result.evidence[key] for key in finding.evidence}
    assert kept == finding.evidence
    if result is not finding:
        assert result.evidence[prefilter.EVIDENCE_KEY]
        assert result.severity == prefilter.raised(finding.severity)


@given(st.sampled_from(sorted(prefilter.ANYWHERE)), LABEL, LABEL)
def test_a_distinctive_word_is_caught_anywhere_in_a_label(
    word: str, before: str, after: str
) -> None:
    assert word in prefilter.instruction_tokens([f"{before}{word}{after}.example"])
    assert word in prefilter.instruction_tokens([f"{before}{word.upper()}{after}.example"])


@given(
    st.sampled_from(sorted(prefilter.WHOLE_WORDS)), st.from_regex(r"[a-z]{1,10}", fullmatch=True)
)
def test_a_common_word_counts_only_on_its_own(word: str, other: str) -> None:
    assert word in prefilter.instruction_tokens([f"{other}-{word}-1.example"])
    assert word not in prefilter.instruction_tokens([f"{other}{word}x.example"])
