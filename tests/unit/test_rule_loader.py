from pathlib import Path

import pytest

from vedette.rules.loader import RuleFileError, load_rules
from vedette.shared.models import Severity


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def by_id(path: Path | None = None) -> dict[str, object]:
    return {spec.id: spec for spec in load_rules(path)}


def test_override_file_changes_only_the_named_values(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "rules:\n"
        "  - id: young-domain\n"
        "    params:\n"
        "      max_age_days: 14\n"
        "  - id: tunnel-like\n"
        "    severity: critical\n"
        "    params:\n"
        "      window_minutes: 5\n",
    )
    defaults = {spec.id: spec for spec in load_rules()}

    rules = {spec.id: spec for spec in load_rules(path)}

    assert rules["young-domain"].params["max_age_days"] == 14
    assert rules["young-domain"].severity is Severity.HIGH
    assert rules["young-domain"].description == defaults["young-domain"].description
    assert rules["tunnel-like"].severity is Severity.CRITICAL
    assert rules["tunnel-like"].params["window_minutes"] == 5
    assert rules["tunnel-like"].params["min_unique_subdomains"] == 30
    assert rules["dga-like"] == defaults["dga-like"]


def test_a_rule_can_be_disabled_in_the_override_file(tmp_path: Path) -> None:
    path = write(tmp_path, "rules:\n  - id: volume-spike\n    enabled: false\n")

    rules = {spec.id: spec for spec in load_rules(path)}

    assert rules["volume-spike"].enabled is False
    assert rules["blocked-burst"].enabled is True


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("rules:\n  - id: no-such-rule\n    severity: low\n", "unknown rule id"),
        ("rules: [unclosed\n", "not valid YAML"),
        ("- just\n- a list\n", "'rules' list"),
        ("rules:\n  - not-a-mapping\n", "'rules' list"),
        ("rules:\n  - id: young-domain\n    severity: scary\n", "young-domain: severity"),
        ("rules:\n  - id: young-domain\n    surprise: 1\n", "young-domain: surprise"),
        (
            "rules:\n  - id: young-domain\n    params:\n      max_age_days: soon\n",
            "'max_age_days' is missing or not a number",
        ),
        (
            "rules:\n  - id: dga-like\n    params:\n      min_randomness: true\n",
            "'min_randomness' is missing or not a number",
        ),
        (
            "rules:\n  - id: dga-like\n    params:\n      min_entropy: 3.2\n",
            "'min_entropy' is no longer used; it was replaced by min_randomness",
        ),
        (
            "rules:\n  - id: dga-burst\n    params:\n      assigned_name_platforms: cdn.example\n",
            "'assigned_name_platforms' must be a list of lower-case domain names",
        ),
        (
            "rules:\n  - id: dga-like\n    params:\n"
            "      assigned_name_platforms: [.CDN.example]\n",
            "'assigned_name_platforms' must be a list of lower-case domain names",
        ),
    ],
)
def test_a_bad_override_file_is_rejected_with_a_clear_reason(
    tmp_path: Path, text: str, message: str
) -> None:
    with pytest.raises(RuleFileError) as excinfo:
        load_rules(write(tmp_path, text))

    assert message in str(excinfo.value)


def test_a_missing_override_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(RuleFileError, match="cannot read rule file"):
        load_rules(tmp_path / "absent.yaml")


def test_packaged_rules_load_without_an_override() -> None:
    assert len(by_id()) == 10


def test_the_assigned_name_platforms_can_be_replaced_in_the_override_file(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "rules:\n  - id: dga-like\n    params:\n      assigned_name_platforms: [cdn.example]\n",
    )

    rules = {spec.id: spec for spec in load_rules(path)}

    assert rules["dga-like"].params["assigned_name_platforms"] == ["cdn.example"]
    assert "cloudfront.net" in rules["dga-burst"].params["assigned_name_platforms"]


def test_both_name_rules_skip_the_same_platforms_by_default() -> None:
    rules = {spec.id: spec for spec in load_rules()}

    platforms = rules["dga-like"].params["assigned_name_platforms"]
    assert platforms == rules["dga-burst"].params["assigned_name_platforms"]
    assert {"cloudfront.net", "amazonaws.com", "googleapis.com"} <= set(platforms)
    assert not {"github.io", "duckdns.org", "ddns.net", "pages.dev"} & set(platforms)
