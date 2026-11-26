"""Loads and validates the declarative rule file."""

from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from vedette.rules.model import RuleSpec

# Parameters each detector requires, with the type it must have.
REQUIRED_PARAMS: dict[str, dict[str, type | tuple[type, ...]]] = {
    "new-device": {},
    "young-domain": {"max_age_days": int},
    "threat-intel-allowed": {"trusted_rank": int},
    "dga-like": {"min_randomness": (int, float), "min_label_length": int},
    "tunnel-like": {
        "min_unique_subdomains": int,
        "window_minutes": int,
        "min_subdomain_length": int,
    },
    "tunnel-slow": {
        "min_unique_subdomains": int,
        "window_minutes": int,
        "min_subdomain_length": int,
    },
    "dga-burst": {"min_new_roots": int, "window_minutes": int},
    "volume-spike": {
        "factor": (int, float),
        "baseline_hours": int,
        "min_baseline_hours": int,
        "min_queries": int,
    },
    "blocked-burst": {
        "min_blocked": int,
        "min_blocked_profile_mode": int,
        "window_minutes": int,
    },
    "new-destination-category": {},
}

#: Optional parameters that hold a list of domain names.
NAME_LIST_PARAMS: dict[str, tuple[str, ...]] = {
    "dga-like": ("assigned_name_platforms",),
    "dga-burst": ("assigned_name_platforms",),
}

#: Parameters a rule no longer reads, with what replaced them.
RETIRED_PARAMS: dict[tuple[str, str], str] = {
    ("dga-like", "min_entropy"): (
        "min_randomness, in bits for the whole label rather than per character (see the "
        "packaged rules.yaml)"
    ),
}


class RuleFileError(Exception):
    """The rule file is missing, malformed or inconsistent."""


def _read(text: str, origin: str) -> list[dict[str, Any]]:
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleFileError(f"{origin}: not valid YAML ({type(exc).__name__})") from exc
    rules = loaded.get("rules") if isinstance(loaded, dict) else None
    if not isinstance(rules, list) or not all(isinstance(item, dict) for item in rules):
        raise RuleFileError(f"{origin}: expected a top-level 'rules' list of mappings")
    return rules


def _check_params(spec: RuleSpec) -> None:
    for name, expected in REQUIRED_PARAMS[spec.id].items():
        value = spec.params.get(name)
        if isinstance(value, bool) or not isinstance(value, expected):
            raise RuleFileError(f"rule {spec.id}: parameter {name!r} is missing or not a number")
    for name in NAME_LIST_PARAMS.get(spec.id, ()):
        value = spec.params.get(name, [])
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item and item == item.strip(" .").lower() for item in value
        ):
            raise RuleFileError(
                f"rule {spec.id}: parameter {name!r} must be a list of lower-case domain names"
            )
    for (rule_id, name), replacement in RETIRED_PARAMS.items():
        if spec.id == rule_id and name in spec.params:
            raise RuleFileError(
                f"rule {spec.id}: parameter {name!r} is no longer used; it was replaced by "
                f"{replacement}"
            )


def load_rules(override_file: Path | None = None) -> list[RuleSpec]:
    """Load the packaged rules, optionally overlaid with a user file.

    The override file has the same shape but may give only the fields to
    change per rule id; ``params`` are merged key by key.

    Raises:
        RuleFileError: A file is unreadable, names an unknown rule, or leaves
            a rule without a parameter its detector needs.
    """
    packaged = resources.files("vedette.rules").joinpath("rules.yaml").read_text(encoding="utf-8")
    merged: dict[str, dict[str, Any]] = {}
    for item in _read(packaged, "packaged rules"):
        merged[str(item.get("id"))] = dict(item)

    if override_file is not None:
        try:
            text = override_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleFileError(f"cannot read rule file {override_file}") from exc
        for item in _read(text, str(override_file)):
            rule_id = str(item.get("id"))
            if rule_id not in merged:
                raise RuleFileError(f"{override_file}: unknown rule id {rule_id!r}")
            base = merged[rule_id]
            params = {**base.get("params", {}), **(item.get("params") or {})}
            merged[rule_id] = {**base, **item, "params": params}

    specs: list[RuleSpec] = []
    for rule_id, item in merged.items():
        if rule_id not in REQUIRED_PARAMS:
            raise RuleFileError(f"unknown rule id {rule_id!r}")
        try:
            spec = RuleSpec.model_validate(item)
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors(include_input=False, include_url=False)
            )
            raise RuleFileError(f"rule {rule_id}: {problems}") from None
        _check_params(spec)
        specs.append(spec)
    missing = set(REQUIRED_PARAMS) - {spec.id for spec in specs}
    if missing:
        raise RuleFileError(f"rule file lacks: {', '.join(sorted(missing))}")
    return specs
