"""Rule definitions, as written in the rules file, and the buckets findings are deduplicated in."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from vedette.shared.models import Severity


class AnalystNotes(BaseModel):
    """What the local model should weigh for one rule, sent with its findings as trusted text.

    Attributes:
        look_alikes: Harmless activity that trips the rule, to rule out first.
        checks: Steps worth suggesting to the owner.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    look_alikes: list[str] = Field(min_length=1)
    checks: list[str] = Field(min_length=1)


class RuleSpec(BaseModel):
    """One declarative rule, as written in the rules YAML file.

    Attributes:
        id: Stable identifier; selects the detector that implements the rule.
        name: What the rule detects, in plain words; the dashboard titles its
            findings with it. The id stands in when it is not set.
        severity: Severity floor of every finding the rule produces.
        description: Why the rule matters, shown to the user.
        enabled: Disabled rules never fire.
        dedupe: How often the same subject and target may produce a new
            finding: ``once`` ever, or once per ``daily`` / ``hourly`` bucket.
        params: Thresholds for the detector.
        evidence: Names of the evidence fields the rule records.
        analyst_notes: Look-alikes and checks the local model is given for
            this rule's findings.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    name: str | None = Field(default=None, min_length=1)
    severity: Severity
    description: str = Field(min_length=1)
    enabled: bool = True
    dedupe: Literal["once", "daily", "hourly"]
    params: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(min_length=1)
    analyst_notes: AnalystNotes | None = None


def bucket(dedupe: str, ts: datetime) -> str:
    """The time bucket a finding falls into for de-duplication."""
    if dedupe == "daily":
        return ts.strftime("%Y-%m-%d")
    if dedupe == "hourly":
        return ts.strftime("%Y-%m-%dT%H")
    return ""
