"""Rule definitions and the findings they produce."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Severity(StrEnum):
    """How urgent a finding is. Rules set a floor that nothing may lower."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Position in the ordering, 0 (info) to 4 (critical)."""
        return _RANK[self.value]


class RuleSpec(BaseModel):
    """One declarative rule, as written in the rules YAML file.

    Attributes:
        id: Stable identifier; selects the detector that implements the rule.
        severity: Severity floor of every finding the rule produces.
        description: Why the rule matters, shown to the user.
        enabled: Disabled rules never fire.
        dedupe: How often the same subject and target may produce a new
            finding: ``once`` ever, or once per ``daily`` / ``hourly`` bucket.
        params: Thresholds for the detector.
        evidence: Names of the evidence fields the rule records.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    severity: Severity
    description: str = Field(min_length=1)
    enabled: bool = True
    dedupe: Literal["once", "daily", "hourly"]
    params: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(min_length=1)


class Finding(BaseModel):
    """A rule firing on an event.

    Attributes:
        rule_id: The rule that fired.
        severity: The rule's severity floor.
        profile_id: Profile the event belongs to.
        subject: Device id, or ``None`` when NextDNS reported no device and the
            rule keyed on the profile instead.
        device_mode: ``True`` when ``subject`` is a real device.
        target: What the finding is about (a root domain, device, IP or category).
        ts: Time of the triggering event.
        dedupe_key: Findings with the same key are merged into one stored row.
        evidence: Structured facts supporting the finding. Untrusted strings.
        event_id: The triggering event.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    profile_id: str
    subject: str | None
    device_mode: bool
    target: str
    ts: AwareDatetime
    dedupe_key: str
    evidence: dict[str, Any]
    event_id: str


def bucket(dedupe: str, ts: datetime) -> str:
    """The time bucket a finding falls into for de-duplication."""
    if dedupe == "daily":
        return ts.strftime("%Y-%m-%d")
    if dedupe == "hourly":
        return ts.strftime("%Y-%m-%dT%H")
    return ""
