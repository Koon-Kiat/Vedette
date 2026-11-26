"""The records that pass between the stages: findings, explanations and messages."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

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


class Verdict(BaseModel):
    """What the model says about one finding, before any guard is applied."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: int
    summary: str = Field(min_length=1)
    likely_cause: str
    recommended_action: str = Field(min_length=1)
    priority: Severity
    group_key: str
    confidence: float = Field(ge=0.0, le=1.0)


class Analysis(BaseModel):
    """The stored explanation of a finding, after every guard has been applied.

    Attributes:
        finding_id: The finding this explains.
        summary: One or two plain sentences on what happened.
        likely_cause: The most probable explanation.
        recommended_action: What the owner should do.
        priority: Never below the rule's severity floor.
        group_key: Findings with the same key belong together in a digest.
        confidence: The model's stated confidence, 0 to 1 (0 for templates).
        source: ``llm``, ``cache`` (an earlier model answer) or ``template``
            (the model was not used or its answer was unusable).
        model: Model that wrote the text, if any.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: int
    summary: str = Field(min_length=1, max_length=400)
    likely_cause: str = Field(max_length=300)
    recommended_action: str = Field(min_length=1, max_length=300)
    priority: Severity
    group_key: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    source: Literal["llm", "cache", "template"]
    model: str | None = None


class AllowlistEntry(BaseModel):
    """One allowlisted root, optionally limited to a profile or a device.

    Attributes:
        root: Domain to allow; its subdomains are allowed too.
        profile: Profile id or label the entry applies to; all profiles if unset.
        device: Device id the entry applies to; all devices if unset.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    root: str = Field(min_length=1)
    profile: str | None = None
    device: str | None = None

    @field_validator("root")
    @classmethod
    def _normalise(cls, value: str) -> str:
        return value.strip().lower().strip(".")


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    """A notification ready to send: plain text, already made safe."""

    title: str
    body: str
    priority: Severity
    tags: tuple[str, ...] = ()
