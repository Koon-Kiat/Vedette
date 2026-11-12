"""The only shapes the LLM stage accepts and produces.

The model's answer must parse into :class:`Verdict` objects or it is rejected.
Nothing else from the model (free text, extra fields, tool calls) is used.
"""

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel.rules.model import Severity


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


_VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "integer"},
        "summary": {"type": "string"},
        "likely_cause": {"type": "string"},
        "recommended_action": {"type": "string"},
        "priority": {"type": "string", "enum": [level.value for level in Severity]},
        "group_key": {"type": "string"},
        "confidence": {"type": "number"},
    },
    "required": [
        "finding_id",
        "summary",
        "likely_cause",
        "recommended_action",
        "priority",
        "group_key",
        "confidence",
    ],
}

# Sent to Ollama in the ``format`` field so generation is constrained to it.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"verdicts": {"type": "array", "items": _VERDICT_SCHEMA}},
    "required": ["verdicts"],
}


def parse_verdicts(content: str) -> list[Verdict]:
    """Parse and validate the model's answer.

    Raises:
        ValueError: The answer is not JSON, not of the expected shape, or any
            verdict in it is invalid. The whole answer is then discarded.
    """
    try:
        body = json.loads(content)
    except ValueError:
        raise ValueError("model answer is not JSON") from None
    verdicts = body.get("verdicts") if isinstance(body, dict) else None
    if not isinstance(verdicts, list):
        raise ValueError("model answer has no 'verdicts' list")
    return [Verdict.model_validate(item) for item in verdicts]
