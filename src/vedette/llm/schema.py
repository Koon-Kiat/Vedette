"""The answer shape the model is held to, and the parser that enforces it.

The model's answer must parse into :class:`~vedette.shared.models.Verdict`
objects or it is rejected. Nothing else from the model (free text, extra
fields, tool calls) is used.
"""

import json
from typing import Any

from vedette.shared.models import Severity, Verdict

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
