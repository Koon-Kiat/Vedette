"""The answer shape the model is held to, and the parser that enforces it.

The model's answer must parse into :class:`~vedette.shared.models.Verdict`
objects or it is rejected. Nothing else from the model (free text, extra
fields, tool calls) is used.
"""

import json
from typing import Any

from vedette.shared.models import ASSESSMENTS, Severity, Verdict

_LIST: dict[str, Any] = {"type": "array", "items": {"type": "string"}}

# The verdict's fields in the order the model writes them. The cause and the
# step come first, as they did before the lists were added: asked for harmless
# explanations first, qwen3:8b took a device name's claim about itself as one
# and then as the cause. The leaning, both sides and the checks follow.
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
        "assessment": {"type": "string", "enum": list(ASSESSMENTS)},
        "harmless_explanations": _LIST,
        "malicious_explanations": _LIST,
        "checks": _LIST,
        "evidence_used": _LIST,
    },
}
_VERDICT_SCHEMA["required"] = list(_VERDICT_SCHEMA["properties"])

# The shorter verdict asked for before prompt version 4. The undefended arm of
# the evaluation keeps it, so its numbers stay comparable from run to run.
_BASE_FIELDS = (
    "finding_id",
    "summary",
    "likely_cause",
    "recommended_action",
    "priority",
    "group_key",
    "confidence",
)
_BASE_VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {name: _VERDICT_SCHEMA["properties"][name] for name in _BASE_FIELDS},
    "required": list(_BASE_FIELDS),
}


def _response(verdict: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"verdicts": {"type": "array", "items": verdict}},
        "required": ["verdicts"],
    }


# Sent to Ollama in the ``format`` field so generation is constrained to it.
RESPONSE_SCHEMA: dict[str, Any] = _response(_VERDICT_SCHEMA)
BASE_RESPONSE_SCHEMA: dict[str, Any] = _response(_BASE_VERDICT_SCHEMA)


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
