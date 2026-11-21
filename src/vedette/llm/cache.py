"""Cache key for model verdicts.

A recurring finding (the same rule on the same target with the same kind of
evidence) should not be sent to the model again. The key is built from the
rule, the target and a hash of coarse features of the evidence: exact
subdomains are left out and numbers are bucketed, so "5 days old" and "6 days
old" share a key while "25 days old" does not.
"""

import hashlib
import json
import math
from typing import Any

from vedette.llm.prompts import PROMPT_VERSION
from vedette.storage.store import StoredFinding

# Evidence that names one specific query rather than describing the finding.
_INSTANCE_FIELDS = frozenset({"fqdn", "sample_fqdn", "label"})


def _feature(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return 0 if value <= 0 else math.floor(math.log2(value)) + 1
    if isinstance(value, (list, tuple)):
        return sorted(str(item) for item in value)
    return str(value)


def cache_key(finding: StoredFinding, model: str) -> str:
    """Key under which the verdict for a finding like this one is cached."""
    features = {
        key: _feature(value)
        for key, value in sorted(finding.evidence.items())
        if key not in _INSTANCE_FIELDS
    }
    material = json.dumps(
        [PROMPT_VERSION, model, finding.rule_id, finding.target, finding.device_mode, features],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
