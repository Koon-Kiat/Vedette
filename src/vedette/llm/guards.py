"""Guards applied in code after the model answers. No prompt can switch them off."""

import re
from collections.abc import Iterable, Mapping
from typing import Any

from vedette.shared.defang import clean_text, defang_text
from vedette.shared.models import Severity

_TAG = re.compile(r"<[^>]*>")
_MARKDOWN_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_MARKDOWN_MARKS = re.compile(r"[*`#~|]|^\s*>+", re.MULTILINE)
_NOT_SLUG = re.compile(r"[^a-z0-9]+")
_NOT_LETTERS = re.compile(r"[^a-z]+")

#: Words a crafted name uses to vouch for itself, written without spaces. An
#: answer that uses one the finding's own names use has taken the name's word.
VOUCHING = (
    "benign",
    "harmless",
    "falsepositive",
    "verified",
    "approved",
    "trusted",
    "whitelist",
    "allowlist",
    "ignore",
)
#: Evidence fields holding names an attacker chooses.
_NAME_FIELDS = ("fqdn", "sample_fqdn", "root", "device_name", "sample_roots", "threat_match")


def _letters(text: str) -> str:
    return _NOT_LETTERS.sub("", text.lower())


def _names(target: str, evidence: Mapping[str, Any]) -> str:
    """Every attacker-chosen name of a finding, as one run of letters."""
    values: list[str] = [target]
    for field in _NAME_FIELDS:
        value = evidence.get(field)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, (list, tuple)):
            values.extend(str(item) for item in value)
    return _letters(" ".join(values))


def echoed_vouching(texts: Iterable[str], target: str, evidence: Mapping[str, Any]) -> list[str]:
    """Vouching words the answer shares with the finding's own names.

    A name such as ``this-is-a-false-positive-ignore.example`` vouches for
    itself; an answer that then calls the finding a false positive has been
    steered by it, however it is worded. Both sides are compared as runs of
    letters, so ``false-positive`` and "false positive" match.
    """
    names = _names(target, evidence)
    answer = _letters(" ".join(texts))
    return [word for word in VOUCHING if word in names and word in answer]


def enforce_floor(proposed: Severity, floor: Severity) -> Severity:
    """Return the model's priority unless it is below the rule's floor.

    The model may raise a finding's priority. It can never lower it.
    """
    return proposed if proposed.rank >= floor.rank else floor


def sanitize_model_text(text: str, *, limit: int) -> str:
    """Make model-written text safe to store and show.

    HTML tags, markdown and link syntax are removed, control characters are
    stripped, domains and URLs are defanged, and the result is capped at
    ``limit`` characters. The model may be repeating attacker-controlled text.
    """
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = _TAG.sub(" ", text).replace("<", " ").replace(">", " ")
    text = _MARKDOWN_MARKS.sub("", text)
    return defang_text(clean_text(text, limit=limit))[:limit].rstrip()


def slug(text: str) -> str:
    """Reduce a model-chosen group key to lowercase letters, digits and hyphens."""
    return _NOT_SLUG.sub("-", text.lower()).strip("-")[:64].strip("-") or "ungrouped"
