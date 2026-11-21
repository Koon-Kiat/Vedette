"""Guards applied in code after the model answers. No prompt can switch them off."""

import re

from vedette.notify.defang import clean_text, defang_text
from vedette.rules.model import Severity

_TAG = re.compile(r"<[^>]*>")
_MARKDOWN_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_MARKDOWN_MARKS = re.compile(r"[*`#~|]|^\s*>+", re.MULTILINE)
_NOT_SLUG = re.compile(r"[^a-z0-9]+")


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
