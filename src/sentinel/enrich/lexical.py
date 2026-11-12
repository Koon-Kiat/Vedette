"""Lexical features of a domain name: cheap signals for machine-generated names."""

import math
from collections import Counter

from pydantic import BaseModel, ConfigDict


class LexicalFeatures(BaseModel):
    """Features of a queried name, computed without any lookup.

    Attributes:
        label: The leftmost label of the name.
        entropy: Shannon entropy of ``label`` in bits per character.
        label_length: Length of ``label``.
        digit_ratio: Share of digits in ``label``.
        subdomain_depth: Number of labels in front of the registrable root.
        subdomain_length: Characters in front of the root, dots included.
    """

    model_config = ConfigDict(frozen=True)

    label: str
    entropy: float
    label_length: int
    digit_ratio: float
    subdomain_depth: int
    subdomain_length: int


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character (0.0 for an empty string)."""
    if not text:
        return 0.0
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in Counter(text).values())


def _subdomain(fqdn: str, root: str | None) -> str:
    """The part of ``fqdn`` in front of its root, without the joining dot."""
    if root and fqdn == root:
        return ""
    if root and fqdn.endswith("." + root):
        return fqdn[: -len(root) - 1]
    labels = fqdn.split(".")
    return ".".join(labels[:-2]) if len(labels) > 2 else ""


def lexical_features(fqdn: str, root: str | None) -> LexicalFeatures:
    """Compute lexical features for a queried name.

    Args:
        fqdn: The full queried name, lower case, without a trailing dot.
        root: Its registrable root if known. Without one, the last two labels
            are assumed to be the root.
    """
    label = fqdn.split(".", 1)[0]
    subdomain = _subdomain(fqdn, root)
    return LexicalFeatures(
        label=label,
        entropy=shannon_entropy(label),
        label_length=len(label),
        digit_ratio=(sum(ch.isdigit() for ch in label) / len(label)) if label else 0.0,
        subdomain_depth=subdomain.count(".") + 1 if subdomain else 0,
        subdomain_length=len(subdomain),
    )
