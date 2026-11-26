"""What a domain name says about itself, worked out without any lookup.

Lexical features are cheap signals for machine-generated names; candidates are
the names a feed match is looked up under.
"""

from pydantic import BaseModel, ConfigDict

from vedette.shared import label_model


class LexicalFeatures(BaseModel):
    """Features of a queried name, computed without any lookup.

    Attributes:
        label: The registered label: the one directly left of the public
            suffix, chosen by whoever registered the domain or, for a customer
            name on a hosting platform, by the customer. Subdomains in front
            of it are left to the tunnel rules.
        label_length: Length of ``label``.
        randomness: Bits by which random characters explain ``label`` better
            than real domain labels do; see :mod:`vedette.shared.label_model`.
        digit_ratio: Share of digits in ``label``.
        subdomain_depth: Number of labels in front of the registrable root.
        subdomain_length: Characters in front of the root, dots included.
    """

    model_config = ConfigDict(frozen=True)

    label: str
    label_length: int
    randomness: float
    digit_ratio: float
    subdomain_depth: int
    subdomain_length: int


def _under(fqdn: str, root: str | None) -> bool:
    """Whether ``root`` is ``fqdn`` itself or one of its parents."""
    return bool(root) and (fqdn == root or fqdn.endswith(f".{root}"))


def _subdomain(fqdn: str, root: str | None) -> str:
    """The part of ``fqdn`` in front of its root, without the joining dot."""
    if root and _under(fqdn, root):
        return fqdn[: -len(root) - 1] if fqdn != root else ""
    labels = fqdn.split(".")
    return ".".join(labels[:-2]) if len(labels) > 2 else ""


def registered_label(fqdn: str, root: str | None) -> str:
    """The label left of the public suffix: the first label of the root.

    NextDNS reports a customer name on a hosting platform (``foo.github.io``)
    as a root of its own, so its first label is the one the customer chose.
    Without a root, or with one that ``fqdn`` is not under, the second-to-last
    label stands in.
    """
    if root and _under(fqdn, root):
        return root.split(".", 1)[0]
    labels = fqdn.split(".")
    return labels[-2] if len(labels) > 1 else labels[0]


def lexical_features(fqdn: str, root: str | None) -> LexicalFeatures:
    """Compute lexical features for a queried name.

    Args:
        fqdn: The full queried name, lower case, without a trailing dot.
        root: Its registrable root if known. Without one, the last two labels
            are assumed to be the root.
    """
    label = registered_label(fqdn, root)
    subdomain = _subdomain(fqdn, root)
    return LexicalFeatures(
        label=label,
        label_length=len(label),
        randomness=label_model.packaged().randomness(label),
        digit_ratio=(sum(ch.isdigit() for ch in label) / len(label)) if label else 0.0,
        subdomain_depth=subdomain.count(".") + 1 if subdomain else 0,
        subdomain_length=len(subdomain),
    )


def candidates(fqdn: str, root: str | None) -> list[str]:
    """The name and each parent domain down to its root, most specific first."""
    labels = fqdn.split(".")
    shortest = root.count(".") + 1 if root and _under(fqdn, root) else 2
    shortest = min(shortest, len(labels))
    return [".".join(labels[start:]) for start in range(len(labels) - shortest + 1)]
