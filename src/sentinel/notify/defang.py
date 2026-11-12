"""Makes attacker-controlled text safe to print or send.

Domain names, device names and reason strings come from DNS traffic an
attacker can influence. Before any of them is shown, domains are defanged so
no client turns them into a link, and control characters are removed so they
cannot rewrite a terminal or smuggle line breaks into a message.
"""

import re
import unicodedata

_SCHEME = re.compile(r"h(?:tt|xx)p(s?)://", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")


def _strip_control(text: str, *, keep_whitespace: bool) -> str:
    kept = []
    for ch in text:
        if keep_whitespace and ch.isspace():
            kept.append(" ")
        elif unicodedata.category(ch)[0] != "C" and ch.isprintable():
            kept.append(ch)
    return "".join(kept)


def defang(value: str) -> str:
    """Return a domain, IP address or URL in a form no client will auto-link.

    ``example.com`` becomes ``example[.]com`` and ``http://`` becomes
    ``hxxp://``. Applying it twice gives the same result as applying it once.
    """
    text = _strip_control(value, keep_whitespace=False)
    text = _SCHEME.sub(lambda match: f"hxxp{match.group(1).lower()}://", text)
    return text.replace("[.]", ".").replace(".", "[.]")


def clean_text(value: str, *, limit: int) -> str:
    """Return free text with control characters removed and length capped."""
    text = _strip_control(value, keep_whitespace=True)
    return _WHITESPACE.sub(" ", text).strip()[:limit]
