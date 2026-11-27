"""Guards applied in code after the model answers. No prompt can switch them off."""

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from vedette.shared.defang import clean_text, defang_text
from vedette.shared.models import Assessment, Severity

_TAG = re.compile(r"<[^>]*>")
_MARKDOWN_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_MARKDOWN_MARKS = re.compile(r"[*`#~|]|^\s*>+", re.MULTILINE)
_NOT_SLUG = re.compile(r"[^a-z0-9]+")
_NOT_LETTERS = re.compile(r"[^a-z]+")
#: A domain-like name: dot-separated labels ending in a 2 to 24 letter suffix.
_NAME = re.compile(
    r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.IGNORECASE
)
#: File extensions that look like a top-level domain but are not one, so
#: ``svchost.exe`` or ``config.json`` in an answer is not taken for a domain.
_FILE_ENDINGS = frozenset(
    (
        "exe", "dll", "sys", "bat", "msi", "tmp", "ini", "log", "txt", "cfg", "conf", "dat",
        "json", "yaml", "yml", "xml", "html", "htm", "php", "js", "css", "jpg", "jpeg", "png",
        "gif", "pdf", "doc", "docx", "xls", "xlsx", "csv", "plist", "apk", "dmg", "deb", "rpm",
        "iso", "img", "dylib", "jar", "vbs", "ps", "lnk", "db", "bak",
    )
)  # fmt: skip
#: What stands in the text for a domain name the model was not given.
REMOVED_NAME = "[a name not in the records]"
#: Fields that hold the owner's records or a domain's standing: what can show
#: that activity is harmless. Names and identifiers (the device name, the
#: queried name, the client address) are not among them.
RECORD_FIELDS = frozenset(
    (
        "popularity_rank",
        "domain_age_days",
        "usual_queries_an_hour",
        "queries_that_hour",
        "first_seen_days_before",
        "top_sites",
        "registered_days_before",
        "threat_feeds",
        "devices_that_looked_it_up",
        "first_looked_up_days_before",
        "customer_name_on_hosting_platform",
        "lookups_within_5_minutes",
        "other_findings_within_an_hour",
        "earlier_findings_same_rule_and_target",
        "rule_findings_last_30_days_other_targets",
    )
)

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


def grounded_leaning(assessment: Assessment | None, cited: Iterable[str]) -> Assessment | None:
    """The answer's leaning, with a harmless one that cites no record made unclear.

    A harmless leaning has to rest on the records (how long and by how many
    devices a domain has been used, what was looked up around it, how the owner
    handled findings like it). One that cites only names and identifiers rests
    on what a name says about itself, which an attacker chooses.
    """
    if assessment == "harmless" and RECORD_FIELDS.isdisjoint(cited):
        return "unclear"
    return assessment


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


def _readable(text: str) -> str:
    """Text with defanged dots and schemes put back, so names can be found."""
    return text.replace("[.]", ".").replace("hxxp", "http")


def _given_names(known: str) -> set[str]:
    """Every domain-like name in what the model was given, and each parent domain of one."""
    names: set[str] = set()
    for match in _NAME.finditer(_readable(known).lower()):
        labels = match.group(1).split(".")
        names.update(".".join(labels[index:]) for index in range(len(labels) - 1))
    return names


def unsupported_names(texts: Iterable[str], known: str) -> list[str]:
    """Domain names in the answer that are not in ``known``, what the model was given.

    A name counts as given when it, or a name below it, appears in the data:
    ``example.com`` is given by ``login.example.com``. A name with a file
    ending (``svchost.exe``) is not a domain and is left alone.
    """
    given = _given_names(known)
    found: list[str] = []
    for text in texts:
        for match in _NAME.finditer(_readable(text)):
            name = match.group(1).lower()
            if name.rsplit(".", 1)[-1] in _FILE_ENDINGS or name in given or name in found:
                continue
            found.append(name)
    return found


def remove_names(text: str, names: Sequence[str]) -> str:
    """``text`` with each of ``names`` replaced by :data:`REMOVED_NAME`."""
    if not names:
        return text
    wanted = {name.lower() for name in names}

    def swap(match: re.Match[str]) -> str:
        return REMOVED_NAME if match.group(1).lower() in wanted else match.group(0)

    return _NAME.sub(swap, _readable(text))


def payload_keys(item: Mapping[str, Any]) -> frozenset[str]:
    """Every field name in one finding as the model was given it, at any depth."""
    keys: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, inner in value.items():
                keys.add(str(key))
                walk(inner)
        elif isinstance(value, (list, tuple)):
            for inner in value:
                walk(inner)

    walk(item)
    return frozenset(keys)


def cited_keys(cited: Iterable[str], allowed: frozenset[str], *, limit: int) -> tuple[str, ...]:
    """The field names an answer cites that the finding really has, in order, without repeats.

    A cited name may be written as a path (``context.domain.top_sites``); its
    last part is what is checked.
    """
    kept: list[str] = []
    for name in cited:
        key = str(name).strip().rsplit(".", 1)[-1]
        if key in allowed and key not in kept:
            kept.append(key)
    return tuple(kept[:limit])


def sanitize_list(items: Iterable[str], *, items_limit: int, limit: int) -> tuple[str, ...]:
    """Sanitise each item of a model-written list; drop empty and repeated ones; cap the count."""
    kept: list[str] = []
    for item in items:
        text = sanitize_model_text(str(item), limit=limit)
        if text and text not in kept:
            kept.append(text)
    return tuple(kept[:items_limit])
