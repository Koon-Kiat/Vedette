"""Template rendering: the Jinja environment and the filters the pages use.

Everything a filter returns from outside data is cleaned and defanged, and
autoescaping is on for every template.
"""

import functools
import hashlib
import importlib.resources
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import jinja2
from markupsafe import Markup, escape

from vedette.health.monitor import CATCHING_UP, OK, duration
from vedette.notify.defang import clean_text, defang_names
from vedette.notify.render import about_text, prose, safe
from vedette.storage.store import StoredFinding
from vedette.web.charts import span


def _local(moment: datetime | None, tz: ZoneInfo) -> str:
    return "never" if moment is None else f"{moment.astimezone(tz):%Y-%m-%d %H:%M}"


def _clock(moment: datetime | None, tz: ZoneInfo) -> str:
    return "" if moment is None else f"{moment.astimezone(tz):%H:%M}"


def _since(moment: datetime | None, now: datetime) -> str:
    if moment is None:
        return "no events yet"
    elapsed = now - moment
    if elapsed < timedelta(minutes=1):
        return "under a minute ago"
    return f"{duration(elapsed)} ago"


def _status_word(value: object) -> str:
    """NextDNS calls a query it let through "default"; the dashboard says "allowed"."""
    return "allowed" if value == "default" else safe(value, limit=40)


def _detail(value: object) -> str:
    """A message the pipeline wrote: names defanged, numbers left as numbers."""
    return defang_names(clean_text(str(value), limit=300))


#: Evidence fields in the order a finding's page lists them, in plain words.
EVIDENCE_LABELS = {
    "fqdn": "Name queried",
    "sample_fqdn": "Example name",
    "root": "Domain",
    "status": "NextDNS status",
    "domain_age_days": "Domain age, days",
    "popularity_rank": "Top-sites rank",
    "threat_feeds": "Threat feeds",
    "threat_match": "Matched on",
    "label": "Leftmost label",
    "label_length": "Label length",
    "entropy": "Entropy, bits per character",
    "digit_ratio": "Share of digits",
    "unique_subdomains": "Distinct subdomains",
    "blocked_in_window": "Blocked in the window",
    "window_minutes": "Window, minutes",
    "new_roots_in_window": "New unknown domains in the window",
    "sample_roots": "Examples",
    "queries_this_hour": "Queries this hour",
    "baseline_per_hour": "Usual queries per hour",
    "factor": "Times the usual",
    "category": "Category",
    "category_name": "Category name",
    "device_id": "Device",
    "device_name": "Device name",
    "client_ip": "Client address",
    "attribution": "Device attribution",
    "instruction_tokens": "Instruction-like words",
}


def _evidence_value(key: str, value: Any) -> str:
    if key == "status":
        return _status_word(value)
    if value is None:  # only the rank is kept when empty: no rank made the rule fire
        return "not ranked"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.2f}".rstrip("0").rstrip(".")
    return safe(value, limit=300)


#: Evidence fields whose values came from outside: names from DNS traffic, the
#: listed name a feed matched, device names, and NextDNS's reason ids and names.
#: The page sets them as outside names.
OUTSIDE_FIELDS = frozenset(
    {
        "fqdn",
        "sample_fqdn",
        "root",
        "label",
        "threat_match",
        "device_name",
        "category",
        "category_name",
        "sample_roots",
    }
)


def _evidence(evidence: Mapping[str, Any]) -> list[tuple[str, str, bool]]:
    """A finding's evidence as (label, value, from outside) rows.

    Every string is cleaned and defanged.
    """
    order = {key: index for index, key in enumerate(EVIDENCE_LABELS)}
    rows = []
    for key in sorted(evidence, key=lambda name: (order.get(name, len(order)), name)):
        value = evidence[key]
        if value is None and key != "popularity_rank":
            continue
        words = key.replace("_", " ")
        label = EVIDENCE_LABELS.get(key) or safe(words[:1].upper() + words[1:], limit=60)
        rows.append((label, _evidence_value(key, value), key in OUTSIDE_FIELDS))
    return rows


def _about(finding: StoredFinding) -> str:
    """What a finding is about, cleaned: a reason's name where NextDNS gave one, else its target."""
    return about_text(finding.rule_id, finding.target, finding.evidence, limit=255)


def _check_state(check: Any) -> tuple[str, str]:
    """A health check's state as (style, word).

    A passing check that is still working something out reads "Retrying" or
    "Catching up", not "OK".
    """
    if not check.ok:
        return "problem", "Problem"
    if check.detail == CATCHING_UP:
        return "watch", "Catching up"
    if check.key.startswith("api:") and check.detail != OK:
        return "watch", "Retrying"
    if check.key == "delivery" and check.detail.startswith("Retrying"):
        return "watch", "Retrying"
    return "ok", "OK"


def _average(value: float | None) -> str:
    """A daily or hourly average: tenths below 100, whole numbers above."""
    if value is None:
        return "n/a"
    if abs(value) >= 100:
        return f"{value:,.0f}"
    return f"{value:,.1f}".removesuffix(".0")


def _breakable(value: str) -> Markup:
    """An already-cleaned name that may wrap only after its defanged dots."""
    return Markup("[.]<wbr>").join(escape(part) for part in value.split("[.]"))


@functools.cache
def _version(path: str) -> str:
    """A short hash of one of our static files, for its URL (``?v=``).

    A changed file gets a new URL, so after an upgrade no browser can pair new
    pages with an old stylesheet or script from its cache. Vendored files carry
    their version in the file name instead.
    """
    content = (importlib.resources.files("vedette.web") / "static" / path).read_bytes()
    return hashlib.sha256(content).hexdigest()[:12]


TEMPLATE_ENV = jinja2.Environment(
    loader=jinja2.PackageLoader("vedette.web", "templates"),
    autoescape=True,
    undefined=jinja2.StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)
TEMPLATE_ENV.filters.update(
    {
        "domain": lambda value: safe(value, limit=255),
        "domain_wrap": lambda value: _breakable(safe(value, limit=255)),
        "about": _about,
        "check_state": _check_state,
        "text": lambda value: safe(value, limit=300),
        "prose": lambda value: prose(value, limit=600),
        "detail": _detail,
        "status_word": _status_word,
        "evidence": _evidence,
        "local": _local,
        "clock": _clock,
        "since": _since,
        "span": lambda finding, tz: span(finding.first_ts, finding.last_ts, tz),
        "ago": duration,
        "num": lambda value: f"{value:,}",
        "pct": lambda value: f"{value:.0%}",
        "secs": lambda value: f"{value / 1000:.1f} s",
        "avg": _average,
    }
)
TEMPLATE_ENV.globals["version"] = _version
