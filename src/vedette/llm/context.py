"""The context pack: the records around each finding, as capped JSON data for the model.

The model used to get little more than the rule's own description, so it
mostly reworded what the template already said. The pack adds what the
owner's records hold: the device's age and usual volume, the domain's rank
band, age, feeds and spread, what else the device looked up and raised around
the same time, and how the owner handled earlier findings like it.

Names in the pack come from DNS traffic and devices, so they are untrusted
like every other value in the payload. Any that holds instruction-like words
is withheld rather than sent; every part is capped in count and length; and
all times are given in days before the finding, so a pack depends only on the
records, not on when it was built.
"""

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol

from vedette.rules import prefilter
from vedette.storage.context import ContextStore, DeviceFacts, DomainFacts, FindingFacts
from vedette.storage.store import StoredFinding

WITHHELD = "(withheld: instruction-like words)"
MAX_NAME = 100


class ContextSource(Protocol):
    """Anything that builds context packs for findings."""

    async def packs(self, found: Sequence[StoredFinding]) -> Mapping[int, dict[str, Any]]:
        """A context pack per finding id."""
        ...


def rank_band(rank: int | None) -> str:
    """A top-sites rank as a band: the exact rank says nothing more to the model."""
    if rank is None:
        return "not ranked"
    for limit in (1_000, 10_000, 100_000):
        if rank <= limit:
            return f"top {limit:,}"
    return "top 1,000,000"


def _days(since: datetime | None, until: datetime) -> int | None:
    return None if since is None else max((until - since).days, 0)


def _name(name: str) -> str:
    """A looked-up name as sent: withheld if it reads like an instruction, else capped."""
    return WITHHELD if prefilter.instruction_tokens([name]) else name[:MAX_NAME]


def _device_name(name: str | None) -> str | None:
    if name is None:
        return None
    return WITHHELD if prefilter.device_tokens([name]) else name[:MAX_NAME]


def _device(facts: DeviceFacts, finding: StoredFinding) -> dict[str, Any]:
    part: dict[str, Any] = {
        "usual_queries_an_hour": (
            None if facts.usual_per_hour is None else round(facts.usual_per_hour, 1)
        ),
        "queries_that_hour": facts.that_hour,
    }
    if finding.device_mode:
        part["first_seen_days_before"] = _days(facts.first_seen, finding.first_ts)
        part["device_name_self_reported"] = _device_name(facts.name)
    else:
        part["scope"] = "whole profile: NextDNS reports no devices here"
    return part


def _domain(
    facts: DomainFacts, finding: StoredFinding, is_platform: Callable[[str], bool] | None
) -> dict[str, Any]:
    root = finding.target
    part: dict[str, Any] = {
        "top_sites": rank_band(facts.rank),
        "registered_days_before": _days(facts.registered_at, finding.first_ts),
        "threat_feeds": list(facts.feeds[:5]),
        "top_level_domain": root.rsplit(".", 1)[-1][:24],
        "devices_that_looked_it_up": facts.devices,
        "first_looked_up_days_before": _days(facts.first_seen, finding.first_ts),
    }
    if is_platform is not None:
        part["customer_name_on_hosting_platform"] = is_platform(root)
    return part


def build_pack(
    facts: FindingFacts,
    finding: StoredFinding,
    is_platform: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """One finding's context pack, from its records."""
    pack: dict[str, Any] = {"device": _device(facts.device, finding)}
    if facts.domain is not None:
        pack["domain"] = _domain(facts.domain, finding, is_platform)
    pack["lookups_within_5_minutes"] = [_name(name) for name in facts.nearby]
    pack["other_findings_within_an_hour"] = [
        {"rule_id": rule, "target": _name(target), "status": status}
        for rule, target, status in facts.beside
    ]
    pack["earlier_findings_same_rule_and_target"] = dict(sorted(facts.earlier.items()))
    pack["rule_findings_last_30_days_other_targets"] = dict(sorted(facts.rule_month.items()))
    return pack


class ContextPacker:
    """Builds context packs from the owner's records."""

    def __init__(
        self, store: ContextStore, *, is_platform: Callable[[str], bool] | None = None
    ) -> None:
        """Read records from ``store``.

        Args:
            store: Where the records are read.
            is_platform: Tells a customer name on a hosting platform from a
                registered domain; without it the pack leaves that out.
        """
        self._store = store
        self._is_platform = is_platform

    async def packs(self, found: Sequence[StoredFinding]) -> dict[int, dict[str, Any]]:
        """A context pack per finding id."""
        facts = await self._store.facts(found)
        return {
            finding.id: build_pack(facts[finding.id], finding, self._is_platform)
            for finding in found
        }
