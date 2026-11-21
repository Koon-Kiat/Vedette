"""The Public Suffix List: which roots are customer names on a hosting platform.

NextDNS reports a customer's hostname on a platform such as ``github.io`` or a
cloud provider as a root of its own, because those platforms list themselves in
the private section of the Public Suffix List. Such a name is not a domain
anyone registered: it has no registration date, and a random-looking one says
nothing about malware. The list tells these names apart exactly. Until a copy
has been downloaded, the enricher falls back to calling a root a platform
customer when one of its parent domains is on the top-sites list.

The list is downloaded at most once per refresh period, stored in the database
and matched locally, so no query about an individual domain leaves the machine.
"""

import asyncio
from collections.abc import Iterable
from datetime import datetime, timedelta

import httpx
import structlog

from vedette.enrich.fetch import ReferenceFetchError, fetch_limited
from vedette.storage.reference import ReferenceStore

log = structlog.get_logger(__name__)

MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024
RETRY_AFTER_FAILURE = timedelta(hours=1)
_PRIVATE_BEGINS = "===BEGIN PRIVATE DOMAINS==="


def _ascii(rule: str) -> str | None:
    """A rule in the ASCII form DNS names arrive in, or ``None`` if it has none."""
    prefix = "!" if rule.startswith("!") else "*." if rule.startswith("*.") else ""
    try:
        name = rule.removeprefix(prefix).encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return prefix + name.lower()


def parse_public_suffix_list(text: str) -> list[tuple[str, bool]]:
    """Rules from the list's text, each with whether it is in the private section."""
    rules: list[tuple[str, bool]] = []
    private = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("//"):
            private = private or _PRIVATE_BEGINS in line
            continue
        if not line:
            continue
        rule = _ascii(line.split()[0])
        if rule is not None:
            rules.append((rule, private))
    return rules


class SuffixRules:
    """Matches names against parsed rules, following the list's own algorithm."""

    def __init__(self, rules: Iterable[tuple[str, bool]]) -> None:
        """Index the rules by kind."""
        self._exact: dict[str, bool] = {}
        self._wildcard: dict[str, bool] = {}
        self._exception: dict[str, bool] = {}
        for rule, private in rules:
            if rule.startswith("!"):
                self._exception[rule[1:]] = private
            elif rule.startswith("*."):
                self._wildcard[rule[2:]] = private
            else:
                self._exact[rule] = private

    def __len__(self) -> int:
        """Number of rules."""
        return len(self._exact) + len(self._wildcard) + len(self._exception)

    def _suffix(self, labels: list[str]) -> tuple[int, bool] | None:
        """How many labels the public suffix has, and whether its rule is private."""
        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            if candidate in self._exception:  # an exception beats every other rule
                return len(labels) - start - 1, self._exception[candidate]
        best: tuple[int, bool] | None = None
        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            size = len(labels) - start
            if candidate in self._exact:
                found = (size, self._exact[candidate])
            elif start > 0 and ".".join(labels[start:]) in self._wildcard:
                found = (size + 1, self._wildcard[candidate])
            else:
                continue
            if best is None or found[0] > best[0]:
                best = found
        return best

    def platform_suffix(self, name: str) -> str | None:
        """The private suffix ``name`` is a customer name under, else ``None``."""
        labels = [label for label in name.lower().rstrip(".").split(".") if label]
        found = self._suffix(labels)
        if found is None:
            return None
        size, private = found
        if not private or size >= len(labels):
            return None
        return ".".join(labels[len(labels) - size :])


class PublicSuffixList:
    """The downloaded list, kept in the database and in memory."""

    def __init__(
        self, reference: ReferenceStore, client: httpx.AsyncClient, *, url: str, refresh_days: int
    ) -> None:
        """Create the list.

        Args:
            reference: Where the list is stored.
            client: HTTP client used to download it.
            url: Location of ``public_suffix_list.dat``.
            refresh_days: Download a fresh copy after this many days.
        """
        self._reference = reference
        self._client = client
        self._url = url
        self._refresh = timedelta(days=refresh_days)
        self._rules = SuffixRules([])
        self._retry_at: datetime | None = None

    @property
    def known(self) -> bool:
        """Whether a list is loaded. If not, the enricher uses its fallback."""
        return len(self._rules) > 0

    async def load(self) -> None:
        """Read a previously downloaded list from the database."""
        self._rules = SuffixRules(await self._reference.public_suffix_rules())

    async def refresh_if_stale(self, now: datetime) -> bool:
        """Download a new list if the stored one is old; return whether it changed.

        A failed or empty download keeps the previous list and is retried an hour later.
        """
        if self._retry_at is not None and now < self._retry_at:
            return False
        last = await self._reference.refreshed_at("public_suffix")
        if last is not None and now - last < self._refresh:
            if not self.known:
                await self.load()
            return False
        try:
            data = await fetch_limited(self._client, self._url, max_bytes=MAX_DOWNLOAD_BYTES)
            rules = await asyncio.to_thread(
                parse_public_suffix_list, data.decode("utf-8", errors="replace")
            )
            if not rules:
                raise ReferenceFetchError("no rules")
        except ReferenceFetchError as exc:
            self._retry_at = now + RETRY_AFTER_FAILURE
            log.warning("public_suffix_refresh_failed", reason=str(exc))
            return False
        entries = await self._reference.replace_public_suffixes(rules, now)
        self._rules = SuffixRules(rules)
        self._retry_at = None
        log.info("public_suffix_refreshed", entries=entries)
        return True

    def platform_suffix(self, name: str) -> str | None:
        """The hosting platform's suffix ``name`` is a customer name under, else ``None``."""
        return self._rules.platform_suffix(name)
