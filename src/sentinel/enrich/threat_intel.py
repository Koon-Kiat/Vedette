"""Matching against free threat-intelligence feeds.

Feeds are downloaded on a schedule, stored locally and matched locally. A name
matches when it, or one of its parent domains down to its registrable root, is
listed. A listed subdomain never taints its parent or siblings.

A feed is untrusted input too: entries are validated, size is capped, and a
refresh that fails or comes back empty keeps the previous entries.
"""

from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field

from sentinel.enrich.fetch import ReferenceFetchError, fetch_limited, is_domain
from sentinel.storage.reference import ReferenceStore

log = structlog.get_logger(__name__)

MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_ENTRIES = 3_000_000
RETRY_AFTER_FAILURE = timedelta(hours=1)
_CACHE_LIMIT = 200_000

type Match = tuple[tuple[str, ...], str]


class Feed(BaseModel):
    """One threat-intelligence feed.

    Attributes:
        name: Short name recorded in findings.
        url: Where to download it.
        format: ``domains`` (one per line), ``hosts`` (address then name) or
            ``urls`` (the host name is extracted).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")
    url: str = Field(min_length=1)
    format: Literal["domains", "hosts", "urls"] = "domains"


def parse_feed(text: str, fmt: str) -> Iterator[str]:
    """Yield the valid domain names in a feed, lower-cased, in file order."""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if fmt == "hosts":
            parts = line.split()
            candidate = parts[1] if len(parts) >= 2 else ""
        elif fmt == "urls":
            try:
                candidate = urlsplit(line).hostname or ""
            except ValueError:
                candidate = ""
        else:
            candidate = line
        candidate = candidate.lower().rstrip(".")
        if is_domain(candidate):
            yield candidate


def candidates(fqdn: str, root: str | None) -> list[str]:
    """The name and each parent domain down to its root, most specific first."""
    labels = fqdn.split(".")
    if root and (fqdn == root or fqdn.endswith("." + root)):
        shortest = root.count(".") + 1
    else:
        shortest = 2
    shortest = min(shortest, len(labels))
    return [".".join(labels[start:]) for start in range(len(labels) - shortest + 1)]


class ThreatIntel:
    """Local lookups against the configured threat feeds."""

    def __init__(
        self,
        reference: ReferenceStore,
        client: httpx.AsyncClient,
        *,
        feeds: Sequence[Feed],
        refresh_hours: int,
    ) -> None:
        """Create the matcher.

        Args:
            reference: Where feed entries are stored.
            client: HTTP client used to download feeds.
            feeds: Feeds to use.
            refresh_hours: Download each feed again after this many hours.
        """
        self._reference = reference
        self._client = client
        self._feeds = tuple(feeds)
        self._refresh = timedelta(hours=refresh_hours)
        self._retry_at: dict[str, datetime] = {}
        self._cache: dict[str, Match | None] = {}

    async def refresh_if_stale(self, now: datetime) -> bool:
        """Refresh every feed that is due; return whether any changed."""
        changed = False
        for feed in self._feeds:
            retry_at = self._retry_at.get(feed.name)
            if retry_at is not None and now < retry_at:
                continue
            last = await self._reference.refreshed_at(f"feed:{feed.name}")
            if last is not None and now - last < self._refresh:
                continue
            try:
                data = await fetch_limited(self._client, feed.url, max_bytes=MAX_DOWNLOAD_BYTES)
                names = list(
                    dict.fromkeys(parse_feed(data.decode("utf-8", "replace"), feed.format))
                )
                if not names:
                    raise ReferenceFetchError("no usable entries")
                if len(names) > MAX_ENTRIES:
                    raise ReferenceFetchError("more entries than the safety limit")
            except ReferenceFetchError as exc:
                self._retry_at[feed.name] = now + RETRY_AFTER_FAILURE
                log.warning("threat_feed_refresh_failed", feed=feed.name, reason=str(exc))
                continue
            entries = await self._reference.replace_feed(feed.name, names, now)
            self._retry_at.pop(feed.name, None)
            changed = True
            log.info("threat_feed_refreshed", feed=feed.name, entries=entries)
        if changed:
            self._cache.clear()
        return changed

    async def match_many(self, names: Iterable[tuple[str, str | None]]) -> dict[str, Match]:
        """Match many ``(fqdn, root)`` pairs; return only the names that are listed.

        Each value is ``(feeds, matched_domain)`` for the most specific listed
        domain.
        """
        pending: dict[str, list[str]] = {}
        wanted: list[str] = []
        for fqdn, root in names:
            wanted.append(fqdn)
            if fqdn not in self._cache and fqdn not in pending:
                pending[fqdn] = candidates(fqdn, root)
        if pending:
            if len(self._cache) > _CACHE_LIMIT:
                self._cache.clear()
            listed = await self._reference.threat_matches(
                {name for options in pending.values() for name in options}
            )
            for fqdn, options in pending.items():
                hit = next((name for name in options if name in listed), None)
                self._cache[fqdn] = (tuple(sorted(listed[hit])), hit) if hit else None
        return {fqdn: match for fqdn in wanted if (match := self._cache.get(fqdn)) is not None}
