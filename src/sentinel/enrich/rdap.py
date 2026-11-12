"""Domain registration age via RDAP, cached.

RDAP is the one enrichment that tells a third party which domain is being
looked at: the registry's RDAP server sees the root being queried. It is
therefore used sparingly (see the enricher) and can be switched off.

The registry for a TLD is found through the IANA bootstrap file. A missing or
failed answer means "unknown", which no rule treats as a signal.
"""

import asyncio
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import httpx
import structlog

from sentinel.enrich.fetch import is_domain
from sentinel.storage.reference import DomainAgeRecord, ReferenceStore

log = structlog.get_logger(__name__)

_BOOTSTRAP_TTL_SECONDS = 24 * 3600.0
_TIMEOUT = httpx.Timeout(10.0)


class RdapUnavailable(Exception):
    """RDAP could not be reached right now; try again later."""


@dataclass(frozen=True, slots=True)
class RdapResult:
    """Outcome of one lookup: ``found``, ``not_found``, ``no_date`` or ``unsupported``."""

    status: str
    registered_at: datetime | None = None


class RdapClient:
    """Looks up a domain's registration date at its registry."""

    def __init__(self, client: httpx.AsyncClient, *, bootstrap_url: str) -> None:
        """Create a client that discovers registries from ``bootstrap_url``."""
        self._client = client
        self._bootstrap_url = bootstrap_url
        self._servers: dict[str, str] = {}
        self._loaded_at: float | None = None
        self._lock = asyncio.Lock()

    async def _server_for(self, tld: str) -> str | None:
        async with self._lock:
            stale = (
                self._loaded_at is None
                or time.monotonic() - self._loaded_at > _BOOTSTRAP_TTL_SECONDS
            )
            if stale:
                await self._load_bootstrap()
        return self._servers.get(tld)

    async def _load_bootstrap(self) -> None:
        try:
            response = await self._client.get(self._bootstrap_url, timeout=_TIMEOUT)
            if response.status_code != 200:
                raise RdapUnavailable(f"bootstrap answered HTTP {response.status_code}")
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RdapUnavailable(f"bootstrap failed: {type(exc).__name__}") from exc
        servers: dict[str, str] = {}
        services = body.get("services") if isinstance(body, dict) else None
        for service in services if isinstance(services, list) else []:
            if not (isinstance(service, list) and len(service) == 2):
                continue
            tlds, urls = service
            if not isinstance(tlds, list) or not isinstance(urls, list):
                continue
            secure = [url for url in urls if isinstance(url, str) and url.startswith("https://")]
            if not secure:
                continue
            for tld in tlds:
                if isinstance(tld, str):
                    servers[tld.lower()] = secure[0]
        self._servers = servers
        self._loaded_at = time.monotonic()

    async def lookup(self, root: str) -> RdapResult:
        """Ask the registry when ``root`` was registered.

        Raises:
            RdapUnavailable: Network failure, rate limiting or a server error.
        """
        server = await self._server_for(root.rsplit(".", 1)[-1])
        if server is None:
            return RdapResult("unsupported")
        url = f"{server.rstrip('/')}/domain/{quote(root, safe='.-_')}"
        try:
            response = await self._client.get(url, timeout=_TIMEOUT)
        except httpx.HTTPError as exc:
            raise RdapUnavailable(type(exc).__name__) from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise RdapUnavailable(f"HTTP {response.status_code}")
        if response.status_code != 200:
            return RdapResult("not_found")
        try:
            body = response.json()
        except ValueError:
            return RdapResult("no_date")
        events = body.get("events") if isinstance(body, dict) else None
        for item in events if isinstance(events, list) else []:
            if isinstance(item, dict) and item.get("eventAction") == "registration":
                try:
                    when = datetime.fromisoformat(str(item.get("eventDate")))
                except ValueError:
                    break
                return RdapResult("found", when if when.tzinfo else when.replace(tzinfo=UTC))
        return RdapResult("no_date")


class DomainAges:
    """Registration ages of roots, from the cache and (optionally) RDAP."""

    def __init__(
        self,
        reference: ReferenceStore,
        rdap: RdapClient | None,
        *,
        negative_retry: timedelta = timedelta(days=7),
        concurrency: int = 5,
    ) -> None:
        """Create the service.

        Args:
            reference: Where answers are cached.
            rdap: Client for live lookups, or ``None`` to use the cache only.
            negative_retry: How long an "unknown" answer is trusted before asking again.
            concurrency: Maximum simultaneous RDAP requests.
        """
        self._reference = reference
        self._rdap = rdap
        self._negative_retry = negative_retry
        self._limit = asyncio.Semaphore(concurrency)

    @staticmethod
    def _days(record: DomainAgeRecord, now: datetime) -> int | None:
        if record.status != "found" or record.registered_at is None:
            return None
        days = (now - record.registered_at).days
        return days if days >= 0 else None

    async def cached(self, roots: Iterable[str], now: datetime) -> dict[str, int | None]:
        """Ages known from the cache alone; ``None`` where unknown. No network."""
        wanted = list(dict.fromkeys(roots))
        records = await self._reference.domain_ages(wanted)
        return {
            root: self._days(records[root], now) if root in records else None for root in wanted
        }

    async def _lookup(self, root: str, now: datetime) -> DomainAgeRecord | None:
        if self._rdap is None:
            return None
        async with self._limit:
            try:
                result = await self._rdap.lookup(root)
            except RdapUnavailable as exc:
                log.warning("rdap_unavailable", reason=str(exc))
                return None
        return DomainAgeRecord(root, result.status, result.registered_at, now)

    async def resolve(self, roots: Iterable[str], now: datetime) -> dict[str, int | None]:
        """Ages of ``roots``, looking up any that are not cached.

        Roots that are not plain domain names are never sent anywhere.
        """
        wanted = list(dict.fromkeys(roots))
        records = await self._reference.domain_ages(wanted)
        to_ask = [
            root
            for root in wanted
            if is_domain(root)
            and (
                root not in records
                or (
                    records[root].status != "found"
                    and now - records[root].fetched_at >= self._negative_retry
                )
            )
        ]
        fresh = [
            record
            for record in await asyncio.gather(*(self._lookup(root, now) for root in to_ask))
            if record is not None
        ]
        await self._reference.save_domain_ages(fresh)
        records.update({record.root: record for record in fresh})
        return {
            root: self._days(records[root], now) if root in records else None for root in wanted
        }
