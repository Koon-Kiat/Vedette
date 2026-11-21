"""Popularity rank from a downloadable top-sites list (Tranco by default).

The list is a zip holding one CSV of ``rank,domain`` rows. It is downloaded at
most once per refresh period, stored in the database and looked up locally, so
no query about an individual domain ever leaves the machine.
"""

import asyncio
import io
import zipfile
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta

import httpx
import structlog

from vedette.enrich.fetch import ReferenceFetchError, fetch_limited, is_domain
from vedette.storage.reference import ReferenceStore

log = structlog.get_logger(__name__)

MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
RETRY_AFTER_FAILURE = timedelta(hours=1)
_CACHE_LIMIT = 200_000


def parse_tranco(
    data: bytes,
    *,
    max_rows: int = 1_500_000,
    max_uncompressed_bytes: int = 256 * 1024 * 1024,
) -> Iterator[tuple[str, int]]:
    """Yield ``(domain, rank)`` from a Tranco-format zip, skipping bad rows.

    Raises:
        ValueError: The data is not a zip archive, has no file in it, or would
            expand beyond ``max_uncompressed_bytes``.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("top-sites list is not a zip archive") from None
    with archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if not members:
            raise ValueError("top-sites zip archive is empty")
        member = members[0]
        if member.file_size > max_uncompressed_bytes:
            raise ValueError("top-sites list is too large when unpacked")
        seen: set[str] = set()
        with archive.open(member) as handle:
            for raw in io.TextIOWrapper(handle, encoding="utf-8", errors="replace"):
                rank_text, _, domain = raw.strip().partition(",")
                domain = domain.strip().lower()
                if not rank_text.isdigit() or int(rank_text) < 1 or not is_domain(domain):
                    continue
                if domain in seen:
                    continue
                seen.add(domain)
                yield domain, int(rank_text)
                if len(seen) >= max_rows:
                    return


class PopularityList:
    """Looks up how popular a root domain is."""

    def __init__(
        self, reference: ReferenceStore, client: httpx.AsyncClient, *, url: str, refresh_days: int
    ) -> None:
        """Create the list.

        Args:
            reference: Where the list is stored.
            client: HTTP client used to download it.
            url: Location of the zip file.
            refresh_days: Download a fresh copy after this many days.
        """
        self._reference = reference
        self._client = client
        self._url = url
        self._refresh = timedelta(days=refresh_days)
        self._known = False
        self._cache: dict[str, int | None] = {}
        self._retry_at: datetime | None = None

    @property
    def known(self) -> bool:
        """Whether a list is loaded. If not, a missing rank means nothing."""
        return self._known

    async def load(self) -> None:
        """Note whether a previously downloaded list is already stored."""
        self._known = await self._reference.popularity_count() > 0

    async def refresh_if_stale(self, now: datetime) -> bool:
        """Download a new list if the stored one is old; return whether it changed.

        A failed download keeps the previous list and is retried an hour later.
        """
        if self._retry_at is not None and now < self._retry_at:
            return False
        last = await self._reference.refreshed_at("popularity")
        if last is not None and now - last < self._refresh:
            if not self._known:
                await self.load()
            return False
        try:
            data = await fetch_limited(self._client, self._url, max_bytes=MAX_DOWNLOAD_BYTES)
            rows = await asyncio.to_thread(lambda: list(parse_tranco(data)))
            if not rows:
                raise ReferenceFetchError("no usable rows")
        except (ReferenceFetchError, ValueError) as exc:
            self._retry_at = now + RETRY_AFTER_FAILURE
            log.warning("popularity_refresh_failed", reason=str(exc))
            return False
        entries = await self._reference.replace_popularity(rows, now)
        self._known = True
        self._cache.clear()
        self._retry_at = None
        log.info("popularity_refreshed", entries=entries)
        return True

    async def ranks(self, roots: Iterable[str]) -> dict[str, int | None]:
        """Rank of each root, or ``None`` when it is not on the list."""
        wanted = set(roots)
        missing = [root for root in wanted if root not in self._cache]
        if missing:
            if len(self._cache) > _CACHE_LIMIT:
                self._cache.clear()
            found = await self._reference.ranks(missing)
            for root in missing:
                self._cache[root] = found.get(root)
        return {root: self._cache[root] for root in wanted}
