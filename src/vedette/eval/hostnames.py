"""The evaluation's list of popular full hostnames: downloaded by ``vedette eval`` itself.

The top-sites list the rules use cannot measure false alerts, because the rules
skip every domain on it. Cisco Umbrella's list ranks the full names its
resolvers see most (``events.data.microsoft.com``), which is what devices
actually look up. Only the evaluation uses it, so the evaluation downloads it,
at most once per refresh period, and keeps the top rows in the database.
Nothing about the network is sent: it is a plain download of a public file.

The list is untrusted input like any other reference list: size-capped,
validated row by row, and a bad download leaves the stored copy in place.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta

import httpx
import structlog

from vedette.enrich.fetch import ReferenceFetchError, fetch_limited
from vedette.enrich.popularity import parse_tranco
from vedette.storage.reference import ReferenceStore

log = structlog.get_logger(__name__)

#: Only the most popular names are kept: the list's tail holds junk and some malicious names.
HOSTNAMES_TOP = 100_000
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
_STATE = "eval_hostnames"


@dataclass(frozen=True, slots=True)
class HostnameList:
    """Whether the evaluation can use the hostname list, and why not if it cannot.

    Attributes:
        available: A stored copy exists and may be used.
        refreshed_at: When the stored copy was downloaded.
        downloaded: This call downloaded a fresh copy.
        problem: What went wrong or why the sets are left out, for the report.
    """

    available: bool
    refreshed_at: datetime | None
    downloaded: bool
    problem: str | None


def _day(moment: datetime) -> str:
    return moment.date().isoformat()


async def ensure_hostnames(
    reference: ReferenceStore,
    client: httpx.AsyncClient,
    *,
    url: str | None,
    refresh: timedelta,
    now: datetime,
    offline: bool,
) -> HostnameList:
    """Make sure a usable copy of the list is stored, downloading it if it is due.

    Args:
        reference: Where the list is kept.
        client: HTTP client for the download.
        url: The list's address; ``None`` leaves the hostname sets out.
        refresh: Download again once the stored copy is this old.
        now: The current time (UTC).
        offline: Download nothing; use the stored copy whatever its age.
    """
    if url is None:
        return HostnameList(
            available=False,
            refreshed_at=None,
            downloaded=False,
            problem="The popular-hostname sets are switched off (evaluation.hostnames_url).",
        )
    stored = await reference.refreshed_at(_STATE)
    if offline:
        if stored is not None:
            return HostnameList(True, stored, downloaded=False, problem=None)
        return HostnameList(
            available=False,
            refreshed_at=None,
            downloaded=False,
            problem=(
                "The run was --offline and no popular-hostname list is stored yet, "
                "so the popular-hostname sets were skipped."
            ),
        )
    if stored is not None and now - stored < refresh:
        return HostnameList(True, stored, downloaded=False, problem=None)
    try:
        data = await fetch_limited(client, url, max_bytes=MAX_DOWNLOAD_BYTES)
        rows = await asyncio.to_thread(lambda: list(parse_tranco(data, max_rows=HOSTNAMES_TOP)))
        if not rows:
            raise ReferenceFetchError("no usable rows")
    except (ReferenceFetchError, ValueError) as exc:
        reason = str(exc)
        log.warning("eval_hostnames_refresh_failed", reason=reason)
        if stored is not None:
            return HostnameList(
                available=True,
                refreshed_at=stored,
                downloaded=False,
                problem=(
                    f"The popular-hostname list could not be downloaded ({reason}); "
                    f"the copy from {_day(stored)} was used."
                ),
            )
        return HostnameList(
            available=False,
            refreshed_at=None,
            downloaded=False,
            problem=(
                f"The popular-hostname list could not be downloaded ({reason}), "
                "so the popular-hostname sets were skipped."
            ),
        )
    entries = await reference.replace_eval_hostnames(((name, rank) for name, rank in rows), now)
    log.info("eval_hostnames_refreshed", entries=entries)
    return HostnameList(available=True, refreshed_at=now, downloaded=True, problem=None)
