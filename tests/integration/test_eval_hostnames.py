"""The evaluation's popular-hostname list: downloaded at most weekly, kept, and skipped safely."""

import zipfile
from datetime import UTC, datetime, timedelta

import httpx
import respx
from sqlalchemy import select

from tests.integration.list_helpers import HOSTNAMES_URL, damaged, zipped
from vedette.eval.hostnames import HostnameList, ensure_hostnames
from vedette.storage.models import eval_hostnames
from vedette.storage.reference import ReferenceStore
from vedette.storage.store import Store

NOW = datetime(2026, 11, 24, 8, 0, tzinfo=UTC)
WEEK = timedelta(days=7)
OTHER_URL = "https://lists.test/other-list.csv.zip"
ROWS = ["1,google.com", "2,www.google.com", "3,not a name", "4,www.google.com", "5,10.0.0.1"]


async def ensure(
    store: Store, *, now: datetime, offline: bool = False, url: str | None = HOSTNAMES_URL
) -> HostnameList:
    async with httpx.AsyncClient() as client:
        return await ensure_hostnames(
            ReferenceStore(store.engine), client, url=url, refresh=WEEK, now=now, offline=offline
        )


async def stored_names(store: Store) -> list[str]:
    async with store.engine.connect() as connection:
        rows = await connection.execute(
            select(eval_hostnames.c.name).order_by(eval_hostnames.c.rank)
        )
        return list(rows.scalars())


async def test_the_list_is_downloaded_once_a_week(store: Store, router: respx.MockRouter) -> None:
    route = router.get(HOSTNAMES_URL).mock(return_value=httpx.Response(200, content=zipped(ROWS)))

    first = await ensure(store, now=NOW)
    again = await ensure(store, now=NOW + timedelta(days=6))
    later = await ensure(store, now=NOW + timedelta(days=8))

    assert (first.available, first.downloaded, first.problem) == (True, True, None)
    assert first.refreshed_at == NOW
    assert (again.available, again.downloaded, again.problem) == (True, False, None)
    assert later.downloaded is True
    assert route.call_count == 2
    # The invalid name, the repeated name and the address are dropped.
    assert await stored_names(store) == ["google.com", "www.google.com"]


async def test_offline_uses_the_stored_copy_without_asking(
    store: Store, router: respx.MockRouter
) -> None:
    route = router.get(HOSTNAMES_URL).mock(return_value=httpx.Response(200, content=zipped(ROWS)))
    await ensure(store, now=NOW)

    offline = await ensure(store, now=NOW + timedelta(days=30), offline=True)

    assert (offline.available, offline.downloaded, offline.problem) == (True, False, None)
    assert offline.refreshed_at == NOW
    assert route.call_count == 1


async def test_offline_without_a_copy_skips_the_sets(
    store: Store, router: respx.MockRouter
) -> None:
    result = await ensure(store, now=NOW, offline=True)

    assert result.available is False
    assert result.problem is not None
    assert "--offline" in result.problem
    assert "skipped" in result.problem
    assert not router.calls


async def test_a_failed_download_falls_back_to_the_stored_copy(
    store: Store, router: respx.MockRouter
) -> None:
    router.get(HOSTNAMES_URL).mock(
        side_effect=[httpx.Response(200, content=zipped(ROWS)), httpx.Response(500)]
    )
    await ensure(store, now=NOW)

    result = await ensure(store, now=NOW + timedelta(days=8))

    assert (result.available, result.downloaded, result.refreshed_at) == (True, False, NOW)
    assert result.problem is not None
    assert "could not be downloaded" in result.problem
    assert "2026-11-24" in result.problem
    assert await stored_names(store) == ["google.com", "www.google.com"]


async def test_a_download_that_is_not_a_zip_skips_the_sets(
    store: Store, router: respx.MockRouter
) -> None:
    router.get(HOSTNAMES_URL).mock(return_value=httpx.Response(200, content=b"<html></html>"))

    result = await ensure(store, now=NOW)

    assert (result.available, result.downloaded) == (False, False)
    assert result.problem is not None
    # It was downloaded; it could not be read. The reason names no other list.
    assert "could not be used (the file is not a zip archive)" in result.problem
    assert "top-sites" not in result.problem
    assert "skipped" in result.problem
    assert await stored_names(store) == []


async def test_a_list_with_no_usable_rows_keeps_nothing(
    store: Store, router: respx.MockRouter
) -> None:
    router.get(HOSTNAMES_URL).mock(
        return_value=httpx.Response(200, content=zipped(["rank,domain", "x,not a name"]))
    )

    result = await ensure(store, now=NOW)

    assert result.available is False
    assert result.problem is not None
    assert "could not be used (no usable rows)" in result.problem
    assert "skipped" in result.problem


async def test_a_missing_url_switches_the_sets_off(store: Store, router: respx.MockRouter) -> None:
    result = await ensure(store, now=NOW, url=None)

    assert result.available is False
    assert result.problem is not None
    assert "switched off" in result.problem
    # A dotted setting name would be bracketed like a domain on the dashboard.
    assert "hostnames_url" in result.problem
    assert "evaluation.hostnames_url" not in result.problem
    assert not router.calls


async def test_a_new_address_is_downloaded_at_once(store: Store, router: respx.MockRouter) -> None:
    first = router.get(HOSTNAMES_URL).mock(
        return_value=httpx.Response(200, content=zipped(["1,google.com"]))
    )
    other = router.get(OTHER_URL).mock(
        return_value=httpx.Response(200, content=zipped(["1,example.org"]))
    )
    await ensure(store, now=NOW)

    switched = await ensure(store, now=NOW + timedelta(days=1), url=OTHER_URL)
    names_after_switch = await stored_names(store)
    back = await ensure(store, now=NOW + timedelta(days=2))

    assert (switched.downloaded, switched.problem) == (True, None)
    assert names_after_switch == ["example.org"]
    assert back.downloaded is True, "the copy from the other address is not reused"
    assert (first.call_count, other.call_count) == (2, 1)
    assert await stored_names(store) == ["google.com"]


async def test_offline_does_not_use_a_copy_from_another_address(
    store: Store, router: respx.MockRouter
) -> None:
    router.get(HOSTNAMES_URL).mock(
        return_value=httpx.Response(200, content=zipped(["1,google.com"]))
    )
    await ensure(store, now=NOW)

    result = await ensure(store, now=NOW, url=OTHER_URL, offline=True)

    assert result.available is False
    assert result.problem is not None
    assert "--offline" in result.problem


async def test_a_damaged_archive_skips_the_sets_without_crashing(
    store: Store, router: respx.MockRouter
) -> None:
    router.get(HOSTNAMES_URL).mock(
        return_value=httpx.Response(200, content=damaged(zipfile.ZIP_DEFLATED))
    )

    result = await ensure(store, now=NOW)

    assert result.available is False
    assert result.problem is not None
    assert "could not be used (the archive is damaged or unreadable" in result.problem
    assert "skipped" in result.problem
