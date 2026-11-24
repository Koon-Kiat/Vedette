"""The evaluation's popular-hostname list: downloaded at most weekly, kept, and skipped safely."""

from datetime import UTC, datetime, timedelta

import httpx
import respx
from sqlalchemy import select

from tests.integration.list_helpers import HOSTNAMES_URL, zipped
from vedette.eval.hostnames import HostnameList, ensure_hostnames
from vedette.storage.models import eval_hostnames
from vedette.storage.reference import ReferenceStore
from vedette.storage.store import Store

NOW = datetime(2026, 11, 24, 8, 0, tzinfo=UTC)
WEEK = timedelta(days=7)
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
    assert "could not be downloaded" in result.problem
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
    assert "skipped" in result.problem


async def test_a_missing_url_switches_the_sets_off(store: Store, router: respx.MockRouter) -> None:
    result = await ensure(store, now=NOW, url=None)

    assert result.available is False
    assert result.problem is not None
    assert "switched off" in result.problem
    assert not router.calls
