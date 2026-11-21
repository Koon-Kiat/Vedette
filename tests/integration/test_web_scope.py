"""The profile switch: one choice in the rail scopes every sheet, remembered per browser."""

import json
import re

import pytest

from tests.integration.web_helpers import logged_in
from tests.web_fixture import build_web_fixture
from vedette.storage.store import Store

ROUTER, PC = "abc123", "def456"  # inks 1 and 2, in the order of the configuration


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    return store


def row_inks(html: str) -> set[str]:
    return set(re.findall(r'<tr id="finding-\d+" class="[^"]*\bink-(\d)\b', html))


async def test_choosing_a_profile_is_remembered_and_scopes_the_findings(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        both = await client.get("/findings?status=all")
        switched = await client.get(f"/scope?to={PC}&next=/findings%3Fstatus%3Dall")
        pc_only = await client.get("/findings?status=all")

    assert row_inks(both.text) == {"1", "2"}
    assert (switched.status_code, switched.headers["location"]) == (303, "/findings?status=all")
    cookie = switched.headers["set-cookie"].lower()
    assert f"vedette_scope={PC}" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert row_inks(pc_only.text) == {"2"}
    assert "pc only" in pc_only.text  # the title block says what the sheet shows


async def test_the_rail_counts_every_profile_whatever_is_shown(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        await client.get(f"/scope?to={PC}&next=/")
        html = (await client.get("/")).text

    switch = html.split('class="layers"', 1)[1].split("</nav>", 1)[0]
    options = re.findall(r'<a class="layer-option[^"]*" href="([^"]+)"([^>]*)>', switch)
    assert [href.split("&")[0] for href, _ in options] == [
        "/scope?to=all",
        f"/scope?to={ROUTER}",
        f"/scope?to={PC}",
    ]
    assert [bool("aria-current" in rest) for _, rest in options] == [False, False, True]
    counts = [int(n) for n in re.findall(r'class="layer-open[^"]*"[^>]*>(\d+) open', switch)]
    assert counts[0] == counts[1] + counts[2] and counts[1] > 0, "router's findings stay counted"


async def test_back_to_both_and_bad_choices(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        unknown = await client.get("/scope?to=nope&next=/")
        away = await client.get("/scope?to=all&next=//evil.example/")
        home = await client.get("/scope?to=all")

    assert unknown.status_code == 422
    assert away.headers["location"] == "/findings"  # never off the dashboard
    assert home.headers["location"] == "/"


async def test_charts_draw_each_profile_shown_as_its_own_layer(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        both = json.loads((await client.get("/api/series")).text)
        await client.get(f"/scope?to={ROUTER}&next=/")
        router = json.loads((await client.get("/api/series")).text)

    assert [(layer["label"], layer["ink"]) for layer in both["layers"]] == [
        ("router", 1),
        ("pc", 2),
    ]
    assert [(layer["label"], layer["ink"]) for layer in router["layers"]] == [("router", 1)]
    assert router["allowed"] == router["layers"][0]["allowed"]


async def test_a_finding_on_a_profile_not_shown_still_opens(filled: Store) -> None:
    pc_finding = next(f.id for f in await filled.list_findings(limit=100) if f.profile_id == PC)
    async with logged_in(filled) as (client, _):
        await client.get(f"/scope?to={ROUTER}&next=/")
        page = await client.get(f"/findings/{pc_finding}")

    assert page.status_code == 200, "a link from an alert or a digest must always work"


async def test_a_finding_links_to_the_next_and_previous_open_finding(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        listed = (await client.get("/findings?status=open")).text
        order = re.findall(r'<tr id="finding-(\d+)"', listed)
        ranked = sorted(
            order,
            key=lambda fid: (
                -int(
                    re.search(rf'id="finding-{fid}"[\s\S]*?class="pri" data-sort="(\d)"', listed)[1]  # type: ignore[index]
                )
            ),
        )
        middle = (await client.get(f"/findings/{ranked[1]}")).text

    assert f'href="/findings/{ranked[0]}" data-key="previous"' in middle
    assert f'href="/findings/{ranked[2]}" data-key="next"' in middle


async def test_the_day_filter_lists_only_days_with_findings(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        html = (await client.get("/findings?status=all")).text

    day_select = html.split('name="date"', 1)[1].split("</select>", 1)[0]
    days = re.findall(r'<option value="(\d{4}-\d{2}-\d{2})"', day_select)
    assert days and days == sorted(days, reverse=True)
    assert 'data-ui="select"' in html  # drawn by the dashboard, not the browser
