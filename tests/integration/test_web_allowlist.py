"""The Allowlist page: what the rules skip, and taking back an entry Mark benign made."""

import re

import pytest

from tests.integration.web_helpers import NOW, logged_in
from tests.web_fixture import build_web_fixture
from vedette.rules.allowlist import AllowlistEntry
from vedette.storage.store import Store
from vedette.storage.triage import TriageStore


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    return store


async def benign_domain_finding(store: Store) -> tuple[int, str]:
    """Mark a domain finding benign, which allowlists its root; return its id and root."""
    found = next(f for f in await store.list_findings(limit=100) if f.rule_id == "young-domain")
    await TriageStore(store.engine).mark_benign(found.id, actor="dashboard", now=NOW)
    return found.id, found.target


async def test_stored_entries_are_listed_with_where_they_came_from(filled: Store) -> None:
    finding_id, root = await benign_domain_finding(filled)

    (entry,) = await TriageStore(filled.engine).stored_allowlist()

    assert (entry.root, entry.finding_id, entry.created_by) == (root, finding_id, "dashboard")
    assert entry.created_at == NOW


async def test_removing_an_entry_keeps_the_finding_benign_and_records_why(filled: Store) -> None:
    finding_id, root = await benign_domain_finding(filled)
    triage = TriageStore(filled.engine)
    (entry,) = await triage.stored_allowlist()

    removed = await triage.remove_allowlist_entry(entry.id, actor="dashboard", now=NOW)

    assert removed is not None and removed.root == root
    assert await triage.stored_allowlist() == []
    assert await triage.remove_allowlist_entry(entry.id, actor="dashboard", now=NOW) is None
    finding = await filled.finding(finding_id)
    assert finding is not None and finding.status == "benign"
    latest = (await triage.audit_for([finding_id]))[-1]
    assert latest.action == "allowlist_removed"
    assert "removed from the allowlist" in latest.detail


async def test_the_page_lists_stored_and_configured_entries(filled: Store) -> None:
    finding_id, root = await benign_domain_finding(filled)
    configured = [AllowlistEntry(root="printer-cloud.example", profile="router")]
    async with logged_in(filled, allowlist=configured) as (client, _):
        html = (await client.get("/allowlist")).text

    assert "<title>Allowlist · Vedette</title>" in html
    assert root.replace(".", "[.]") in re.sub(r"<wbr>", "", html), "names are defanged"
    assert f'href="/findings/{finding_id}"' in html
    assert "printer-cloud[.]example" in re.sub(r"<wbr>", "", html)
    assert "config.yaml" in html
    assert 'aria-current="page"><span class="page-name">Allowlist' in html


async def test_an_empty_allowlist_says_how_entries_are_made(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        html = (await client.get("/allowlist")).text

    assert "Nothing is allowlisted" in html
    assert "Mark benign" in html


async def test_removing_from_the_page_needs_the_csrf_token(filled: Store) -> None:
    await benign_domain_finding(filled)
    (entry,) = await TriageStore(filled.engine).stored_allowlist()
    async with logged_in(filled) as (client, csrf):
        refused = await client.post(f"/allowlist/{entry.id}/remove", data={"csrf_token": "x"})
        missing = await client.post("/allowlist/99999/remove", data={"csrf_token": csrf})
        done = await client.post(f"/allowlist/{entry.id}/remove", data={"csrf_token": csrf})

    assert refused.status_code == 403
    assert missing.status_code == 404
    assert (done.status_code, done.headers["location"]) == (303, "/allowlist")
    assert await TriageStore(filled.engine).stored_allowlist() == []


async def test_removing_through_htmx_reloads_the_page(filled: Store) -> None:
    await benign_domain_finding(filled)
    (entry,) = await TriageStore(filled.engine).stored_allowlist()
    async with logged_in(filled) as (client, csrf):
        response = await client.post(
            f"/allowlist/{entry.id}/remove",
            data={"csrf_token": csrf},
            headers={"HX-Request": "true"},
        )

    assert response.headers["HX-Redirect"] == "/allowlist"


async def test_every_page_is_numbered_out_of_nine_and_the_brand_is_vedette(filled: Store) -> None:
    async with logged_in(filled) as (client, _):
        findings = (await client.get("/findings")).text
        allowlist = (await client.get("/allowlist")).text
        evaluation = (await client.get("/evaluation")).text

    assert "3 of 9" in findings and "6 of 9" in allowlist and "9 of 9" in evaluation
    brand = re.search(r'<span class="brand-name">(.*?)</span></a>', findings)
    assert brand is not None and "NextDNS" not in brand[1] and "Vedette" in brand[1]
