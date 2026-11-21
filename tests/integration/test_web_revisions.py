"""Decisions are entered as lettered revisions, and the Overview counts today's."""

import re

import pytest

from sentinel.storage.store import Store
from tests.integration.web_helpers import logged_in
from tests.web_fixture import build_web_fixture


@pytest.fixture
async def filled(store: Store) -> Store:
    await build_web_fixture(store)
    return store


def row(html: str, finding_id: int) -> str:
    match = re.search(rf'<tr id="finding-{finding_id}"[\s\S]*?</tr>', html)
    assert match is not None
    return match[0]


async def test_each_decision_on_a_row_carries_the_next_revision_letter(filled: Store) -> None:
    fid = next(f.id for f in await filled.list_findings(limit=100) if f.severity.value == "low")
    async with logged_in(filled) as (client, csrf):
        before = (await client.get("/")).text
        await client.post(f"/findings/{fid}/acknowledge", data={"csrf_token": csrf, "next": "/"})
        acknowledged = row((await client.get("/findings?status=all")).text, fid)
        await client.post(f"/findings/{fid}/reopen", data={"csrf_token": csrf, "next": "/"})
        reopened = row((await client.get("/findings?status=all")).text, fid)
        after = (await client.get("/")).text

    assert 'class="corr-letter" title="Revision A">A</span><s>open</s>' in acknowledged
    assert '<span class="corr-new">acknowledged' in acknowledged
    assert (
        'class="corr-letter" title="Revision B">B</span><span class="corr-new">reopened' in reopened
    )

    def today(html: str) -> int:
        found = re.search(r'<dt>Revisions today</dt><dd class="figure">(\d+)</dd>', html)
        assert found is not None
        return int(found[1])

    assert today(after) == today(before) + 2
