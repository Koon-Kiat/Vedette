"""The analyst stage inside the running pipeline, with Ollama mocked."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from structlog.testing import capture_logs

from tests.integration.conftest import (
    pipeline_env,
    read_when_migrated,
    running_pipeline,
    wait_until,
)
from tests.integration.fake_nextdns import FakeNextDns
from vedette.shared.models import Analysis
from vedette.storage.analysis import AnalysisStore
from vedette.storage.store import Store, StoredFinding

OLLAMA_CHAT = "http://ollama.test/api/chat"


@pytest.fixture
def database_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, router: respx.MockRouter) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'pipeline.db'}"
    pipeline_env(
        monkeypatch,
        router,
        url,
        findings=True,
        extra={"VEDETTE_LLM__BASE_URL": "http://ollama.test"},
    )
    return url


def answer_every_finding(request: httpx.Request, **overrides: Any) -> httpx.Response:
    """Behave like a model that returns one verdict per finding it was sent."""
    asked = json.loads(json.loads(request.content)["messages"][1]["content"])["findings"]
    verdicts = [
        {
            "finding_id": item["finding_id"],
            "summary": f"Explained {item['rule_id']}.",
            "likely_cause": "A cause.",
            "recommended_action": "An action.",
            "priority": "info",
            "group_key": item["rule_id"],
            "confidence": 0.5,
            **overrides,
        }
        for item in asked
    ]
    content = json.dumps({"verdicts": verdicts})
    return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})


async def state_of(store: Store) -> tuple[list[StoredFinding], dict[int, Analysis]]:
    found = await store.list_findings(limit=1000)
    return found, await AnalysisStore(store.engine).analyses_for([f.id for f in found])


async def read_state(database_url: str) -> tuple[list[StoredFinding], dict[int, Analysis]]:
    store = Store.open(database_url)
    try:
        return await state_of(store)
    finally:
        await store.close()


async def run_pipeline(
    database_url: str,
    *,
    until_analysed: bool,
    at_least_findings: int = 1,
    and_also: Callable[[], bool] = lambda: True,
) -> None:
    async def done() -> bool:
        state = await read_when_migrated(database_url, state_of)
        if state is None:
            return False
        found, analyses = state
        if len(found) < at_least_findings or not and_also():
            return False
        return len(analyses) == len(found) if until_analysed else True

    async with running_pipeline():
        await wait_until(done, timeout=20)


async def test_findings_are_explained_and_no_priority_drops_below_its_floor(
    server: FakeNextDns, database_url: str, router: respx.MockRouter
) -> None:
    server.add_entries(40)
    router.post(OLLAMA_CHAT).mock(side_effect=answer_every_finding)  # always answers "info"

    await run_pipeline(database_url, until_analysed=True, at_least_findings=3)

    found, analyses = await read_state(database_url)
    assert {a.source for a in analyses.values()} == {"llm"}
    for finding in found:
        analysis = analyses[finding.id]
        assert analysis.priority is finding.severity, "the model said info; the floor won"
        assert analysis.summary == f"Explained {finding.rule_id}."
    assert any(f.severity.value == "critical" for f in found)


async def test_ollama_being_down_does_not_stop_findings_and_is_caught_up_later(
    server: FakeNextDns, database_url: str, router: respx.MockRouter
) -> None:
    server.add_entries(40)
    route = router.post(OLLAMA_CHAT).mock(side_effect=httpx.ConnectError("ollama is down"))

    with capture_logs() as logs:
        await run_pipeline(
            database_url,
            until_analysed=False,
            at_least_findings=3,
            # Wait for the worker to have reported the outage, not merely attempted a call.
            and_also=lambda: "analyst_ollama_unavailable" in [entry["event"] for entry in logs],
        )
    assert "analyst_ollama_unavailable" in [entry["event"] for entry in logs]

    found, analyses = await read_state(database_url)
    assert len(found) >= 3
    assert analyses == {}, "nothing is invented while the model is unreachable"

    route.mock(side_effect=answer_every_finding)
    await run_pipeline(database_url, until_analysed=True, at_least_findings=3)

    found, analyses = await read_state(database_url)
    assert sorted(analyses) == sorted(f.id for f in found)
