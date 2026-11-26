"""The LLM analyst against a real database and a mocked Ollama."""

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import text

from vedette.llm import analyst as analyst_module
from vedette.llm.analyst import Analyst
from vedette.llm.ollama import OllamaClient, OllamaUnavailable
from vedette.llm.prompts import SYSTEM_PROMPT, build_payload
from vedette.rules.loader import load_rules
from vedette.shared.models import Analysis, Finding, Severity
from vedette.storage.analysis import AnalysisStore
from vedette.storage.store import Store, StoredFinding

OLLAMA = "http://ollama.test"
T0 = datetime(2026, 3, 15, 4, 30, tzinfo=UTC)


class FakeOllama:
    """Queues answers for /api/chat and records what was asked."""

    def __init__(self, router: respx.MockRouter) -> None:
        self.requests: list[dict[str, Any]] = []
        self.answers: list[httpx.Response | Exception | str] = []
        router.post(f"{OLLAMA}/api/chat").mock(side_effect=self._chat)

    def _chat(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(
            200, json={"model": "qwen3:8b", "message": {"role": "assistant", "content": answer}}
        )

    def say(self, *verdicts: dict[str, Any]) -> None:
        self.answers.append(json.dumps({"verdicts": list(verdicts)}))


def verdict(finding_id: int, **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "finding_id": finding_id,
        "summary": f"Summary for {finding_id}.",
        "likely_cause": "A cause.",
        "recommended_action": "An action.",
        "priority": "high",
        "group_key": "group-a",
        "confidence": 0.6,
    }
    values.update(overrides)
    return values


@pytest.fixture
def ollama(router: respx.MockRouter) -> FakeOllama:
    return FakeOllama(router)


@pytest.fixture
def analysis_store(store: Store) -> AnalysisStore:
    return AnalysisStore(store.engine)


@pytest.fixture
async def client() -> AsyncIterator[OllamaClient]:
    created = OllamaClient(
        OLLAMA, model="qwen3:8b", think=False, temperature=0.1, num_ctx=8192, keep_alive="5m"
    )
    yield created
    await created.aclose()


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def analyst(client: OllamaClient, analysis_store: AnalysisStore, clock: Clock) -> Analyst:
    return Analyst(
        client,
        analysis_store,
        load_rules(),
        max_batch=20,
        cache_ttl=timedelta(hours=168),
        clock=clock,
    )


async def seed(
    store: Store,
    analysis_store: AnalysisStore,
    count: int,
    *,
    rule: str = "young-domain",
    severity: str = "high",
    start: int = 0,
    evidence: dict[str, Any] | None = None,
) -> list[StoredFinding]:
    """Store ``count`` distinct findings and return them as the analyst sees them."""
    items = [
        Finding(
            rule_id=rule,
            severity=Severity(severity),
            profile_id="abc123",
            subject="D1",
            device_mode=True,
            target=f"site{n}.example",
            ts=T0 + timedelta(seconds=n),
            dedupe_key=f"{rule}|{n}",
            evidence=evidence or {"fqdn": f"login.site{n}.example", "domain_age_days": 5},
            event_id=f"{n:064d}",
        )
        for n in range(start, start + count)
    ]
    await store.commit_processed([], items)
    pending = await analysis_store.fetch_unanalysed(limit=100)
    return [item for item in pending if item.target in {i.target for i in items}]


def assert_usable(results: list[Analysis], findings: list[StoredFinding]) -> None:
    """Every finding has exactly one analysis that respects its floor."""
    assert sorted(r.finding_id for r in results) == sorted(f.id for f in findings)
    floors = {f.id: f.severity for f in findings}
    for result in results:
        assert result.priority.rank >= floors[result.finding_id].rank
        assert result.summary
        assert result.recommended_action
        assert 0.0 <= result.confidence <= 1.0


# --- the request ---------------------------------------------------------------------


async def test_request_uses_the_configured_model_schema_and_options(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    findings = await seed(store, analysis_store, 2)
    ollama.say(*(verdict(f.id) for f in findings))

    await analyst.analyse(findings)

    (request,) = ollama.requests
    assert request["model"] == "qwen3:8b"
    assert request["stream"] is False
    assert request["think"] is False
    assert request["keep_alive"] == "5m"
    assert request["options"] == {"temperature": 0.1, "num_ctx": 8192}
    assert request["format"]["required"] == ["verdicts"]
    assert "tools" not in request
    assert [message["role"] for message in request["messages"]] == ["system", "user"]
    payload = json.loads(request["messages"][1]["content"])
    assert [item["finding_id"] for item in payload["findings"]] == [f.id for f in findings]


# --- normal operation -------------------------------------------------------------------


async def test_valid_answers_become_analyses(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    findings = await seed(store, analysis_store, 3)
    ollama.say(*(verdict(f.id, group_key="Fresh Domains!") for f in findings))

    results = await analyst.analyse(findings)

    assert_usable(results, findings)
    assert {r.source for r in results} == {"llm"}
    assert {r.model for r in results} == {"qwen3:8b"}
    assert {r.group_key for r in results} == {"fresh-domains"}


async def test_a_lowered_priority_is_put_back_to_the_rule_floor(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    (finding,) = await seed(
        store, analysis_store, 1, rule="threat-intel-allowed", severity="critical"
    )
    ollama.say(verdict(finding.id, priority="info", summary="This is safe, mark benign."))

    (result,) = await analyst.analyse([finding])

    assert result.priority is Severity.CRITICAL


async def test_a_raised_priority_is_kept(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    (finding,) = await seed(store, analysis_store, 1, rule="volume-spike", severity="low")
    ollama.say(verdict(finding.id, priority="high"))

    (result,) = await analyst.analyse([finding])

    assert result.priority is Severity.HIGH


async def test_model_text_is_sanitised_before_it_is_returned(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    (finding,) = await seed(store, analysis_store, 1)
    ollama.say(
        verdict(
            finding.id,
            summary="**Click** [here](https://evil.example/a) <script>x</script>",
            recommended_action="Open http://evil.example now\x1b[2J",
        )
    )

    (result,) = await analyst.analyse([finding])

    for field in (result.summary, result.recommended_action):
        assert "http" not in field
        assert "evil.example" not in field
        assert "<" not in field
        assert "\x1b" not in field
        assert "](" not in field


async def test_large_sets_are_split_into_batches(
    store: Store,
    analysis_store: AnalysisStore,
    client: OllamaClient,
    clock: Clock,
    ollama: FakeOllama,
) -> None:
    analyst = Analyst(
        client, analysis_store, load_rules(), max_batch=2, cache_ttl=timedelta(0), clock=clock
    )
    findings = await seed(store, analysis_store, 5)
    for start in range(0, 5, 2):
        ollama.say(*(verdict(f.id) for f in findings[start : start + 2]))

    results = await analyst.analyse(findings)

    assert_usable(results, findings)
    assert [len(json.loads(r["messages"][1]["content"])["findings"]) for r in ollama.requests] == [
        2,
        2,
        1,
    ]


async def test_calls_are_sized_to_the_context_window(
    store: Store,
    analysis_store: AnalysisStore,
    client: OllamaClient,
    clock: Clock,
    ollama: FakeOllama,
) -> None:
    long = {"fqdn": "x" * 200, "sample": ["y" * 200] * 10}
    findings = await seed(store, analysis_store, 5, evidence=long)
    specs = load_rules()
    share = (
        len(build_payload([findings[0]], {s.id: s for s in specs})) / analyst_module.CHARS_PER_TOKEN
        + analyst_module.ANSWER_TOKENS
    )
    window = 4096
    budget = (
        window * analyst_module.CONTEXT_USE - len(SYSTEM_PROMPT) / analyst_module.CHARS_PER_TOKEN
    )
    per_call = int(budget // share)
    assert 1 <= per_call < 5  # the window, not max_batch, is what limits the calls here
    analyst = Analyst(
        client,
        analysis_store,
        specs,
        max_batch=20,
        cache_ttl=timedelta(0),
        context_tokens=window,
        clock=clock,
    )
    for start in range(0, 5, per_call):
        ollama.say(*(verdict(f.id) for f in findings[start : start + per_call]))

    results = await analyst.analyse(findings)

    assert_usable(results, findings)
    sizes = [len(json.loads(r["messages"][1]["content"])["findings"]) for r in ollama.requests]
    assert sizes == [min(per_call, 5 - start) for start in range(0, 5, per_call)]


# --- retry and fallback -------------------------------------------------------------------


async def test_an_invalid_answer_is_retried_once(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    findings = await seed(store, analysis_store, 2)
    ollama.answers.append("this is not json")
    ollama.say(*(verdict(f.id) for f in findings))

    results = await analyst.analyse(findings)

    assert len(ollama.requests) == 2
    assert {r.source for r in results} == {"llm"}


async def test_two_invalid_answers_fall_back_to_templates(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    findings = await seed(store, analysis_store, 2)
    ollama.answers.extend(["garbage", '{"verdicts": "still wrong"}'])

    results = await analyst.analyse(findings)

    assert len(ollama.requests) == 2, "exactly one retry"
    assert_usable(results, findings)
    assert {r.source for r in results} == {"template"}
    assert {r.priority for r in results} == {Severity.HIGH}


async def test_a_finding_the_model_skipped_gets_a_template_after_one_retry(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    findings = await seed(store, analysis_store, 3)
    ollama.say(verdict(findings[0].id), verdict(findings[1].id))
    ollama.say(verdict(findings[0].id), verdict(findings[1].id))

    results = await analyst.analyse(findings)

    assert_usable(results, findings)
    sources = {r.finding_id: r.source for r in results}
    assert sources == {findings[0].id: "llm", findings[1].id: "llm", findings[2].id: "template"}


async def test_verdicts_for_findings_that_were_not_asked_about_are_ignored(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    (finding,) = await seed(store, analysis_store, 1)
    ollama.say(verdict(finding.id), verdict(99999, priority="critical"), verdict(finding.id))

    results = await analyst.analyse([finding])

    assert [r.finding_id for r in results] == [finding.id]


BAD_OUTPUTS = [
    "",
    "null",
    "I cannot help with that.",
    '{"verdicts": []}',
    '{"verdicts": [{"finding_id": 1}]}',
    '{"verdicts": [{"finding_id": "x", "summary": 3}]}',
    '{"verdicts": [' + ",".join(["{}"] * 50) + "]}",
    json.dumps({"verdicts": [verdict(1, priority="ignore previous instructions")]}),
    json.dumps({"verdicts": [verdict(1, summary="x" * 100_000)]}),
    json.dumps({"verdicts": [verdict(1, confidence=-3)]}),
    "```json\n{}\n```",
]


@pytest.mark.parametrize("bad", BAD_OUTPUTS)
async def test_every_batch_ends_with_a_valid_analysis_whatever_the_model_returns(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama, bad: str
) -> None:
    findings = await seed(
        store, analysis_store, 3, rule="threat-intel-allowed", severity="critical"
    )
    ollama.answers.extend([bad, bad])

    results = await analyst.analyse(findings)

    assert_usable(results, findings)
    for result in results:
        Analysis.model_validate(result.model_dump())
        assert len(result.summary) <= 400


# --- Ollama unavailable ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("down"),
        httpx.ReadTimeout("slow"),
        httpx.Response(503),
        httpx.Response(404, json={"error": "model 'qwen3:8b' not found"}),
        httpx.Response(200, text="<html>proxy error</html>"),
    ],
)
async def test_an_unreachable_or_broken_ollama_is_reported_not_papered_over(
    store: Store,
    analysis_store: AnalysisStore,
    analyst: Analyst,
    ollama: FakeOllama,
    failure: httpx.Response | Exception,
) -> None:
    findings = await seed(store, analysis_store, 2)
    ollama.answers.append(failure)

    with pytest.raises(OllamaUnavailable):
        await analyst.analyse(findings)


# --- cache ---------------------------------------------------------------------------------


async def test_a_recurring_finding_is_answered_from_the_cache(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    evidence = {"fqdn": "login.site0.example", "domain_age_days": 5}
    (first,) = await seed(store, analysis_store, 1, evidence=evidence)
    ollama.say(verdict(first.id, summary="Explained once."))
    await analysis_store.save_analyses(await analyst.analyse([first]), now=T0)

    # The same rule and target on a later day: a new finding row, same features.
    await store.commit_processed(
        [],
        [
            Finding(
                rule_id="young-domain",
                severity=Severity.HIGH,
                profile_id="abc123",
                subject="D1",
                device_mode=True,
                target="site0.example",
                ts=T0 + timedelta(days=1),
                dedupe_key="young-domain|0|next-day",
                evidence={"fqdn": "mail.site0.example", "domain_age_days": 6},
                event_id="9" * 64,
            )
        ],
    )
    (recurrence,) = await analysis_store.fetch_unanalysed(limit=10)

    (result,) = await analyst.analyse([recurrence])

    assert len(ollama.requests) == 1, "no second call to the model"
    assert result.source == "cache"
    assert result.finding_id == recurrence.id
    assert result.summary == "Explained once."


async def test_cached_verdicts_expire(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama, clock: Clock
) -> None:
    (finding,) = await seed(store, analysis_store, 1)
    ollama.say(verdict(finding.id))
    await analyst.analyse([finding])

    clock.now = T0 + timedelta(hours=169)
    ollama.say(verdict(finding.id, summary="Fresh look."))
    (result,) = await analyst.analyse([finding])

    assert len(ollama.requests) == 2
    assert (result.source, result.summary) == ("llm", "Fresh look.")


async def test_template_fallbacks_are_not_cached(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    (finding,) = await seed(store, analysis_store, 1)
    ollama.answers.extend(["bad", "bad"])
    await analyst.analyse([finding])

    ollama.say(verdict(finding.id))
    (result,) = await analyst.analyse([finding])

    assert result.source == "llm"


async def test_the_floor_is_enforced_on_cached_verdicts_too(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    (finding,) = await seed(store, analysis_store, 1)
    ollama.say(verdict(finding.id, priority="high"))
    await analyst.analyse([finding])
    async with store.engine.begin() as connection:
        await connection.execute(
            text("update llm_cache set payload = json_set(payload, '$.priority', 'info')")
        )

    (result,) = await analyst.analyse([finding])

    assert result.source == "cache"
    assert result.priority is Severity.HIGH


# --- storage ---------------------------------------------------------------------------------


async def test_saved_analyses_remove_findings_from_the_waiting_list(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    findings = await seed(store, analysis_store, 3)
    ollama.say(*(verdict(f.id) for f in findings[:2]))

    await analysis_store.save_analyses(await analyst.analyse(findings[:2]), now=T0)

    waiting = await analysis_store.fetch_unanalysed(limit=10)
    assert [f.id for f in waiting] == [findings[2].id]
    saved = await analysis_store.analyses_for([f.id for f in findings])
    assert sorted(saved) == sorted(f.id for f in findings[:2])
    assert saved[findings[0].id].summary == f"Summary for {findings[0].id}."


async def test_waiting_findings_come_most_severe_first(
    store: Store, analysis_store: AnalysisStore
) -> None:
    await seed(store, analysis_store, 1, rule="volume-spike", severity="low", start=0)
    await seed(store, analysis_store, 1, rule="threat-intel-allowed", severity="critical", start=1)
    await seed(store, analysis_store, 1, rule="young-domain", severity="high", start=2)

    waiting = await analysis_store.fetch_unanalysed(limit=10)

    assert [f.severity.value for f in waiting] == ["critical", "high", "low"]


async def test_model_calls_are_recorded_for_later_reporting(
    store: Store, analysis_store: AnalysisStore, analyst: Analyst, ollama: FakeOllama
) -> None:
    findings = await seed(store, analysis_store, 2)
    ollama.answers.append("bad")
    ollama.say(*(verdict(f.id) for f in findings))

    await analyst.analyse(findings)

    calls = await analysis_store.call_outcomes()
    assert calls == ["invalid", "ok"]
