"""LLM analyst: explains and groups findings, and may only raise their priority.

For each finding the result is always a valid :class:`Analysis`:

1. a cached verdict for an equivalent earlier finding, if one is still fresh;
2. otherwise the model's verdict, validated against the schema, with one retry
   if the answer is invalid or leaves findings out;
3. otherwise a template built from the trusted rule definition.

Whatever the source, the priority is raised to the rule's floor if it is below
it, and all text is sanitised. The analyst never decides whether a finding
exists; rules did that before it ran.
"""

import time
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime, timedelta
from itertools import batched
from typing import Literal

import structlog
from pydantic import ValidationError

from vedette.llm.cache import cache_key
from vedette.llm.fallback import template_analysis
from vedette.llm.guards import enforce_floor, sanitize_model_text, slug
from vedette.llm.ollama import OllamaClient, OllamaUnavailable
from vedette.llm.prompts import SYSTEM_PROMPT, build_payload
from vedette.llm.schema import RESPONSE_SCHEMA, Analysis, Verdict, parse_verdicts
from vedette.rules.model import RuleSpec
from vedette.storage.analysis import AnalysisStore
from vedette.storage.store import StoredFinding

log = structlog.get_logger(__name__)

MAX_ATTEMPTS = 2  # the first try plus one retry

# Sizing a call to the model's context window. Measured on qwen3:8b: the JSON
# payload ran about 3 characters per token and each answer about 130 tokens.
# The allowances below are looser (names that tokenise badly, longer answers),
# and a tenth of the window stays free, so a call is never cut short.
CHARS_PER_TOKEN = 2.5
ANSWER_TOKENS = 200
CONTEXT_USE = 0.9


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Analyst:
    """Turns findings into stored explanations."""

    def __init__(
        self,
        client: OllamaClient,
        store: AnalysisStore,
        specs: Sequence[RuleSpec],
        *,
        max_batch: int,
        cache_ttl: timedelta,
        context_tokens: int | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        """Create an analyst.

        Args:
            client: The Ollama client.
            store: Where the verdict cache and call records live.
            specs: Rule definitions (trusted descriptions for the prompt).
            max_batch: Most findings sent to the model in one call.
            cache_ttl: How long a model verdict is reused; zero disables the cache.
            context_tokens: The model's context window (``num_ctx``). Calls are
                then also sized so the prompt and the answers fit in it; with
                None, only ``max_batch`` limits a call.
            clock: Returns the current time (UTC).
        """
        self._client = client
        self._store = store
        self._specs = {spec.id: spec for spec in specs}
        self._max_batch = max_batch
        self._cache_ttl = cache_ttl
        self._context_tokens = context_tokens
        self._clock = clock

    def _batches(self, pending: Sequence[StoredFinding]) -> Iterator[list[StoredFinding]]:
        """Split findings into calls of at most ``max_batch`` that fit the context window.

        A finding's share is its serialised length in tokens plus room for its
        answer. One finding too large for any call still goes alone; its
        evidence is capped by ``build_payload`` anyway.
        """
        if self._context_tokens is None:
            yield from (list(batch) for batch in batched(pending, self._max_batch, strict=False))
            return
        budget = self._context_tokens * CONTEXT_USE - len(SYSTEM_PROMPT) / CHARS_PER_TOKEN
        batch: list[StoredFinding] = []
        used = 0.0
        for finding in pending:
            cost = len(build_payload([finding], self._specs)) / CHARS_PER_TOKEN + ANSWER_TOKENS
            if batch and (len(batch) >= self._max_batch or used + cost > budget):
                yield batch
                batch, used = [], 0.0
            batch.append(finding)
            used += cost
        if batch:
            yield batch

    def _finish(
        self, finding: StoredFinding, verdict: Verdict, source: Literal["llm", "cache"]
    ) -> Analysis | None:
        """Apply the guards to a verdict; ``None`` if nothing usable is left."""
        try:
            return Analysis(
                finding_id=finding.id,
                summary=sanitize_model_text(verdict.summary, limit=400),
                likely_cause=sanitize_model_text(verdict.likely_cause, limit=300),
                recommended_action=sanitize_model_text(verdict.recommended_action, limit=300),
                priority=enforce_floor(verdict.priority, finding.severity),
                group_key=slug(verdict.group_key),
                confidence=verdict.confidence,
                source=source,
                model=self._client.model,
            )
        except ValidationError:
            return None

    async def _ask(self, batch: Sequence[StoredFinding]) -> dict[int, Verdict]:
        """Ask the model about a batch; return the valid verdicts it gave.

        Retries once when the answer is invalid or incomplete.
        """
        wanted = {finding.id for finding in batch}
        payload = build_payload(batch, self._specs)
        got: dict[int, Verdict] = {}
        for _ in range(MAX_ATTEMPTS):
            started_at = self._clock()
            started = time.monotonic()
            try:
                content = await self._client.chat_json(SYSTEM_PROMPT, payload, RESPONSE_SCHEMA)
            except OllamaUnavailable:
                await self._record(started_at, started, len(batch), "unavailable")
                raise
            try:
                verdicts = parse_verdicts(content)
            except ValueError:
                await self._record(started_at, started, len(batch), "invalid")
                continue
            for verdict in verdicts:
                if verdict.finding_id in wanted:
                    got.setdefault(verdict.finding_id, verdict)
            if wanted <= got.keys():
                await self._record(started_at, started, len(batch), "ok")
                break
            await self._record(started_at, started, len(batch), "incomplete")
        return got

    async def _record(
        self, started_at: datetime, started: float, findings: int, outcome: str
    ) -> None:
        await self._store.record_call(
            started_at=started_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            findings=findings,
            outcome=outcome,
            model=self._client.model,
        )

    async def analyse(self, findings: Sequence[StoredFinding]) -> list[Analysis]:
        """Explain every finding, in the order given.

        Raises:
            OllamaUnavailable: The model could not be reached. Nothing is
                returned so the caller can try again later; findings
                themselves are unaffected.
        """
        now = self._clock()
        model = self._client.model
        keys = {finding.id: cache_key(finding, model) for finding in findings}
        use_cache = self._cache_ttl > timedelta(0)
        cached = await self._store.cache_get(set(keys.values()), now) if use_cache else {}

        results: dict[int, Analysis] = {}
        pending: list[StoredFinding] = []
        for finding in findings:
            verdict = cached.get(keys[finding.id])
            analysis = (
                self._finish(
                    finding, verdict.model_copy(update={"finding_id": finding.id}), "cache"
                )
                if verdict is not None
                else None
            )
            if analysis is not None:
                results[finding.id] = analysis
            else:
                pending.append(finding)

        for batch in self._batches(pending):
            verdicts = await self._ask(batch)
            for finding in batch:
                verdict = verdicts.get(finding.id)
                analysis = self._finish(finding, verdict, "llm") if verdict is not None else None
                if analysis is None:
                    results[finding.id] = template_analysis(
                        finding, self._specs.get(finding.rule_id)
                    )
                    continue
                results[finding.id] = analysis
                if use_cache:
                    await self._store.cache_put(
                        keys[finding.id], analysis, now=now, expires_at=now + self._cache_ttl
                    )

        sources = [results[finding.id].source for finding in findings]
        log.info(
            "findings_analysed",
            count=len(findings),
            llm=sources.count("llm"),
            cache=sources.count("cache"),
            template=sources.count("template"),
        )
        return [results[finding.id] for finding in findings]
