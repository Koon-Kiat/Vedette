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

import json
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from itertools import batched
from typing import Any, Literal

import structlog
from pydantic import ValidationError

from vedette.llm.cache import cache_key
from vedette.llm.context import ContextSource
from vedette.llm.fallback import template_analysis
from vedette.llm.guards import (
    cited_keys,
    echoed_vouching,
    enforce_floor,
    grounded_leaning,
    payload_keys,
    remove_names,
    sanitize_list,
    sanitize_model_text,
    slug,
    unsupported_names,
)
from vedette.llm.ollama import OllamaClient, OllamaUnavailable
from vedette.llm.prompts import (
    MAX_CHECKS,
    MAX_EVIDENCE_USED,
    MAX_EXPLANATIONS,
    build_payload,
    payload_items,
    serialise,
    system_prompt,
)
from vedette.llm.schema import RESPONSE_SCHEMA, parse_verdicts
from vedette.rules.model import RuleSpec
from vedette.shared.defang import defang
from vedette.shared.models import Analysis, Verdict
from vedette.storage.analysis import AnalysisStore
from vedette.storage.store import StoredFinding

log = structlog.get_logger(__name__)

MAX_ATTEMPTS = 2  # the first try plus one retry

# Sizing a call to the model's context window. Measured on qwen3:8b: the JSON
# payload ran about 3 characters per token, and each answer about 140 tokens
# before the leaning, the lists and the checks were added and about 200 after.
# The allowances below are looser (names that tokenise badly, longer answers),
# and a tenth of the window stays free, so a call is never cut short.
CHARS_PER_TOKEN = 2.5
ANSWER_TOKENS = 300
CONTEXT_USE = 0.9
#: Longest item kept in an answer's lists.
MAX_ITEM = 160


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _texts(verdict: Verdict) -> tuple[str, ...]:
    """Every piece of text in a verdict that the owner reads."""
    return (
        verdict.summary,
        verdict.likely_cause,
        verdict.recommended_action,
        *verdict.harmless_explanations,
        *verdict.malicious_explanations,
        *verdict.checks,
    )


def _without_names(verdict: Verdict, names: Sequence[str]) -> Verdict:
    """The verdict with each of ``names`` taken out of its text."""
    return verdict.model_copy(
        update={
            "summary": remove_names(verdict.summary, names),
            "likely_cause": remove_names(verdict.likely_cause, names),
            "recommended_action": remove_names(verdict.recommended_action, names),
            "harmless_explanations": tuple(
                remove_names(text, names) for text in verdict.harmless_explanations
            ),
            "malicious_explanations": tuple(
                remove_names(text, names) for text in verdict.malicious_explanations
            ),
            "checks": tuple(remove_names(text, names) for text in verdict.checks),
        }
    )


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
        context: ContextSource | None = None,
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
            context: Builds the records around each finding sent to the model;
                without it, findings go with their evidence only.
            clock: Returns the current time (UTC).
        """
        self._client = client
        self._store = store
        self._specs = {spec.id: spec for spec in specs}
        self._max_batch = max_batch
        self._cache_ttl = cache_ttl
        self._context_tokens = context_tokens
        self._context = context
        self._clock = clock

    def _batches(
        self, pending: Sequence[StoredFinding], contexts: Mapping[int, dict[str, Any]]
    ) -> Iterator[list[StoredFinding]]:
        """Split findings into calls of at most ``max_batch`` that fit the context window.

        A finding's share is its serialised length in tokens plus room for its
        answer. One finding too large for any call still goes alone; its
        evidence is capped by ``build_payload`` anyway.
        """
        if self._context_tokens is None:
            yield from (list(batch) for batch in batched(pending, self._max_batch, strict=False))
            return
        longest = system_prompt(self._specs, self._specs)
        budget = self._context_tokens * CONTEXT_USE - len(longest) / CHARS_PER_TOKEN
        batch: list[StoredFinding] = []
        used = 0.0
        for finding in pending:
            payload = build_payload([finding], self._specs, contexts)
            cost = len(payload) / CHARS_PER_TOKEN + ANSWER_TOKENS
            if batch and (len(batch) >= self._max_batch or used + cost > budget):
                yield batch
                batch, used = [], 0.0
            batch.append(finding)
            used += cost
        if batch:
            yield batch

    def _finish(
        self,
        finding: StoredFinding,
        verdict: Verdict,
        source: Literal["llm", "cache"],
        given: Mapping[str, Any] | None = None,
        removed: tuple[str, ...] = (),
    ) -> Analysis | None:
        """Apply the guards to a verdict; ``None`` if nothing usable is left.

        An answer that repeats a vouching word the finding's own names use
        (benign, false positive, verified) is not used: the name has steered it.

        ``given`` is the finding as the model was given it. Any domain name the
        answer writes that is not in it is taken out of the text and recorded,
        and only evidence fields the finding has are kept as cited. A cached
        verdict went through both when it was stored, so it comes without
        ``given`` and with the names taken out then in ``removed``. A harmless
        leaning that cites no record becomes unclear.
        """
        echoed = echoed_vouching(_texts(verdict), finding.target, finding.evidence)
        if echoed:
            log.warning("analysis_echoed_name", finding_id=finding.id, words=echoed)
            return None
        cited = verdict.evidence_used[:MAX_EVIDENCE_USED]
        if given is not None:
            names = unsupported_names(_texts(verdict), json.dumps(given, ensure_ascii=True))
            if names:
                log.warning(
                    "analysis_named_unknown_domains", finding_id=finding.id, names=len(names)
                )
                verdict = _without_names(verdict, names)
            removed = tuple(defang(name) for name in names)
            cited = cited_keys(verdict.evidence_used, payload_keys(given), limit=MAX_EVIDENCE_USED)
        assessment = grounded_leaning(verdict.assessment, cited)
        if assessment != verdict.assessment:
            log.info("analysis_leaning_ungrounded", finding_id=finding.id)
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
                assessment=assessment,
                harmless=sanitize_list(
                    verdict.harmless_explanations, items_limit=MAX_EXPLANATIONS, limit=MAX_ITEM
                ),
                malicious=sanitize_list(
                    verdict.malicious_explanations, items_limit=MAX_EXPLANATIONS, limit=MAX_ITEM
                ),
                checks=sanitize_list(verdict.checks, items_limit=MAX_CHECKS, limit=MAX_ITEM),
                evidence_used=cited,
                removed_names=removed,
            )
        except ValidationError:
            return None

    async def _ask(
        self, batch: Sequence[StoredFinding], given: Mapping[int, dict[str, Any]]
    ) -> dict[int, Verdict]:
        """Ask the model about a batch; return the valid verdicts it gave.

        ``given`` holds each finding as the model is given it. Retries once
        when the answer is invalid or incomplete.
        """
        wanted = {finding.id for finding in batch}
        payload = serialise([given[finding.id] for finding in batch])
        system = system_prompt(self._specs, (finding.rule_id for finding in batch))
        got: dict[int, Verdict] = {}
        for _ in range(MAX_ATTEMPTS):
            started_at = self._clock()
            started = time.monotonic()
            try:
                content = await self._client.chat_json(system, payload, RESPONSE_SCHEMA)
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
            hit = cached.get(keys[finding.id])
            analysis = (
                self._finish(
                    finding,
                    hit.verdict.model_copy(update={"finding_id": finding.id}),
                    "cache",
                    removed=hit.removed_names,
                )
                if hit is not None
                else None
            )
            if analysis is not None:
                results[finding.id] = analysis
            else:
                pending.append(finding)

        contexts = await self._context.packs(pending) if self._context and pending else {}
        for batch in self._batches(pending, contexts):
            given = {
                item["finding_id"]: item for item in payload_items(batch, self._specs, contexts)
            }
            verdicts = await self._ask(batch, given)
            for finding in batch:
                verdict = verdicts.get(finding.id)
                analysis = (
                    self._finish(finding, verdict, "llm", given[finding.id])
                    if verdict is not None
                    else None
                )
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
