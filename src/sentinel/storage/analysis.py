"""Storage for the LLM stage: analyses, the verdict cache and call records."""

from collections.abc import Collection, Sequence
from datetime import datetime
from itertools import batched

from pydantic import ValidationError
from sqlalchemy import case, delete, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from sentinel.llm.schema import Analysis, Verdict
from sentinel.rules.model import Severity
from sentinel.storage.models import finding_analysis, findings, llm_cache, llm_calls
from sentinel.storage.store import StoredFinding, finding_from_row

_IN_CHUNK = 500


class AnalysisStore:
    """Reads and writes what the LLM analyst needs and produces."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Use the given database engine (shared with the event store)."""
        self._engine = engine

    # --- analyses -------------------------------------------------------------------

    async def fetch_unanalysed(self, *, limit: int) -> list[StoredFinding]:
        """Findings without an analysis yet: most severe first, then newest."""
        rank = case(
            {level.value: level.rank for level in Severity}, value=findings.c.severity, else_=0
        )
        statement = (
            select(findings)
            .outerjoin(finding_analysis, finding_analysis.c.finding_id == findings.c.id)
            .where(finding_analysis.c.finding_id.is_(None))
            .order_by(rank.desc(), findings.c.last_ts.desc(), findings.c.id.desc())
            .limit(limit)
        )
        async with self._engine.connect() as connection:
            rows = (await connection.execute(statement)).all()
        return [finding_from_row(row) for row in rows]

    async def save_analyses(self, analyses: Sequence[Analysis], *, now: datetime) -> None:
        """Store analyses, replacing any earlier one for the same finding."""
        if not analyses:
            return
        statement = sqlite_insert(finding_analysis)
        rows = [
            {
                "finding_id": item.finding_id,
                "summary": item.summary,
                "likely_cause": item.likely_cause,
                "recommended_action": item.recommended_action,
                "priority": item.priority.value,
                "group_key": item.group_key,
                "confidence": item.confidence,
                "source": item.source,
                "model": item.model,
                "created_at": now,
            }
            for item in analyses
        ]
        updatable = [name for name in rows[0] if name != "finding_id"]
        async with self._engine.begin() as connection:
            await connection.execute(
                statement.on_conflict_do_update(
                    index_elements=["finding_id"],
                    set_={name: statement.excluded[name] for name in updatable},
                ),
                rows,
            )

    async def analyses_for(self, finding_ids: Collection[int]) -> dict[int, Analysis]:
        """Stored analyses for the given findings, by finding id."""
        found: dict[int, Analysis] = {}
        async with self._engine.connect() as connection:
            for chunk in batched(finding_ids, _IN_CHUNK, strict=False):
                rows = await connection.execute(
                    select(finding_analysis).where(finding_analysis.c.finding_id.in_(chunk))
                )
                for row in rows:
                    found[row.finding_id] = Analysis(
                        finding_id=row.finding_id,
                        summary=row.summary,
                        likely_cause=row.likely_cause,
                        recommended_action=row.recommended_action,
                        priority=Severity(row.priority),
                        group_key=row.group_key,
                        confidence=row.confidence,
                        source=row.source,
                        model=row.model,
                    )
        return found

    # --- verdict cache ----------------------------------------------------------------

    async def cache_get(self, keys: Collection[str], now: datetime) -> dict[str, Verdict]:
        """Unexpired cached verdicts for the given keys.

        An entry that no longer validates is treated as absent.
        """
        found: dict[str, Verdict] = {}
        async with self._engine.connect() as connection:
            for chunk in batched(keys, _IN_CHUNK, strict=False):
                rows = await connection.execute(
                    select(llm_cache.c.cache_key, llm_cache.c.payload).where(
                        llm_cache.c.cache_key.in_(chunk), llm_cache.c.expires_at > now
                    )
                )
                for row in rows:
                    try:
                        found[row.cache_key] = Verdict.model_validate(
                            {**row.payload, "finding_id": 0}
                        )
                    except ValidationError:
                        continue
        return found

    async def cache_put(
        self, key: str, analysis: Analysis, *, now: datetime, expires_at: datetime
    ) -> None:
        """Cache a model verdict (already sanitised) until ``expires_at``."""
        payload = {
            "summary": analysis.summary,
            "likely_cause": analysis.likely_cause,
            "recommended_action": analysis.recommended_action,
            "priority": analysis.priority.value,
            "group_key": analysis.group_key,
            "confidence": analysis.confidence,
        }
        statement = sqlite_insert(llm_cache).values(
            cache_key=key,
            payload=payload,
            model=analysis.model or "",
            created_at=now,
            expires_at=expires_at,
        )
        async with self._engine.begin() as connection:
            await connection.execute(
                statement.on_conflict_do_update(
                    index_elements=["cache_key"],
                    set_={
                        "payload": payload,
                        "model": analysis.model or "",
                        "created_at": now,
                        "expires_at": expires_at,
                    },
                )
            )

    async def purge_expired_cache(self, now: datetime) -> None:
        """Delete cache entries that have expired."""
        async with self._engine.begin() as connection:
            await connection.execute(delete(llm_cache).where(llm_cache.c.expires_at <= now))

    # --- call records -------------------------------------------------------------------

    async def record_call(
        self, *, started_at: datetime, duration_ms: int, findings: int, outcome: str, model: str
    ) -> None:
        """Record one call to the model: ``ok``, ``invalid``, ``incomplete`` or ``unavailable``."""
        async with self._engine.begin() as connection:
            await connection.execute(
                llm_calls.insert().values(
                    started_at=started_at,
                    duration_ms=duration_ms,
                    findings=findings,
                    outcome=outcome,
                    model=model,
                )
            )

    async def call_outcomes(self) -> list[str]:
        """Outcome of every recorded model call, oldest first."""
        async with self._engine.connect() as connection:
            rows = await connection.execute(select(llm_calls.c.outcome).order_by(llm_calls.c.id))
            return [row.outcome for row in rows]
