"""Stored results of ``vedette eval``."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from vedette.storage.models import eval_runs


@dataclass(frozen=True, slots=True)
class EvalRun:
    """One evaluation run: its numbers and the report as written."""

    id: int
    started_at: datetime
    finished_at: datetime
    summary: dict[str, Any]
    report: str


class EvalStore:
    """Saves evaluation runs and reads the latest one."""

    def __init__(self, engine: AsyncEngine) -> None:
        """Use the given database engine."""
        self._engine = engine

    async def save(
        self, *, started_at: datetime, finished_at: datetime, summary: dict[str, Any], report: str
    ) -> int:
        """Store a run; returns its id."""
        async with self._engine.begin() as connection:
            result = await connection.execute(
                eval_runs.insert().values(
                    started_at=started_at,
                    finished_at=finished_at,
                    summary=summary,
                    report=report,
                )
            )
            key = result.inserted_primary_key
            if key is None:  # pragma: no cover - SQLite always returns the new id
                raise RuntimeError("the database returned no id for the evaluation run")
            return int(key[0])

    async def latest(self) -> EvalRun | None:
        """The most recent run, if any."""
        async with self._engine.connect() as connection:
            row = (
                await connection.execute(select(eval_runs).order_by(eval_runs.c.id.desc()).limit(1))
            ).one_or_none()
        if row is None:
            return None
        return EvalRun(
            id=row.id,
            started_at=row.started_at,
            finished_at=row.finished_at,
            summary=dict(row.summary),
            report=row.report,
        )
