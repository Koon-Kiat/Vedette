"""Analyst worker: keeps stored findings explained by the local model.

It polls for findings that have no analysis yet, most severe first, sends them
to the analyst in batches and stores the result. Findings exist and can alert
whether or not this stage is working: if Ollama is unreachable the worker
waits and tries again, and nothing is invented in the meantime.
"""

import asyncio
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import structlog

from sentinel.llm.analyst import Analyst
from sentinel.llm.ollama import OllamaUnavailable
from sentinel.retry import backoff_delay
from sentinel.storage.analysis import AnalysisStore

log = structlog.get_logger(__name__)

UNEXPECTED_RETRY_SECONDS = 30.0
MAX_UNAVAILABLE_WAIT_SECONDS = 300.0


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AnalystWorker:
    """Runs the analyst over findings as they appear."""

    def __init__(
        self,
        store: AnalysisStore,
        analyst: Analyst,
        *,
        batch_size: int,
        idle_seconds: float = 5.0,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        """Create the worker.

        Args:
            store: Where findings wait and analyses are stored.
            analyst: Explains findings.
            batch_size: Findings handled per pass.
            idle_seconds: Pause when nothing is waiting.
            clock: Returns the current time (UTC).
            sleep: Awaitable used for pauses.
            rng: Random source for backoff jitter.
        """
        self._store = store
        self._analyst = analyst
        self._batch_size = batch_size
        self._idle_seconds = idle_seconds
        self._clock = clock
        self._sleep = sleep
        self._rng = rng
        self._failures = 0

    async def run(self) -> None:
        """Analyse forever. Cancel the task to stop."""
        while True:
            await self._sleep(await self._pass())

    async def _pass(self) -> float:
        """Handle one batch; return seconds to wait before the next."""
        try:
            waiting = await self._store.fetch_unanalysed(limit=self._batch_size)
            if not waiting:
                return self._idle_seconds
            analyses = await self._analyst.analyse(waiting)
            await self._store.save_analyses(analyses, now=self._clock())
        except OllamaUnavailable as exc:
            delay = backoff_delay(
                self._failures, base=5.0, cap=MAX_UNAVAILABLE_WAIT_SECONDS, rng=self._rng
            )
            self._failures += 1
            log.warning("analyst_ollama_unavailable", reason=str(exc), retry_in=delay)
            return delay
        except Exception:  # must keep running unattended; logged with traceback
            log.exception("analyst_unexpected_error")
            return UNEXPECTED_RETRY_SECONDS
        self._failures = 0
        return 0.0
