"""The scheduled purge: removes data older than the configured retention."""

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncEngine

from vedette.storage.retention import purge_expired

log = structlog.get_logger(__name__)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RetentionWorker:
    """Runs the retention purge shortly after start-up and then every hour."""

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        events_days: int,
        findings_days: int,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        first_delay_seconds: float = 60.0,
        interval_seconds: float = 3600.0,
    ) -> None:
        """Create the worker.

        Args:
            engine: The database to purge.
            events_days: Raw events older than this many days are deleted.
            findings_days: Findings (and what came from them) older than this
                many days are deleted.
            clock: Returns the current time (UTC).
            sleep: Awaitable used between runs.
            first_delay_seconds: Wait before the first purge, so start-up work
                (backfill, warm-up) goes first.
            interval_seconds: Time between purges.
        """
        self._engine = engine
        self._events_days = events_days
        self._findings_days = findings_days
        self._clock = clock
        self._sleep = sleep
        self._first_delay = first_delay_seconds
        self._interval = interval_seconds

    async def purge_once(self) -> int:
        """Run one purge and log what it removed. Returns the rows removed."""
        purged = await purge_expired(
            self._engine,
            now=self._clock(),
            events_days=self._events_days,
            findings_days=self._findings_days,
        )
        if purged.total:
            log.info("retention_purged", rows=purged.total, **purged.counts)
        return purged.total

    async def run(self) -> None:
        """Run forever. Cancel the task to stop."""
        await self._sleep(self._first_delay)
        while True:
            try:
                await self.purge_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - logged, and retried at the next interval
                log.error("retention_purge_failed", error=type(exc).__name__, detail=str(exc)[:200])
            await self._sleep(self._interval)
