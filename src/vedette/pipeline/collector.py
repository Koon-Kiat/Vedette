"""Collector: keeps one profile's events flowing from a log source into storage.

Lifecycle for a profile:

1. No usable stream cursor: read history (the first time, the configured
   backfill window; later, from just before the last fully synced moment),
   then record the stream cursor captured at the start of that read.
2. Follow the live stream from the stored cursor, committing each event
   together with the cursor that follows it.
3. If the source rejects the cursor, forget it and go back to step 1.

Because history is stored idempotently and the resume point only moves once
data is safely on disk, the process can be killed at any moment without
leaving gaps or duplicates.
"""

import asyncio
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import structlog

from vedette.health.state import HealthState
from vedette.retry import backoff_delay
from vedette.sources.base import (
    LogSource,
    SourceAuthError,
    SourceError,
    SourceUnavailable,
    StreamCursorRejected,
    StreamIdle,
)
from vedette.storage.store import CollectorState, Store

log = structlog.get_logger(__name__)

GAP_OVERLAP = timedelta(minutes=5)
# A streamed event this recent means the stream has replayed whatever arrived
# while Vedette was off and is now live.
CAUGHT_UP_LAG = timedelta(minutes=5)
AUTH_RETRY_SECONDS = 300.0
ERROR_RETRY_SECONDS = 300.0
UNEXPECTED_RETRY_SECONDS = 30.0


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ProfileCollector:
    """Collects one profile's logs until cancelled."""

    def __init__(
        self,
        profile_id: str,
        source: LogSource,
        store: Store,
        *,
        backfill_days: int,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: Callable[[], float] = random.random,
        health: HealthState | None = None,
    ) -> None:
        """Create a collector.

        Args:
            profile_id: Profile to collect.
            source: Where logs come from.
            store: Where events and the resume state are kept.
            backfill_days: History window to read on the very first run.
            clock: Returns the current time (UTC); replaced in tests.
            sleep: Awaitable used to wait between attempts.
            rng: Random source for backoff jitter.
            health: Where to report whether the source is reachable.
        """
        self._profile_id = profile_id
        self._health = health
        self._source = source
        self._store = store
        self._backfill_days = backfill_days
        self._clock = clock
        self._sleep = sleep
        self._rng = rng
        self._failures = 0
        self._log = log.bind(profile_id=profile_id)

    async def run(self) -> None:
        """Collect forever. Cancel the task to stop; cancellation is always safe."""
        while True:
            delay = await self._attempt()
            await self._sleep(delay)

    def _source_ok(self) -> None:
        if self._health is not None:
            self._health.source_ok(self._profile_id, now=self._clock())

    def _caught_up(self) -> None:
        if self._health is not None:
            self._health.caught_up(self._profile_id)

    def _source_failed(self, reason: str) -> None:
        if self._health is not None:
            self._health.source_failed(self._profile_id, reason, now=self._clock())

    async def _attempt(self) -> float:
        """Run one backfill or one stream session; return seconds to wait next."""
        try:
            await self._cycle()
        except StreamIdle:
            self._log.info("collector_stream_idle")
            self._source_ok()
            self._caught_up()
        except StreamCursorRejected as exc:
            await self._store.clear_stream_cursor(self._profile_id)
            self._log.warning("collector_stream_cursor_rejected", reason=str(exc))
        except SourceAuthError as exc:
            self._log.error("collector_auth_failed", reason=str(exc))
            self._source_failed(str(exc))
            return AUTH_RETRY_SECONDS
        except SourceUnavailable as exc:
            delay = (
                exc.retry_after
                if exc.retry_after is not None
                else backoff_delay(self._failures, rng=self._rng)
            )
            self._failures += 1
            self._log.warning("collector_source_unavailable", reason=str(exc), retry_in=delay)
            self._source_failed(str(exc))
            return delay
        except SourceError as exc:
            self._log.error("collector_source_error", reason=str(exc))
            self._source_failed(str(exc))
            return ERROR_RETRY_SECONDS
        except Exception:  # noqa: BLE001 - must keep running unattended; logged with traceback
            self._log.exception("collector_unexpected_error")
            self._source_failed("unexpected error in the collector")
            return UNEXPECTED_RETRY_SECONDS
        delay = backoff_delay(self._failures, rng=self._rng)
        self._failures += 1
        return delay

    async def _cycle(self) -> None:
        state = await self._store.get_state(self._profile_id)
        if state is None or state.stream_cursor is None:
            await self._backfill(state)
            self._failures = 0
            return
        self._log.info("collector_stream_opening")
        async for item in self._source.stream(
            self._profile_id, state.stream_cursor, on_open=self._source_ok
        ):
            await self._store.save_stream_events(
                self._profile_id, [item.event], stream_cursor=item.cursor
            )
            self._failures = 0
            if item.event.ts >= self._clock() - CAUGHT_UP_LAG:
                self._caught_up()
        self._log.info("collector_stream_closed")

    async def _backfill(self, state: CollectorState | None) -> None:
        if state is not None and state.backfill_completed_at and state.synced_through:
            kind = "gap_fill"
            since = state.synced_through - GAP_OVERLAP
        else:
            kind = "initial"
            since = self._clock() - timedelta(days=self._backfill_days)
        self._log.info("collector_backfill_started", kind=kind, since=since.isoformat())

        stream_cursor: str | None = None
        newest = state.synced_through if state is not None else None
        pages = 0
        stored = 0
        async for page in self._source.backfill(self._profile_id, since):
            if stream_cursor is None and page.stream_cursor is not None:
                stream_cursor = page.stream_cursor
            stored += await self._store.save_events(page.events)
            pages += 1
            for item in page.events:
                if newest is None or item.ts > newest:
                    newest = item.ts
        if stream_cursor is None:
            raise SourceError("backfill finished without a stream cursor")
        await self._store.complete_backfill(
            self._profile_id, stream_cursor=stream_cursor, synced_through=newest
        )
        self._source_ok()
        self._caught_up()
        self._log.info("collector_backfill_completed", kind=kind, pages=pages, events_stored=stored)
