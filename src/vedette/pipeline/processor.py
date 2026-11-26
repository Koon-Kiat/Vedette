"""Enricher and rule-engine workers.

The enricher reads stored events that have not been through the rules yet,
oldest first, enriches a batch and publishes it on the queue. The rule worker
consumes the batch, evaluates every rule, and in one transaction stores the
findings and marks the events processed. A crash before that commit leaves the
events unprocessed, so they are simply enriched and evaluated again; nothing
is lost and nothing is counted twice.

Reading from storage (instead of receiving events straight from the collector)
also puts history, which the collector receives newest first, back in
chronological order. A profile is only processed while its collector holds a
stream cursor, that is, when no backfill is in flight.
"""

import asyncio
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol

import structlog

from vedette.enrich.enricher import Enricher
from vedette.enrich.model import EnrichedEvent
from vedette.pipeline.queue import EventQueue
from vedette.rules.engine import RuleEngine
from vedette.shared.models import Finding
from vedette.storage.store import Store

log = structlog.get_logger(__name__)

UNEXPECTED_RETRY_SECONDS = 30.0
REFRESH_CHECK_SECONDS = 600.0

type Batch = list[EnrichedEvent]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Refreshable(Protocol):
    """Reference data that can refresh itself when it is stale."""

    async def refresh_if_stale(self, now: datetime) -> bool:
        """Refresh if due; return whether anything changed."""
        ...


class EnricherWorker:
    """Feeds enriched batches to the rule worker, one at a time."""

    def __init__(
        self,
        profile_ids: Sequence[str],
        store: Store,
        enricher: Enricher,
        references: Sequence[Refreshable],
        queue: EventQueue[Batch],
        *,
        batch_size: int = 500,
        idle_seconds: float = 2.0,
        clock: Callable[[], datetime] = _utc_now,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Create the worker.

        Args:
            profile_ids: Profiles to process.
            store: Event storage.
            enricher: Adds context to events.
            references: Reference data to keep fresh (popularity, threat feeds).
            queue: Where enriched batches are published.
            batch_size: Events per batch.
            idle_seconds: Pause when there is nothing to do.
            clock: Returns the current time (UTC).
            sleep: Awaitable used for pauses.
        """
        self._profile_ids = tuple(profile_ids)
        self._store = store
        self._enricher = enricher
        self._references = tuple(references)
        self._queue = queue
        self._batch_size = batch_size
        self._idle_seconds = idle_seconds
        self._clock = clock
        self._sleep = sleep
        self._next_refresh_check = 0.0

    async def run(self) -> None:
        """Process forever. Cancel the task to stop."""
        while True:
            try:
                worked = await self._pass()
            except Exception:  # must keep running unattended; logged with traceback
                log.exception("enricher_unexpected_error")
                await self._sleep(UNEXPECTED_RETRY_SECONDS)
                continue
            if not worked:
                await self._sleep(self._idle_seconds)

    async def _refresh_references(self, now: datetime) -> None:
        if time.monotonic() < self._next_refresh_check:
            return
        for reference in self._references:
            await reference.refresh_if_stale(now)
        self._next_refresh_check = time.monotonic() + REFRESH_CHECK_SECONDS

    async def _pass(self) -> bool:
        """Publish at most one batch per profile; return whether any was published."""
        now = self._clock()
        await self._refresh_references(now)
        worked = False
        for profile_id in self._profile_ids:
            state = await self._store.get_state(profile_id)
            if state is None or state.stream_cursor is None:
                continue
            events = await self._store.fetch_unprocessed(profile_id, limit=self._batch_size)
            if not events:
                continue
            await self._queue.publish(await self._enricher.enrich_batch(events, now))
            while await self._queue.depth() > 0:  # noqa: ASYNC110 - queue has no drained event
                await asyncio.sleep(0.005)
            worked = True
        return worked


class RuleWorker:
    """Evaluates rules on enriched batches and stores the findings."""

    def __init__(
        self,
        profile_ids: Sequence[str],
        store: Store,
        engine: RuleEngine,
        queue: EventQueue[Batch],
        *,
        warm_up: timedelta,
        clock: Callable[[], datetime] = _utc_now,
        allowlist_refresh: Callable[[], Awaitable[None]] | None = None,
        refresh_seconds: float = 30.0,
    ) -> None:
        """Create the worker.

        Args:
            profile_ids: Profiles being processed.
            store: Event and finding storage.
            engine: The rule engine.
            queue: Where enriched batches arrive.
            warm_up: How much processed history to replay into the engine at
                start, so its windows and baselines survive a restart.
            clock: Returns the current time (UTC).
            allowlist_refresh: Reloads the engine's allowlist (configured plus
                stored entries), so "mark benign" takes effect without a restart.
            refresh_seconds: Reload at most this often, checked before each batch.
        """
        self._profile_ids = tuple(profile_ids)
        self._store = store
        self._engine = engine
        self._queue = queue
        self._warm_up = warm_up
        self._clock = clock
        self._allowlist_refresh = allowlist_refresh
        self._refresh_seconds = refresh_seconds
        self._refreshed_at: float | None = None

    async def _restore_engine_state(self) -> None:
        since = self._clock() - self._warm_up
        replayed = 0
        for profile_id in self._profile_ids:
            earliest = await self._store.earliest_event_ts(profile_id)
            if earliest is not None:
                self._engine.set_profile_start(profile_id, earliest)
            async for fields in self._store.iter_processed_fields(profile_id, since=since):
                self._engine.observe_fields(*fields)
                replayed += 1
        log.info("rule_engine_warmed_up", events_replayed=replayed)

    async def _refresh_allowlist(self) -> None:
        if self._allowlist_refresh is None:
            return
        now = time.monotonic()
        if self._refreshed_at is not None and now - self._refreshed_at < self._refresh_seconds:
            return
        await self._allowlist_refresh()
        self._refreshed_at = now

    async def run(self) -> None:
        """Process forever. Cancel the task to stop.

        An unexpected error is not swallowed here: engine state would no
        longer match storage, so the process exits and restarts clean.
        """
        await self._restore_engine_state()
        while True:
            for message in await self._queue.consume(max_items=1, wait_seconds=1.0):
                await self._refresh_allowlist()
                found: list[Finding] = []
                for item in message.payload:
                    found.extend(self._engine.evaluate(item))
                await self._store.commit_processed(
                    [item.event.event_id for item in message.payload], found
                )
                await self._queue.ack([message.id])
                if found:
                    log.info(
                        "findings_recorded",
                        count=len(found),
                        by_rule=dict(Counter(finding.rule_id for finding in found)),
                    )
