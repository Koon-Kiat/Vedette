"""Starts the pipeline stages and stops them cleanly.

The collector is real. The remaining stages are idle placeholders: each one
starts, waits for the stop signal and exits. Real stages replace them one at a
time.
"""

import asyncio
import signal

import structlog

from sentinel.config import Settings
from sentinel.pipeline.collector import ProfileCollector
from sentinel.sources.nextdns import NextDnsSource
from sentinel.storage.migrate import run_migrations
from sentinel.storage.store import Store

log = structlog.get_logger(__name__)

STAGE_NAMES: tuple[str, ...] = (
    "collector",
    "enricher",
    "rule_engine",
    "llm_analyst",
    "notifier",
    "health_monitor",
)
_PLACEHOLDER_STAGES = STAGE_NAMES[1:]


class Pipeline:
    """The set of long-running stages that make up the Sentinel."""

    def __init__(self, settings: Settings) -> None:
        """Create a pipeline for the given settings."""
        self._settings = settings

    async def run(self, stop: asyncio.Event) -> None:
        """Run every stage until ``stop`` is set, then wait for them to finish."""
        log.info(
            "pipeline_started",
            enabled_profiles=[profile.label for profile in self._settings.enabled_profiles],
            stages=list(STAGE_NAMES),
        )
        async with asyncio.TaskGroup() as group:
            group.create_task(self._collector_stage(stop), name="collector")
            for name in _PLACEHOLDER_STAGES:
                group.create_task(self._idle_stage(name, stop), name=name)
        log.info("pipeline_stopped")

    async def _idle_stage(self, name: str, stop: asyncio.Event) -> None:
        log.info("stage_started", stage=name, placeholder=True)
        await stop.wait()
        log.info("stage_stopped", stage=name)

    def _collector_blocker(self) -> str | None:
        """Why the collector cannot run, or ``None`` if it can."""
        if self._settings.nextdns_api_key is None:
            return "NEXTDNS_API_KEY is not set"
        if not self._settings.enabled_profiles:
            return "no profile is enabled"
        return None

    async def _collector_stage(self, stop: asyncio.Event) -> None:
        log.info("stage_started", stage="collector", placeholder=False)
        blocker = self._collector_blocker()
        if blocker is not None:
            log.warning("collector_idle", reason=blocker)
            await stop.wait()
        else:
            await self._collect_until(stop)
        log.info("stage_stopped", stage="collector")

    async def _collect_until(self, stop: asyncio.Event) -> None:
        """Run one collector per enabled profile until ``stop`` is set."""
        settings = self._settings
        if settings.nextdns_api_key is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("collector started without an API key")
        database_url = settings.storage.database_url
        await asyncio.to_thread(run_migrations, database_url)
        store = Store.open(database_url)
        source = NextDnsSource(
            settings.nextdns_api_key.get_secret_value(),
            raw=settings.ingest.raw,
            page_size=settings.ingest.page_size,
        )
        try:
            async with asyncio.TaskGroup() as group:
                tasks = [
                    group.create_task(
                        ProfileCollector(
                            profile.id,
                            source,
                            store,
                            backfill_days=settings.ingest.backfill_days,
                        ).run(),
                        name=f"collector:{profile.label}",
                    )
                    for profile in settings.enabled_profiles
                ]
                await stop.wait()
                for task in tasks:
                    task.cancel()
        finally:
            await source.aclose()
            await store.close()


async def run_until_signalled(settings: Settings) -> None:
    """Run the pipeline until the process receives SIGINT or SIGTERM."""
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_shutdown(signal_name: str) -> None:
        log.info("shutdown_requested", signal=signal_name)
        stop.set()

    handled = (signal.SIGINT, signal.SIGTERM)
    for sig in handled:
        loop.add_signal_handler(sig, request_shutdown, sig.name)
    try:
        await Pipeline(settings).run(stop)
    finally:
        for sig in handled:
            loop.remove_signal_handler(sig)
