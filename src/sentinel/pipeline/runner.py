"""Starts the pipeline stages and stops them cleanly.

The stages are idle placeholders for now: each one starts, waits for the stop
signal and exits. Real stages replace them one at a time.
"""

import asyncio
import signal

import structlog

from sentinel.config import Settings

log = structlog.get_logger(__name__)

STAGE_NAMES: tuple[str, ...] = (
    "collector",
    "enricher",
    "rule_engine",
    "llm_analyst",
    "notifier",
    "health_monitor",
)


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
            for name in STAGE_NAMES:
                group.create_task(self._idle_stage(name, stop), name=name)
        log.info("pipeline_stopped")

    async def _idle_stage(self, name: str, stop: asyncio.Event) -> None:
        log.info("stage_started", stage=name, placeholder=True)
        await stop.wait()
        log.info("stage_stopped", stage=name)


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
