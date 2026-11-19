"""Starts the pipeline stages and stops them cleanly.

All six stages run: collector, enricher, rule engine, LLM analyst, notifier
and health monitor, plus the ``/healthz`` endpoint on the loopback interface.
"""

import asyncio
import signal
from datetime import timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import structlog
from sqlalchemy.engine import make_url

from sentinel import __version__
from sentinel.config import Settings
from sentinel.enrich.enricher import Enricher
from sentinel.enrich.first_seen import FirstSeenTracker
from sentinel.enrich.popularity import PopularityList
from sentinel.enrich.rdap import DomainAges, RdapClient
from sentinel.enrich.threat_intel import ThreatIntel
from sentinel.health.monitor import HealthMonitor, OllamaProbe
from sentinel.health.server import start_health_server
from sentinel.health.state import HealthState
from sentinel.llm.analyst import Analyst
from sentinel.llm.ollama import OllamaClient
from sentinel.notify.digest import DigestBuilder
from sentinel.notify.factory import build_channel
from sentinel.notify.schedule import QuietHours, parse_clock
from sentinel.pipeline.analyst import AnalystWorker
from sentinel.pipeline.collector import ProfileCollector
from sentinel.pipeline.notifier import AlertWorker, DeliveryWorker, DigestScheduler
from sentinel.pipeline.processor import Batch, EnricherWorker, RuleWorker
from sentinel.pipeline.queue import MemoryQueue
from sentinel.rules.allowlist import Allowlist
from sentinel.rules.engine import RuleEngine
from sentinel.rules.loader import load_rules
from sentinel.sources.nextdns import NextDnsSource
from sentinel.storage.analysis import AnalysisStore
from sentinel.storage.health import HealthStore
from sentinel.storage.migrate import run_migrations
from sentinel.storage.notifications import NotificationStore
from sentinel.storage.reference import ReferenceStore
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
_ACTIVE_STAGES = STAGE_NAMES
_PLACEHOLDER_STAGES: tuple[str, ...] = ()


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
            group.create_task(self._active_stages(stop), name="active-stages")
            for name in _PLACEHOLDER_STAGES:
                group.create_task(self._idle_stage(name, stop), name=name)
        log.info("pipeline_stopped")

    async def _idle_stage(self, name: str, stop: asyncio.Event) -> None:
        log.info("stage_started", stage=name, placeholder=True)
        await stop.wait()
        log.info("stage_stopped", stage=name)

    def _blocker(self) -> str | None:
        """Why the collector cannot run, or ``None`` if it can."""
        if self._settings.nextdns_api_key is None:
            return "NEXTDNS_API_KEY is not set"
        if not self._settings.enabled_profiles:
            return "no profile is enabled"
        return None

    async def _active_stages(self, stop: asyncio.Event) -> None:
        for name in _ACTIVE_STAGES:
            log.info("stage_started", stage=name, placeholder=False)
        blocker = self._blocker()
        if blocker is not None:
            log.warning("collector_idle", reason=blocker)
            await stop.wait()
        else:
            await self._work_until(stop)
        for name in _ACTIVE_STAGES:
            log.info("stage_stopped", stage=name)

    async def _work_until(self, stop: asyncio.Event) -> None:
        """Run every stage until ``stop`` is set."""
        settings = self._settings
        if settings.nextdns_api_key is None:  # pragma: no cover - guarded by the caller
            raise RuntimeError("pipeline started without an API key")
        profiles = settings.enabled_profiles
        profile_ids = [profile.id for profile in profiles]
        specs = load_rules(settings.rules.file)

        database_url = settings.storage.database_url
        await asyncio.to_thread(run_migrations, database_url)
        store = Store.open(database_url)
        source = NextDnsSource(
            settings.nextdns_api_key.get_secret_value(),
            raw=settings.ingest.raw,
            page_size=settings.ingest.page_size,
        )
        # Used only for reference data (top-sites list, threat feeds, RDAP).
        # It never carries the NextDNS API key.
        web = httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(60.0),
            headers={"User-Agent": f"nextdns-sentinel/{__version__}"},
        )
        llm = settings.llm
        # The model gets no tools; this client only ever posts chat requests to Ollama.
        ollama = OllamaClient(
            llm.base_url,
            model=llm.model,
            think=llm.think,
            temperature=llm.temperature,
            num_ctx=llm.num_ctx,
            keep_alive=llm.keep_alive,
        )
        probe = OllamaProbe(llm.base_url, llm.model)
        channel = build_channel(settings)
        healthz: asyncio.Server | None = None
        try:
            reference = ReferenceStore(store.engine)
            enrich = settings.enrich
            popularity = PopularityList(
                reference,
                web,
                url=enrich.popularity.url,
                refresh_days=enrich.popularity.refresh_days,
            )
            await popularity.load()
            threat_intel = ThreatIntel(
                reference,
                web,
                feeds=enrich.threat_intel.feeds,
                refresh_hours=enrich.threat_intel.refresh_hours,
            )
            rdap = (
                RdapClient(web, bootstrap_url=enrich.rdap.bootstrap_url)
                if enrich.rdap.enabled
                else None
            )
            enricher = Enricher(
                popularity=popularity,
                threat_intel=threat_intel,
                ages=DomainAges(reference, rdap),
                first_seen=await FirstSeenTracker.load(reference),
                rdap_max_event_age=timedelta(hours=enrich.rdap.max_event_age_hours),
                rdap_max_lookups_per_batch=enrich.rdap.max_lookups_per_batch,
            )
            engine = RuleEngine(
                specs,
                allowlist=Allowlist(
                    settings.allowlist, labels={profile.id: profile.label for profile in profiles}
                ),
                learning=timedelta(days=settings.rules.learning_days),
            )
            baseline_hours = max(
                (int(spec.params.get("baseline_hours", 0)) for spec in specs), default=0
            )
            analysis_store = AnalysisStore(store.engine)
            analyst = Analyst(
                ollama,
                analysis_store,
                specs,
                max_batch=llm.max_findings_per_batch,
                cache_ttl=timedelta(hours=llm.cache_ttl_hours),
            )
            queue: MemoryQueue[Batch] = MemoryQueue()
            tz = ZoneInfo(settings.timezone)
            notify = settings.notify
            labels = {profile.id: profile.label for profile in profiles}
            cooldown = timedelta(minutes=notify.alert_cooldown_minutes)
            notifications = NotificationStore(store.engine)
            health_state = HealthState()
            monitor = HealthMonitor(
                store=store,
                state=health_state,
                health_store=HealthStore(store.engine),
                notifications=notifications,
                profiles=profiles,
                config=settings.health,
                ollama=probe,
                data_path=_data_dir(database_url),
                tz=tz,
            )
            healthz = await _start_healthz(monitor, settings.health.healthz_port)
            if channel is None:
                log.warning("notify_channel_not_configured", detail="alerts are kept, not sent")
            else:
                log.info("notify_channel", channel=channel.name)
            workers = [
                *(
                    ProfileCollector(
                        profile.id,
                        source,
                        store,
                        backfill_days=settings.ingest.backfill_days,
                        health=health_state,
                    ).run()
                    for profile in profiles
                ),
                EnricherWorker(
                    profile_ids, store, enricher, [popularity, threat_intel], queue
                ).run(),
                RuleWorker(
                    profile_ids,
                    store,
                    engine,
                    queue,
                    warm_up=timedelta(hours=baseline_hours + 2),
                ).run(),
                AnalystWorker(analysis_store, analyst, batch_size=llm.max_findings_per_batch).run(),
                AlertWorker(
                    notifications,
                    specs=specs,
                    labels=labels,
                    tz=tz,
                    cooldown=cooldown,
                    max_age=timedelta(minutes=notify.alert_max_age_minutes),
                    analysis_wait=timedelta(seconds=notify.analysis_wait_seconds),
                ).run(),
                DeliveryWorker(
                    notifications,
                    channel,
                    quiet_hours=QuietHours.parse(notify.quiet_hours),
                    tz=tz,
                ).run(),
                DigestScheduler(
                    notifications,
                    DigestBuilder(store.engine, profiles=profiles, tz=tz, specs=specs),
                    digest_time=parse_clock(notify.digest_time),
                    tz=tz,
                ).run(),
                monitor.run(),
            ]
            async with asyncio.TaskGroup() as group:
                tasks = [group.create_task(worker) for worker in workers]
                await stop.wait()
                for task in tasks:
                    task.cancel()
        finally:
            if healthz is not None:
                healthz.close()
                await healthz.wait_closed()
            if channel is not None:
                await channel.aclose()
            await probe.aclose()
            await ollama.aclose()
            await web.aclose()
            await source.aclose()
            await store.close()


def _data_dir(database_url: str) -> Path | None:
    """Directory of the SQLite database file, for the disk check."""
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database:
        return None
    return Path(url.database).parent


async def _start_healthz(monitor: HealthMonitor, port: int) -> asyncio.Server | None:
    """Serve /healthz on the loopback interface; carry on without it if the port is taken."""
    try:
        return await start_health_server(monitor.snapshot, host="127.0.0.1", port=port)
    except OSError as exc:
        log.error("healthz_unavailable", port=port, reason=type(exc).__name__)
        return None


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
