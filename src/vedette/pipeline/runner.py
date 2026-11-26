"""Starts the pipeline stages and stops them cleanly.

All six stages run: collector, enricher, rule engine, LLM analyst, notifier
and health monitor, plus the ``/healthz`` endpoint on the loopback interface
and, when a token is set, the dashboard.
"""

import asyncio
import contextlib
import signal
import socket
from collections.abc import Coroutine, Iterator, Sequence
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import structlog
import uvicorn
from sqlalchemy.engine import make_url

from vedette import __version__
from vedette.config import Settings
from vedette.enrich.enricher import Enricher
from vedette.enrich.first_seen import FirstSeenTracker
from vedette.enrich.popularity import PopularityList
from vedette.enrich.public_suffix import PublicSuffixList
from vedette.enrich.rdap import DomainAges, RdapClient
from vedette.enrich.threat_intel import ThreatIntel
from vedette.health.heartbeat import Heartbeat
from vedette.health.monitor import HealthMonitor, OllamaProbe
from vedette.health.server import start_health_server
from vedette.health.state import HealthState
from vedette.llm.analyst import Analyst
from vedette.llm.ollama import OllamaClient
from vedette.notify.digest import DigestBuilder
from vedette.notify.factory import build_channel
from vedette.notify.schedule import QuietHours, parse_clock
from vedette.pipeline.analyst import AnalystWorker
from vedette.pipeline.collector import ProfileCollector
from vedette.pipeline.notifier import AlertWorker, DeliveryWorker, DigestScheduler
from vedette.pipeline.processor import Batch, EnricherWorker, RuleWorker
from vedette.pipeline.queue import MemoryQueue
from vedette.pipeline.retention import RetentionWorker
from vedette.rules.allowlist import Allowlist
from vedette.rules.engine import RuleEngine
from vedette.rules.loader import load_rules
from vedette.rules.model import RuleSpec
from vedette.sources.nextdns import NextDnsSource
from vedette.storage.analysis import AnalysisStore
from vedette.storage.health import HealthStore
from vedette.storage.migrate import run_migrations
from vedette.storage.notifications import NotificationStore
from vedette.storage.reference import ReferenceStore
from vedette.storage.store import Store
from vedette.storage.triage import TriageStore
from vedette.web.app import DashboardContext, create_app

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
    """The set of long-running stages that make up Vedette."""

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
            headers={"User-Agent": f"vedette/{__version__}"},
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
        # Only for HEARTBEAT_URL, so the ping carries no other credential.
        beat_client = (
            httpx.AsyncClient(headers={"User-Agent": f"vedette/{__version__}"})
            if settings.heartbeat_url is not None
            else None
        )
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
            suffixes = PublicSuffixList(
                reference,
                web,
                url=enrich.public_suffix.url,
                refresh_days=enrich.public_suffix.refresh_days,
            )
            await suffixes.load()
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
                suffixes=suffixes,
            )
            allowlist = Allowlist(
                settings.allowlist, labels={profile.id: profile.label for profile in profiles}
            )
            triage = TriageStore(store.engine)

            async def refresh_allowlist() -> None:
                allowlist.replace([*settings.allowlist, *await triage.allowlist_entries()])

            engine = RuleEngine(
                specs,
                allowlist=allowlist,
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
                context_tokens=llm.num_ctx,
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
                channel=notify.channel,
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
                    profile_ids, store, enricher, [popularity, suffixes, threat_intel], queue
                ).run(),
                RuleWorker(
                    profile_ids,
                    store,
                    engine,
                    queue,
                    warm_up=timedelta(hours=baseline_hours + 2),
                    allowlist_refresh=refresh_allowlist,
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
                    oldest_data=partial(_oldest_event, store, [p.id for p in profiles]),
                ).run(),
                monitor.run(),
                RetentionWorker(
                    store.engine,
                    events_days=settings.retention.events_days,
                    findings_days=settings.retention.findings_days,
                ).run(),
            ]
            if settings.heartbeat_url is not None and beat_client is not None:
                workers.append(
                    Heartbeat(
                        monitor,
                        settings.heartbeat_url.get_secret_value(),
                        client=beat_client,
                        interval=timedelta(minutes=settings.health.heartbeat_minutes),
                    ).run()
                )
                log.info("heartbeat_enabled", minutes=settings.health.heartbeat_minutes)
            await _serve_until(stop, workers, _dashboard(settings, store, specs, tz))
        finally:
            if healthz is not None:
                healthz.close()
                await healthz.wait_closed()
            if channel is not None:
                await channel.aclose()
            if beat_client is not None:
                await beat_client.aclose()
            await probe.aclose()
            await ollama.aclose()
            await web.aclose()
            await source.aclose()
            await store.close()


async def _serve_until(
    stop: asyncio.Event,
    workers: Sequence[Coroutine[Any, Any, None]],
    dashboard: tuple[uvicorn.Server, socket.socket] | None,
) -> None:
    """Run the workers and the dashboard until ``stop`` is set, then cancel them."""
    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(worker) for worker in workers]
        if dashboard is not None:
            server, sock = dashboard
            group.create_task(server.serve(sockets=[sock]), name="dashboard")
        await stop.wait()
        if dashboard is not None:
            dashboard[0].should_exit = True
        for task in tasks:
            task.cancel()


class _DashboardServer(uvicorn.Server):
    """uvicorn without its own signal handling: the pipeline owns SIGINT and SIGTERM."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        """Leave the process's signal handlers alone."""
        yield


def _dashboard(
    settings: Settings, store: Store, specs: Sequence[RuleSpec], tz: ZoneInfo
) -> tuple[uvicorn.Server, socket.socket] | None:
    """Build the dashboard server and bind its port, or say why it stays off."""
    config = settings.dashboard
    if not config.enabled:
        log.info("dashboard_disabled", reason="dashboard.enabled is false")
        return None
    if settings.dashboard_token is None:
        log.warning("dashboard_disabled", reason="DASHBOARD_TOKEN is not set")
        return None
    app = create_app(
        DashboardContext(
            engine=store.engine,
            profiles=settings.enabled_profiles,
            tz=tz,
            token=settings.dashboard_token.get_secret_value(),
            specs=specs,
            session_lifetime=timedelta(hours=config.session_hours),
            allowed_hosts=config.allowed_hosts,
            digest_time=settings.notify.digest_time,
            allowlist=settings.allowlist,
        )
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((config.host, config.port))
        sock.listen(64)
    except OSError as exc:
        sock.close()
        log.error("dashboard_unavailable", port=config.port, reason=type(exc).__name__)
        return None
    server = _DashboardServer(
        uvicorn.Config(
            app,
            log_config=None,
            access_log=False,
            server_header=False,
            date_header=False,
            lifespan="off",
            proxy_headers=False,
            timeout_graceful_shutdown=5,
        )
    )
    log.info("dashboard_listening", host=config.host, port=config.port)
    return server, sock


async def _oldest_event(store: Store, profile_ids: Sequence[str]) -> datetime | None:
    """Time of the oldest stored event across the given profiles, if any."""
    times = [await store.earliest_event_ts(profile_id) for profile_id in profile_ids]
    return min((t for t in times if t is not None), default=None)


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
