"""Runs the whole evaluation and returns its numbers as plain JSON-ready data."""

import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import structlog

from vedette.config import Settings
from vedette.eval import datasets
from vedette.eval.detection import DetectionResult, Detector
from vedette.eval.history import history_metrics
from vedette.eval.hostnames import ensure_hostnames
from vedette.eval.injection import InjectionResult, RecordingClient, run_defended, run_undefended
from vedette.llm.ollama import OllamaUnavailable
from vedette.rules.model import RuleSpec
from vedette.storage.migrate import run_migrations
from vedette.storage.reference import ReferenceStore
from vedette.storage.store import Store
from vedette.storage.triage import TriageStore

log = structlog.get_logger(__name__)

#: Flagged names kept per public set, so each false alert can be checked.
EXAMPLES = 20
TOP_SITES_CONSTRUCTION = (
    "The rules skip domains on the top-sites list, so only a threat-feed match on a domain "
    "outside the top 1,000 can flag one. A sanity check, not a false-alert rate."
)
FEEDS_CONSTRUCTION = (
    "The feeds are the same ones the threat-intel rule matches, so recall with the feed "
    "match on is high by construction."
)


def _detection(result: DetectionResult) -> dict[str, Any]:
    return {**asdict(result), "rate": result.rate}


def _injection(result: InjectionResult) -> dict[str, Any]:
    p50, p95 = result.latency()
    data = asdict(result)
    data.pop("durations_ms")
    return {
        **data,
        "success_rate": result.success_rate,
        "schema_failure_rate": result.schema_failure_rate,
        "p50_ms": p50,
        "p95_ms": p95,
    }


async def run_suite(
    settings: Settings,
    specs: Sequence[RuleSpec],
    *,
    models: Sequence[str],
    thinks: Sequence[bool],
    with_llm: bool = True,
    offline: bool = False,
    http_client: httpx.AsyncClient | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run every part of the evaluation that the local data allows.

    The popular-hostname list is the one thing downloaded, at most once per
    ``evaluation.refresh_days``; with ``offline`` the stored copy is used or
    those sets are skipped. ``http_client`` downloads it (one is opened if not given).
    """
    now = now or datetime.now(UTC)
    profile_ids = [profile.id for profile in settings.enabled_profiles] or [
        profile.id for profile in settings.profiles
    ]
    scratch_dir = Path(tempfile.mkdtemp(prefix="vedette-eval-"))
    scratch_url = f"sqlite+aiosqlite:///{scratch_dir / 'scratch.db'}"
    run_migrations(scratch_url)
    store = Store.open(settings.storage.database_url)
    scratch = Store.open(scratch_url)
    errors: list[str] = []
    http = http_client or httpx.AsyncClient(timeout=httpx.Timeout(60.0), follow_redirects=True)
    try:
        listing = await ensure_hostnames(
            ReferenceStore(store.engine),
            http,
            url=settings.evaluation.hostnames_url,
            refresh=timedelta(days=settings.evaluation.refresh_days),
            now=now,
            offline=offline,
        )
        if listing.problem:
            errors.append(listing.problem)
        top = await datasets.top_sites(store.engine)
        own = await datasets.own_history(store.engine)
        feeds = await datasets.feed_domains(store.engine)
        dga_random, dga_words = datasets.dga_names()
        fast, slow = datasets.tunnel_sessions()
        sustained = datasets.sustained_tunnel_sessions()
        bursts_random, bursts_words = datasets.dga_bursts()
        young, old = datasets.dated_domains()
        injection = datasets.injection_names()

        async with Detector(store.engine, scratch.engine, specs, now) as detector:
            if not detector.popularity_known:
                errors.append(
                    "No top-sites list is stored yet, so the popularity-based rules "
                    "(dga-like, young-domain) could not be judged fairly."
                )
            hostnames = (
                await datasets.popular_hostnames(store.engine, detector.root_of)
                if listing.available
                else []
            )
            suffix_list = detector.suffixes_known
            if hostnames and not suffix_list:
                errors.append(
                    "No Public Suffix List is stored yet, so popular hostnames were grouped "
                    "by their last two labels."
                )
            # Public lists are judged without cached registration dates: only the
            # owner's own lookups fill that cache, and these sets print names.
            detection = [
                await detector.names(
                    "Top sites, local list",
                    "benign",
                    top,
                    dates=False,
                    construction=TOP_SITES_CONSTRUCTION,
                ),
                await detector.names(
                    "Top sites, as if unlisted",
                    "benign",
                    top,
                    ranks=False,
                    dates=False,
                    note="the same names with their rank removed",
                    examples=EXAMPLES,
                ),
            ]
            if hostnames:
                detection += [
                    await detector.names(
                        "Popular hostnames (Cisco Umbrella)",
                        "benign",
                        hostnames,
                        dates=False,
                        note="full names, every 100th of the top 100,000",
                        examples=EXAMPLES,
                    ),
                    await detector.names(
                        "Popular hostnames, as if unlisted",
                        "benign",
                        hostnames,
                        ranks=False,
                        dates=False,
                        examples=EXAMPLES,
                    ),
                ]
            detection += [
                await detector.names("Your own history, sample", "benign", own),
                await detector.names(
                    "Threat-feed domains", "malicious", feeds, construction=FEEDS_CONSTRUCTION
                ),
                await detector.names(
                    "Threat-feed domains, feed lookup off",
                    "malicious",
                    feeds,
                    feeds=False,
                    note="what the other rules catch without the feed match",
                ),
                await detector.names("Random-character DGA names", "malicious", dga_random),
                await detector.names("Dictionary-word DGA names", "malicious", dga_words),
                await detector.sessions("Tunnels, 40 lookups in 5 minutes", fast),
                await detector.sessions("Tunnels, 20 lookups in 10 minutes", slow),
                await detector.sessions("Tunnels, a lookup a minute for 2 hours", sustained),
                await detector.bursts("Bursts of 30 random-character domains", bursts_random),
                await detector.bursts("Bursts of 30 dictionary-word domains", bursts_words),
                await detector.dated(
                    "Young domains, registration dates given",
                    "malicious",
                    young,
                    note="measures the rule; the registry lookup is not part of it",
                ),
                await detector.dated("Older domains, registration dates given", "benign", old),
                await detector.names("Crafted injection names", "malicious", injection),
            ]
            replay = await detector.replay(
                store,
                profile_ids,
                allowlist=[
                    *settings.allowlist,
                    *await TriageStore(store.engine).allowlist_entries(),
                ],
                learning=timedelta(days=settings.rules.learning_days),
            )
        history = await history_metrics(store.engine, profile_ids, now)

        results: list[InjectionResult] = []
        if with_llm:
            llm = settings.llm
            for model in models:
                for think in thinks:
                    for defended in (True, False):
                        client = RecordingClient(
                            llm.base_url,
                            model=model,
                            think=think,
                            temperature=llm.temperature,
                            num_ctx=llm.num_ctx,
                            keep_alive=llm.keep_alive,
                        )
                        log.info(
                            "eval_injection_round", model=model, think=think, defences=defended
                        )
                        try:
                            if defended:
                                results.append(
                                    await run_defended(
                                        client,
                                        injection,
                                        specs,
                                        scratch.engine,
                                        think=think,
                                        now=now,
                                    )
                                )
                            else:
                                results.append(
                                    await run_undefended(client, injection, think=think, now=now)
                                )
                        except OllamaUnavailable as exc:
                            errors.append(f"{model}: the local model could not be used ({exc}).")
                            break
                        finally:
                            await client.aclose()
    finally:
        if http_client is None:
            await http.aclose()
        await scratch.close()
        await store.close()
        shutil.rmtree(scratch_dir, ignore_errors=True)

    return {
        "generated_at": now.isoformat(),
        "production_model": settings.llm.model,
        "models": list(models),
        "thinking": [("on" if think else "off") for think in thinks],
        "with_llm": with_llm,
        "dataset_sizes": {
            "top_sites": len(top),
            "hostnames": len(hostnames),
            "own_history": len(own),
            "feeds": len(feeds),
            "dga_random": len(dga_random),
            "dga_words": len(dga_words),
            "tunnels_fast": len(fast),
            "tunnels_slow": len(slow),
            "tunnels_sustained": len(sustained),
            "bursts_random": len(bursts_random),
            "bursts_words": len(bursts_words),
            "young": len(young),
            "old": len(old),
            "injection": len(injection),
        },
        "detection": [_detection(result) for result in detection],
        "history": {
            **asdict(history),
            "alerts_per_day": history.alerts_per_day,
            "llm_calls_per_day": history.llm_calls_per_day,
        },
        "replay": {
            "events": replay.events,
            "days": round(replay.days, 1),
            "rules": [
                {
                    "rule": rule,
                    "findings": count,
                    "per_day": replay.per_day(count),
                    "alerting": replay.alerting.get(rule, 0),
                    "alerting_per_day": replay.per_day(replay.alerting.get(rule, 0)),
                }
                for rule, count in replay.findings.items()
            ],
        },
        "injection": [_injection(result) for result in results],
        "injection_names": [name.fqdn for name in injection],
        "hostname_list": {
            "source": settings.evaluation.hostnames_url,
            "refreshed_at": (
                listing.refreshed_at.isoformat() if listing.refreshed_at is not None else None
            ),
            "suffix_list": suffix_list,
        },
        "errors": errors,
    }
