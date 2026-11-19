"""Runs the whole evaluation and returns its numbers as plain JSON-ready data."""

import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from sentinel.config import Settings
from sentinel.eval import datasets
from sentinel.eval.detection import DetectionResult, Detector
from sentinel.eval.history import history_metrics
from sentinel.eval.injection import InjectionResult, RecordingClient, run_defended, run_undefended
from sentinel.llm.ollama import OllamaUnavailable
from sentinel.rules.model import RuleSpec
from sentinel.storage.migrate import run_migrations
from sentinel.storage.store import Store

log = structlog.get_logger(__name__)


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
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run every part of the evaluation that the local data allows."""
    now = now or datetime.now(UTC)
    profile_ids = [profile.id for profile in settings.enabled_profiles] or [
        profile.id for profile in settings.profiles
    ]
    scratch_dir = Path(tempfile.mkdtemp(prefix="sentinel-eval-"))
    scratch_url = f"sqlite+aiosqlite:///{scratch_dir / 'scratch.db'}"
    run_migrations(scratch_url)
    store = Store.open(settings.storage.database_url)
    scratch = Store.open(scratch_url)
    errors: list[str] = []
    try:
        top = await datasets.top_sites(store.engine)
        own = await datasets.own_history(store.engine)
        feeds = await datasets.feed_domains(store.engine)
        dga_random, dga_words = datasets.dga_names()
        fast, slow = datasets.tunnel_sessions()
        injection = datasets.injection_names()

        async with Detector(store.engine, scratch.engine, specs, now) as detector:
            if not detector.popularity_known:
                errors.append(
                    "No top-sites list is stored yet, so the popularity-based rules "
                    "(dga-like, young-domain) could not be judged fairly."
                )
            detection = [
                await detector.names("Top sites, local list", "benign", top),
                await detector.names("Your own history, sample", "benign", own),
                await detector.names("Threat-feed domains", "malicious", feeds),
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
                await detector.names("Crafted injection names", "malicious", injection),
            ]
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
            "own_history": len(own),
            "feeds": len(feeds),
            "dga_random": len(dga_random),
            "dga_words": len(dga_words),
            "tunnels_fast": len(fast),
            "tunnels_slow": len(slow),
            "injection": len(injection),
        },
        "detection": [_detection(result) for result in detection],
        "history": {
            **asdict(history),
            "alerts_per_day": history.alerts_per_day,
            "llm_calls_per_day": history.llm_calls_per_day,
        },
        "injection": [_injection(result) for result in results],
        "injection_names": [name.fqdn for name in injection],
        "errors": errors,
    }
