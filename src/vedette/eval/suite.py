"""Runs the whole evaluation and returns its numbers as plain JSON-ready data."""

import asyncio
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import structlog

from vedette.config import LlmConfig, Settings
from vedette.eval import blend, datasets, dga_families, quality
from vedette.eval.detection import DetectionResult, Detector
from vedette.eval.history import history_metrics
from vedette.eval.hostnames import ensure_hostnames
from vedette.eval.injection import (
    CrossResult,
    InjectionResult,
    RecordingClient,
    as_crafted,
    combine,
    every_nth_per_category,
    mixed_sample,
    prefilter_hits,
    run_cross,
    run_defended,
    run_undefended,
    settle,
)
from vedette.eval.stats import wilson
from vedette.llm.ollama import OllamaUnavailable
from vedette.rules.model import RuleSpec
from vedette.storage.migrate import run_migrations
from vedette.storage.reference import ReferenceStore
from vedette.storage.store import Store, StoredFinding
from vedette.storage.triage import TriageStore

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Depth:
    """How much of the model tests a run does.

    The quick depth finishes in under ten minutes on one local GPU. The fresh
    held-out set, the measure that matters now, goes to the defended analyst in
    full and every third of its items to the undefended one; the first
    held-out set, which shaped earlier defences, is a regression check on every
    fourth item with the defences on. The cross-finding test runs one item per
    category with the defences on only, and the gold set is explained once.
    The full depth runs both sets with the defences on and off, three runs of
    the gold set, and the cross-finding test on four items per category with
    the defences on, in about 18 minutes. That test's undefended arm is
    left out of both: it costs as much as the defended one and only shows a
    naive analyst being steered, which the injection test already shows. A
    depth of ``0`` skips that arm.
    """

    first_defended_every: int
    first_undefended_every: int
    fresh_undefended_every: int
    cross_per_category: int
    cross_arms: tuple[bool, ...]
    quality_runs: int


QUICK = Depth(
    first_defended_every=4,
    first_undefended_every=0,
    fresh_undefended_every=3,
    cross_per_category=1,
    cross_arms=(True,),
    quality_runs=1,
)
FULL = Depth(
    first_defended_every=1,
    first_undefended_every=1,
    fresh_undefended_every=1,
    cross_per_category=4,
    cross_arms=(True,),
    quality_runs=3,
)

#: The held-out sets, as results name them.
FIRST, FRESH = "held-out", "fresh"


def _sampled(items: Sequence[datasets.Crafted], every: int) -> list[datasets.Crafted]:
    return every_nth_per_category(items, every) if every else []


#: Flagged names kept per public set, so each false alert can be checked.
EXAMPLES = 20
TOP_SITES_CONSTRUCTION = (
    "The rules skip domains on the top-sites list, so only a threat-feed match on a domain "
    "outside the top 1,000 can flag one. A sanity check, not a false-alert rate."
)
NAME_RULES_ONLY = "name rules only: feed lookup and registration dates off"
FEEDS_CONSTRUCTION = (
    "The feeds are the same ones the threat-intel rule matches, so recall with the feed "
    "match on is high by construction."
)


def _detection(result: DetectionResult) -> dict[str, Any]:
    return {**asdict(result), "rate": result.rate}


async def _hostname_rows(
    detector: Detector, hostnames: list[datasets.Name], platform_names: list[datasets.Name]
) -> list[DetectionResult]:
    """The popular-hostname sets, when the list could be had."""
    rows = []
    if hostnames:
        rows += [
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
    if platform_names:
        rows.append(
            await detector.names(
                "Popular hostnames on hosting platforms",
                "benign",
                platform_names,
                dates=False,
                note="customer names under a platform, from the top 100,000",
                examples=EXAMPLES,
            )
        )
    return rows


async def _generated_rows(
    detector: Detector, families: dict[str, list[datasets.Name]]
) -> list[DetectionResult]:
    """Generated domain names: synthetic ones, then the real families three ways."""
    dga_random, dga_words = datasets.dga_names()
    generated = [name for names in families.values() for name in names]
    return [
        await detector.names(
            "Random-character DGA names",
            "malicious",
            dga_random,
            note="synthetic, like the labels the threshold was set on",
        ),
        await detector.names("Dictionary-word DGA names", "malicious", dga_words),
        await detector.names(
            "Real DGA families",
            "malicious",
            generated,
            feeds=False,
            dates=False,
            note=f"{len(families)} families, held out; {NAME_RULES_ONLY}",
        ),
        await detector.names(
            "Real DGA families, behind a prefix",
            "malicious",
            datasets.prefixed(generated),
            feeds=False,
            dates=False,
            note="the same names under www., mail., cdn. or api.",
        ),
        await detector.names(
            "DGA labels on hosting platforms",
            "malicious",
            datasets.platform_hosted(families),
            feeds=False,
            dates=False,
            note="customer names on duckdns.org, github.io and eight more",
        ),
    ]


async def _families(
    detector: Detector, families: dict[str, list[datasets.Name]]
) -> list[dict[str, Any]]:
    """What dga-like flags in each real malware family, bare and behind a prefix."""
    rows = []
    for family in dga_families.FAMILIES:
        names = families[family.name]
        bare = await detector.names(family.name, "malicious", names, feeds=False, dates=False)
        behind = await detector.names(
            family.name, "malicious", datasets.prefixed(names), feeds=False, dates=False
        )
        rows.append(
            {
                "family": family.name,
                "style": family.style,
                "items": bare.items,
                "flagged": bare.by_rule.get("dga-like", 0),
                "prefixed_flagged": behind.by_rule.get("dga-like", 0),
            }
        )
    return rows


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


def _quality(result: quality.QualityResult) -> dict[str, Any]:
    data = asdict(result)
    data.pop("durations_ms")
    right, scored = result.leaning_right
    return {**data, "mean_ms": result.mean_ms, "leaning_right": right, "leaning_scored": scored}


def _cross(result: CrossResult) -> dict[str, Any]:
    data = asdict(result)
    data.pop("durations_ms")
    return {
        **data,
        "affected_rate": result.affected_rate,
        "ci": wilson(result.affected, result.batches),
    }


@dataclass(slots=True)
class _ModelRuns:
    """Everything one model and thinking setting was asked."""

    injection: list[InjectionResult]
    cross: list[CrossResult]
    quality: quality.QualityResult | None


async def _ask_model(
    settings: Settings,
    specs: Sequence[RuleSpec],
    scratch: Store,
    model: str,
    think: bool,
    *,
    arms: Sequence[tuple[str, bool, Sequence[datasets.Crafted]]],
    sample: Sequence[datasets.Crafted],
    gold: Sequence[quality.GoldItem],
    gold_findings: Sequence[StoredFinding],
    depth: Depth,
    repeats: int,
    parallel: int,
    now: datetime,
) -> _ModelRuns:
    """Every injection run and the explanation-quality run for one model and thinking setting.

    All runs are started together and share one limit of ``parallel`` calls in
    flight, so the model server is kept busy without queueing. ``arms`` are
    the injection runs as (set, defences on, items); an arm with no items is
    skipped, and with no gold items the quality test is.

    Raises:
        OllamaUnavailable: The model could not be used.
    """
    llm = settings.llm
    limit = asyncio.Semaphore(parallel)

    async def injection(
        repeat: int, dataset: str, defended: bool, items: Sequence[datasets.Crafted]
    ) -> InjectionResult:
        log.info(
            "eval_injection_round",
            model=model,
            think=think,
            dataset=dataset,
            defences=defended,
            repeat=repeat,
        )
        recording = _client(llm, model, think, limit)
        try:
            if defended:
                result = await run_defended(
                    recording, items, specs, scratch.engine, think=think, now=now
                )
            else:
                result = await run_undefended(recording, items, think=think, now=now)
        finally:
            await recording.aclose()
        result.repeat = repeat
        result.dataset = dataset
        return result

    async def cross(defended: bool) -> CrossResult:
        log.info("eval_cross_finding_round", model=model, think=think, defences=defended)
        recording = _client(llm, model, think, limit)
        try:
            return await run_cross(
                recording, sample, specs, scratch.engine, defended=defended, think=think, now=now
            )
        finally:
            await recording.aclose()

    async def explain_once(run: int) -> quality.QualityResult:
        log.info("eval_quality_round", model=model, think=think, run=run)
        recording = _client(llm, model, think, limit)
        try:
            analyst = quality.production_analyst(
                recording, specs, scratch.engine, context_tokens=recording.num_ctx
            )
            return await quality.model_quality(recording, analyst, gold, gold_findings, think=think)
        finally:
            await recording.aclose()

    async def explain() -> list[quality.QualityResult]:
        if not gold:
            return []
        runs = range(1, depth.quality_runs + 1)
        first, *others = await settle(explain_once(run) for run in runs)
        for other in others:
            first.merge(other)
        return [first]

    rounds = [
        (repeat, dataset, defended, items)
        for repeat in range(1, repeats + 1)
        for dataset, defended, items in arms
        if items
    ]
    crossed = asyncio.ensure_future(
        settle([cross(defended) for defended in depth.cross_arms if sample])
    )
    done = asyncio.ensure_future(settle([injection(*key) for key in rounds]))
    explained = asyncio.ensure_future(explain())
    # Every run finishes before a failure is raised, so no call is cut off half-way.
    await asyncio.wait([crossed, done, explained])
    # Read every failure, so none is reported as never retrieved.
    for failure in [done.exception(), crossed.exception(), explained.exception()]:
        if failure is not None:
            raise failure
    scored = explained.result()
    return _ModelRuns(done.result(), crossed.result(), scored[0] if scored else None)


def _client(llm: LlmConfig, model: str, think: bool, limit: asyncio.Semaphore) -> RecordingClient:
    return RecordingClient(
        llm.base_url,
        model=model,
        think=think,
        temperature=llm.temperature,
        num_ctx=llm.num_ctx,
        keep_alive=llm.keep_alive,
        limit=limit,
    )


async def run_suite(
    settings: Settings,
    specs: Sequence[RuleSpec],
    *,
    models: Sequence[str],
    thinks: Sequence[bool],
    with_llm: bool = True,
    injection_test: bool = True,
    repeats: int = 1,
    cross: bool = True,
    cross_per_category: int | None = None,
    full: bool = False,
    parallel: int = 1,
    offline: bool = False,
    http_client: httpx.AsyncClient | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run every part of the evaluation that the local data allows.

    The popular-hostname list is the one thing downloaded, at most once per
    ``evaluation.refresh_days``; with ``offline`` the stored copy is used or
    those sets are skipped. ``http_client`` downloads it (one is opened if not given).
    ``full`` runs every model test in full (:data:`FULL`); otherwise a quick
    depth (:data:`QUICK`) keeps the run to minutes. The held-out injection set
    goes to each model ``repeats`` times per thinking and defence setting. With
    ``cross``, the first ``cross_per_category`` items of each category (the
    depth's number unless given) are also put among ordinary findings, on the
    first model only, to see whether they change what it says about the others. Up to
    ``parallel`` model calls are in flight at once; set the model server to
    answer as many together (``OLLAMA_NUM_PARALLEL``). Every model also explains
    the gold set of findings, scored against the template; ``injection_test`` off
    skips the injection and cross-finding tests and runs only that.
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
        families = datasets.family_names()
        gold = quality.load_gold(specs)
        gold_findings = await quality.seed(scratch.engine, gold, specs, now)
        template_quality = quality.template_quality(gold, gold_findings, specs)
        injection = datasets.injection_names()
        held_out = datasets.held_out_injection()
        fresh = datasets.fresh_injection()
        depth = FULL if full else QUICK
        per_category = cross_per_category or depth.cross_per_category
        sample = mixed_sample(held_out, per_category) if cross else []
        first_defended = _sampled(held_out, depth.first_defended_every)
        undefended = _sampled(held_out, depth.first_undefended_every)
        # A planted lookup reaches only the context pack, which the undefended
        # analyst never builds, so context items go to the defended one only.
        plain_fresh = [item for item in fresh if item.carrier != "context"]
        fresh_undefended = _sampled(plain_fresh, depth.fresh_undefended_every)
        arms = [
            (FRESH, True, fresh),
            (FRESH, False, fresh_undefended),
            (FIRST, True, first_defended),
            (FIRST, False, undefended),
        ]
        prefilter = {
            "development": prefilter_hits(as_crafted(injection), now),
            "held_out": prefilter_hits(held_out, now),
            "fresh": prefilter_hits(fresh, now),
        }

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
            platform_names = (
                await datasets.platform_hostnames(
                    store.engine, detector.root_of, detector.is_platform
                )
                if listing.available and suffix_list
                else []
            )
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
            detection += await _hostname_rows(detector, hostnames, platform_names)
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
            ]
            detection += await _generated_rows(detector, families)
            detection += [
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
                await detector.names(
                    "Held-out injection names",
                    "malicious",
                    [
                        datasets.Name(fqdn=item.fqdn, root=item.root)
                        for item in held_out
                        if item.fqdn and item.root
                    ],
                    note="the looked-up names of the held-out set",
                ),
            ]
            family_rows = await _families(detector, families)
            allowlist = [
                *settings.allowlist,
                *await TriageStore(store.engine).allowlist_entries(),
            ]
            learning = timedelta(days=settings.rules.learning_days)
            replay = await detector.replay(
                store, profile_ids, allowlist=allowlist, learning=learning
            )
            in_traffic = await blend.attacks_in_traffic(
                detector,
                store,
                profile_ids,
                allowlist=allowlist,
                learning=learning,
                clean=replay,
                families=families,
                feeds=feeds,
            )
        history = await history_metrics(store.engine, profile_ids, now)

        results: list[InjectionResult] = []
        crosses: list[CrossResult] = []
        explained: list[quality.QualityResult] = []
        if with_llm:
            for number, model in enumerate(models):
                for think in thinks:
                    try:
                        runs = await _ask_model(
                            settings,
                            specs,
                            scratch,
                            model,
                            think,
                            arms=arms if injection_test else [],
                            depth=depth,
                            sample=sample if number == 0 and injection_test else [],
                            gold=gold,
                            gold_findings=gold_findings,
                            repeats=repeats,
                            parallel=parallel,
                            now=now,
                        )
                    except OllamaUnavailable as exc:
                        errors.append(f"{model}: the local model could not be used ({exc}).")
                        break
                    results += runs.injection
                    crosses += runs.cross
                    if runs.quality is not None:
                        explained.append(runs.quality)
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
        "injection_run": with_llm and injection_test,
        "depth": "full" if full else "quick",
        "quality_runs": depth.quality_runs,
        "repeats": repeats,
        "parallel": parallel,
        "dataset_sizes": {
            "top_sites": len(top),
            "hostnames": len(hostnames),
            "own_history": len(own),
            "feeds": len(feeds),
            "dga_random": len(dga_random),
            "dga_words": len(dga_words),
            "dga_families": sum(len(names) for names in families.values()),
            "families": len(families),
            "platform_hosted": len(datasets.platform_hosted(families)),
            "platform_hostnames": len(platform_names),
            "tunnels_fast": len(fast),
            "tunnels_slow": len(slow),
            "tunnels_sustained": len(sustained),
            "bursts_random": len(bursts_random),
            "bursts_words": len(bursts_words),
            "young": len(young),
            "old": len(old),
            "injection": len(injection),
            "injection_held_out": len(held_out),
            "cross_sample": len(sample),
            "injection_undefended": len(undefended),
            "injection_first_defended": len(first_defended),
            "injection_first_defended_every": depth.first_defended_every,
            "injection_first_undefended_every": depth.first_undefended_every,
            "fresh_undefended_every": depth.fresh_undefended_every,
            "injection_fresh": len(fresh),
            "fresh_undefended": len(fresh_undefended),
        },
        "held_out_categories": {
            category: counts[0] for category, counts in prefilter["held_out"].items()
        },
        "fresh_categories": {
            category: counts[0] for category, counts in prefilter["fresh"].items()
        },
        "prefilter": prefilter,
        "detection": [_detection(result) for result in detection],
        "dga_families": family_rows,
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
        "in_traffic": in_traffic,
        "injection": [_injection(result) for result in results],
        "injection_combined": combine(results),
        "cross_finding": [_cross(result) for result in crosses],
        "quality": {
            "items": len(gold),
            "kinds": {kind: sum(item.kind == kind for item in gold) for kind in quality.KINDS},
            "template": _quality(template_quality),
            "models": [_quality(result) for result in explained],
        },
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
