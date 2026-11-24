"""The ``vedette`` command-line interface."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import typer
from sqlalchemy.engine import make_url

from vedette import __version__
from vedette.config import ConfigError, Settings, load_settings
from vedette.eval.report import render_markdown
from vedette.eval.suite import run_suite
from vedette.llm.schema import Analysis
from vedette.log import configure_logging
from vedette.notify.channels import Channel, DeliveryError, OutgoingMessage
from vedette.notify.defang import clean_text, defang, defang_text
from vedette.notify.digest import DigestBuilder, render_digest
from vedette.notify.factory import build_channel
from vedette.notify.render import render_test
from vedette.pipeline.runner import run_until_signalled
from vedette.rules.loader import load_rules
from vedette.rules.model import Severity
from vedette.sources.base import DnsEvent, SourceError
from vedette.sources.nextdns import NextDnsSource
from vedette.sources.nextdns_export import ExportFormatError, read_export
from vedette.storage.analysis import AnalysisStore
from vedette.storage.evaluation import EvalStore
from vedette.storage.migrate import run_migrations
from vedette.storage.notifications import NotificationStore
from vedette.storage.retention import Purged, private_umask, purge_all, purge_expired
from vedette.storage.store import Store, StoredFinding
from vedette.storage.triage import DOMAIN_RULES, TriageStore

app = typer.Typer(
    name="vedette",
    help="Vedette: watch NextDNS logs for suspicious DNS activity.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


def _print_version(requested: bool) -> None:
    if requested:
        typer.echo(f"vedette {__version__}")
        raise typer.Exit


def _load_or_exit(config: Path | None) -> Settings:
    """Load settings, or print a one-line error and exit with status 2."""
    try:
        return load_settings(config)
    except ConfigError as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(code=2) from None


def _secret_values(settings: Settings) -> list[str]:
    """Secret values the log redactor must scrub."""
    return settings.secret_values()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_print_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Vedette: watch NextDNS logs for suspicious DNS activity."""
    private_umask()  # the database and everything else written stays owner-only


@app.command()
def run(
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Run the pipeline until interrupted."""
    settings = _load_or_exit(config)
    configure_logging(settings.log_level, secrets=_secret_values(settings))
    asyncio.run(run_until_signalled(settings))


def _safe(value: Any) -> str:
    """Render an untrusted evidence value for a terminal: defanged, no control characters."""
    if isinstance(value, list):
        return ", ".join(_safe(item) for item in value)
    if isinstance(value, str):
        return defang(clean_text(value, limit=300))
    return clean_text(str(value), limit=300)


def _resolve_profile(settings: Settings, wanted: str | None) -> str | None:
    """Turn a profile label or id into its id, or exit with status 2 if unknown."""
    if wanted is None:
        return None
    for profile in settings.profiles:
        if wanted in (profile.id, profile.label):
            return profile.id
    typer.echo(f"Unknown profile: {clean_text(wanted, limit=80)}", err=True)
    raise typer.Exit(code=2)


def _database_missing(database_url: str) -> str | None:
    """Path of the SQLite file if it does not exist yet, else ``None``."""
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite" and url.database and not Path(url.database).exists():
        return url.database
    return None


async def _load_findings(
    database_url: str,
    profile_id: str | None,
    rule: str | None,
    min_severity: Severity | None,
    limit: int,
) -> list[tuple[StoredFinding, Analysis | None]]:
    store = Store.open(database_url)
    try:
        found = await store.list_findings(
            profile_id=profile_id, rule_id=rule, min_severity=min_severity, limit=limit
        )
        analyses = await AnalysisStore(store.engine).analyses_for([item.id for item in found])
        return [(item, analyses.get(item.id)) for item in found]
    finally:
        await store.close()


def _as_json(item: StoredFinding, analysis: Analysis | None) -> dict[str, Any]:
    return {
        "analysis": analysis.model_dump(mode="json", exclude={"finding_id"})
        if analysis is not None
        else None,
        "id": item.id,
        "rule_id": item.rule_id,
        "severity": item.severity.value,
        "profile_id": item.profile_id,
        "subject": item.subject,
        "device_mode": item.device_mode,
        "target": item.target,
        "first_ts": item.first_ts.isoformat(),
        "last_ts": item.last_ts.isoformat(),
        "event_count": item.event_count,
        "evidence": item.evidence,
        "status": item.status,
    }


def _explanation(item: StoredFinding, analysis: Analysis | None) -> list[str]:
    """Lines describing the analysis of a finding. Model text is re-sanitised here."""
    if analysis is None:
        return ["    explanation: not analysed yet"]

    def text(value: str) -> str:
        return defang_text(clean_text(value, limit=400))

    lines = []
    if analysis.priority.rank > item.severity.rank:
        lines.append(
            f"    priority: {analysis.priority.value.upper()} "
            f"(raised from {item.severity.value.upper()} by the analysis)"
        )
    lines += [
        f"    summary: {text(analysis.summary)}",
        f"    likely cause: {text(analysis.likely_cause)}",
        f"    recommended action: {text(analysis.recommended_action)}",
    ]
    if analysis.source == "template" or analysis.model is None:
        lines.append("    explained by: standard explanation (the local model was not used)")
    else:
        origin = "reused from an earlier identical finding" if analysis.source == "cache" else ""
        lines.append(
            f"    explained by: {clean_text(analysis.model, limit=64)}, "
            f"confidence {analysis.confidence:.2f}" + (f", {origin}" if origin else "")
        )
    return lines


def _as_text(item: StoredFinding, analysis: Analysis | None, settings: Settings) -> str:
    labels = {profile.id: profile.label for profile in settings.profiles}
    when = item.last_ts.astimezone(ZoneInfo(settings.timezone)).strftime("%Y-%m-%d %H:%M")
    profile = clean_text(labels.get(item.profile_id, item.profile_id), limit=64)
    who = f"device {_safe(item.subject)}" if item.device_mode else "device attribution unavailable"
    target = profile if item.target == item.profile_id else _safe(item.target)
    priority = analysis.priority if analysis is not None else item.severity
    lines = [
        f"{when}  {priority.value.upper():<8}  {item.rule_id}  {target}"
        f"  [{profile}, {who}]  x{item.event_count}"
    ]
    lines.extend(_explanation(item, analysis))
    lines.extend(
        f"    {clean_text(str(key), limit=64)}: {_safe(value)}"
        for key, value in sorted(item.evidence.items())
        if value is not None
    )
    return "\n".join(lines)


@app.command()
def findings(
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Only this profile (label or id).")
    ] = None,
    min_severity: Annotated[
        str | None,
        typer.Option(
            "--min-severity", help="Lowest severity to show: info, low, medium, high, critical."
        ),
    ] = None,
    rule: Annotated[str | None, typer.Option("--rule", help="Only this rule id.")] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=1000, help="Maximum findings.")] = 50,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Print raw JSON (domains are NOT defanged in this form)."),
    ] = False,
) -> None:
    """List findings with their evidence, most recent first.

    Domains are defanged (example[.]com) and control characters removed, because
    names in DNS logs are attacker-controlled.
    """
    settings = _load_or_exit(config)
    profile_id = _resolve_profile(settings, profile)
    severity: Severity | None = None
    if min_severity is not None:
        try:
            severity = Severity(min_severity.lower())
        except ValueError:
            typer.echo("Unknown severity: use info, low, medium, high or critical.", err=True)
            raise typer.Exit(code=2) from None

    database_url = settings.storage.database_url
    missing = _database_missing(database_url)
    if missing is not None:
        typer.echo(f"No database yet at {missing}: start the pipeline with 'vedette run' first.")
        return
    run_migrations(database_url)
    items = asyncio.run(_load_findings(database_url, profile_id, rule, severity, limit))

    if as_json:
        typer.echo(json.dumps([_as_json(item, analysis) for item, analysis in items], indent=2))
    elif not items:
        typer.echo("No findings.")
    else:
        typer.echo("\n\n".join(_as_text(item, analysis, settings) for item, analysis in items))


async def _store_events(database_url: str, events: list[DnsEvent]) -> int:
    store = Store.open(database_url)
    try:
        new = 0
        for start in range(0, len(events), 1000):
            new += await store.save_events(events[start : start + 1000])
        return new
    finally:
        await store.close()


@app.command("import")
def import_export(
    file: Annotated[
        Path, typer.Argument(help="NextDNS log export (the CSV from the dashboard's Logs page).")
    ],
    profile: Annotated[
        str, typer.Option("--profile", help="Profile the file was exported from (label or id).")
    ],
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Load history from a NextDNS log export instead of the API.

    Events already collected are recognised and not stored twice. The live
    stream still comes from the API; the rules evaluate imported events the
    next time the pipeline runs with the profile enabled.
    """
    settings = _load_or_exit(config)
    profile_id = _resolve_profile(settings, profile)
    if profile_id is None:  # pragma: no cover - --profile is required
        raise typer.Exit(code=2)
    raw = settings.ingest.raw
    try:
        result = read_export(file, profile_id, raw=raw)
    except ExportFormatError as exc:
        typer.echo(f"Cannot import: {exc}", err=True)
        raise typer.Exit(code=2) from None
    except OSError as exc:
        typer.echo(f"Cannot read the file: {type(exc).__name__}", err=True)
        raise typer.Exit(code=2) from None

    database_url = settings.storage.database_url
    run_migrations(database_url)
    new = asyncio.run(_store_events(database_url, result.events))

    typer.echo(f"{result.rows} rows read")
    typer.echo(f"{new} new events stored")
    typer.echo(f"{len(result.events) - new} already stored")
    typer.echo(f"{result.skipped_other_types} skipped (other query types)")
    typer.echo(f"{result.merged_same_instant} merged (same name at the same instant)")
    typer.echo(f"{result.skipped_malformed} skipped (unreadable)")
    if not raw:
        typer.echo(
            "Note: an export is NextDNS's raw view. It includes repeat lookups that the "
            "API's default view leaves out, so imported periods hold more events than "
            "collected ones. Set ingest.raw: true if the two must match exactly."
        )
    enabled = {item.id for item in settings.enabled_profiles}
    if profile_id not in enabled:
        typer.echo(
            "This profile is not enabled, so the rules will not evaluate these events yet. "
            "Set 'enabled: true' for it in config.yaml and restart the pipeline."
        )


async def _send_test(channel: Channel, message: OutgoingMessage) -> None:
    try:
        await channel.send(message)
    finally:
        await channel.aclose()


def _record_test(settings: Settings, message: OutgoingMessage, error: str | None) -> None:
    """Keep the test's outcome, so the "Alert delivery" health check can clear or fail."""
    database_url = settings.storage.database_url
    if _database_missing(database_url) is not None:
        return
    run_migrations(database_url)

    async def record() -> None:
        store = Store.open(database_url)
        try:
            await NotificationStore(store.engine).record_test(
                message, now=datetime.now(UTC), error=error
            )
        finally:
            await store.close()

    asyncio.run(record())


@app.command()
def notify(
    test: Annotated[
        bool, typer.Option("--test", help="Send a test message through the configured channel.")
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Check that notifications reach you."""
    if not test:
        typer.echo("Nothing to do: use --test to send a test notification.", err=True)
        raise typer.Exit(code=2)
    settings = _load_or_exit(config)
    channel = build_channel(settings)
    if channel is None:
        typer.echo(
            "No notification channel is configured (notify.channel is none). Set "
            "notify.channel to ntfy, discord or email in config.yaml, add its secret to .env, "
            "and try again.",
            err=True,
        )
        raise typer.Exit(code=2)
    name = channel.name
    message = render_test(datetime.now(UTC), ZoneInfo(settings.timezone))
    error: str | None = None
    try:
        asyncio.run(_send_test(channel, message))
    except DeliveryError as exc:
        error = str(exc)
    _record_test(settings, message, error)
    if error is not None:
        typer.echo(f"Test notification failed via {name}: {error}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Test notification sent via {name}.")


async def _build_digest(settings: Settings, period_end: datetime) -> tuple[str, str]:
    store = Store.open(settings.storage.database_url)
    try:
        builder = DigestBuilder(
            store.engine,
            profiles=settings.enabled_profiles,
            tz=ZoneInfo(settings.timezone),
            specs=load_rules(settings.rules.file),
        )
        return render_digest(await builder.build(period_end))
    finally:
        await store.close()


@app.command()
def digest(
    at: Annotated[
        str | None,
        typer.Option(
            "--at",
            help="End of the 24-hour period, local time (YYYY-MM-DDTHH:MM). Defaults to now.",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Print the digest for the last 24 hours. Nothing is sent or stored."""
    settings = _load_or_exit(config)
    tz = ZoneInfo(settings.timezone)
    if at is None:
        period_end = datetime.now(UTC)
    else:
        try:
            period_end = datetime.fromisoformat(at).replace(tzinfo=tz).astimezone(UTC)
        except ValueError:
            typer.echo("--at must look like 2026-03-15T08:00", err=True)
            raise typer.Exit(code=2) from None
    database_url = settings.storage.database_url
    missing = _database_missing(database_url)
    if missing is not None:
        typer.echo(f"No database yet at {missing}: start the pipeline with 'vedette run' first.")
        return
    run_migrations(database_url)
    title, body = asyncio.run(_build_digest(settings, period_end))
    typer.echo(f"{title}\n\n{body}")


async def _find(database_url: str, finding_id: int) -> StoredFinding | None:
    store = Store.open(database_url)
    try:
        return await store.finding(finding_id)
    finally:
        await store.close()


async def _mark_benign(database_url: str, finding_id: int) -> StoredFinding | None:
    store = Store.open(database_url)
    try:
        return await TriageStore(store.engine).mark_benign(
            finding_id, actor="cli", now=datetime.now(UTC)
        )
    finally:
        await store.close()


@app.command()
def benign(
    finding_id: Annotated[
        int, typer.Argument(help="Finding number, as shown by 'vedette findings'.")
    ],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Mark a finding benign. For a domain finding, the rules stop flagging that domain.

    The domain is allowlisted for the finding's profile; reopen the finding in
    the dashboard to undo it.
    """
    settings = _load_or_exit(config)
    database_url = settings.storage.database_url
    missing = _database_missing(database_url)
    if missing is not None:
        typer.echo(f"No database yet at {missing}: start the pipeline with 'vedette run' first.")
        raise typer.Exit(code=2)
    run_migrations(database_url)
    finding = asyncio.run(_find(database_url, finding_id))
    if finding is None:
        typer.echo(f"No finding {finding_id}.", err=True)
        raise typer.Exit(code=2)
    labels = {profile.id: profile.label for profile in settings.profiles}
    profile = clean_text(labels.get(finding.profile_id, finding.profile_id), limit=64)
    what = f"{finding.rule_id}: {_safe(finding.target)} on {profile}"
    if finding.rule_id in DOMAIN_RULES:
        question = f"Mark {what} benign, and stop flagging {_safe(finding.target)} on {profile}?"
    else:
        question = f"Mark {what} benign?"
    if not yes and not typer.confirm(question, default=False):
        raise typer.Exit(code=1)
    asyncio.run(_mark_benign(database_url, finding_id))
    typer.echo(f"Marked benign: {what}.")


async def _backfill(
    settings: Settings, api_key: str, profile_ids: list[str], since: datetime
) -> dict[str, tuple[int, int]]:
    """Read history for each profile and store it. Returns (read, new) per profile."""
    source = NextDnsSource(
        api_key,
        raw=settings.ingest.raw,
        page_size=settings.ingest.page_size,
    )
    store = Store.open(settings.storage.database_url)
    counts: dict[str, tuple[int, int]] = {}
    try:
        for profile_id in profile_ids:
            read = new = 0
            async for page in source.backfill(profile_id, since):
                read += len(page.events)
                new += await store.save_events(page.events)
            counts[profile_id] = (read, new)
    finally:
        await store.close()
        await source.aclose()
    return counts


@app.command()
def backfill(
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile label or id. Default: every enabled one."),
    ] = None,
    days: Annotated[
        int | None,
        typer.Option(
            "--days",
            min=1,
            help="How many days back to read. Default: ingest.backfill_days.",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Read a period of history from the NextDNS API and store it.

    Events already stored are recognised and not stored twice, and the live
    stream's position is not touched. The pipeline evaluates the new events in
    the background. Reading many days makes many API requests.
    """
    settings = _load_or_exit(config)
    configure_logging(settings.log_level, secrets=_secret_values(settings))
    api_key = settings.nextdns_api_key
    if api_key is None:
        typer.echo("NEXTDNS_API_KEY is not set.", err=True)
        raise typer.Exit(code=2)
    wanted = _resolve_profile(settings, profile)
    profile_ids = [wanted] if wanted is not None else [p.id for p in settings.enabled_profiles]
    if not profile_ids:
        typer.echo("No profile is enabled.", err=True)
        raise typer.Exit(code=2)
    span = days if days is not None else settings.ingest.backfill_days
    if span > settings.retention.events_days:
        typer.echo(
            f"--days {span} is longer than the retention of {settings.retention.events_days} "
            "days; the scheduled purge would delete the older events again.",
            err=True,
        )
        raise typer.Exit(code=2)
    run_migrations(settings.storage.database_url)
    since = datetime.now(UTC) - timedelta(days=span)
    try:
        counts = asyncio.run(_backfill(settings, api_key.get_secret_value(), profile_ids, since))
    except SourceError as exc:
        typer.echo(f"NextDNS: {clean_text(str(exc), limit=200)}", err=True)
        raise typer.Exit(code=1) from None
    labels = {p.id: p.label for p in settings.profiles}
    for profile_id, (read, new) in counts.items():
        label = clean_text(labels.get(profile_id, profile_id), limit=64)
        typer.echo(f"{label}: read {read} events, {new} new.")


async def _evaluate(
    settings: Settings, models: list[str], thinks: list[bool], with_llm: bool, offline: bool
) -> tuple[dict[str, Any], str]:
    started = datetime.now(UTC)
    summary = await run_suite(
        settings,
        load_rules(),
        models=models,
        thinks=thinks,
        with_llm=with_llm,
        offline=offline,
        now=started,
    )
    report = render_markdown(summary)
    store = Store.open(settings.storage.database_url)
    try:
        await EvalStore(store.engine).save(
            started_at=started, finished_at=datetime.now(UTC), summary=summary, report=report
        )
    finally:
        await store.close()
    return summary, report


@app.command("eval")
def evaluate(
    model: Annotated[
        list[str] | None,
        typer.Option(
            "--model", "-m", help="Model to test; repeat for several. Default: llm.model."
        ),
    ] = None,
    think: Annotated[
        str,
        typer.Option(help="Thinking for the injection test: off, on or both."),
    ] = "both",
    llm: Annotated[
        bool, typer.Option("--llm/--no-llm", help="Run the prompt-injection test on the model.")
    ] = True,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline", help="Download nothing; use the stored hostname list, or skip those sets."
        ),
    ] = False,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Where to write the report (Markdown).")
    ] = Path("EVALUATION.md"),
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Measure detection, false alerts, prompt-injection resistance, speed and load.

    Uses the local reference data and your stored history (only counted, never
    printed), downloads Cisco Umbrella's public list of popular hostnames at most
    once a week (--offline uses the stored copy), and asks the local model about
    crafted names. Nothing about your network is sent anywhere. The results also
    appear on the dashboard's Evaluation page.
    """
    settings = _load_or_exit(config)
    configure_logging(settings.log_level, secrets=_secret_values(settings))
    modes = {"off": [False], "on": [True], "both": [False, True]}
    if think not in modes:
        typer.echo("--think must be off, on or both.", err=True)
        raise typer.Exit(code=2)
    models = model or [settings.llm.model]
    run_migrations(settings.storage.database_url)
    summary, report = asyncio.run(_evaluate(settings, models, modes[think], llm, offline))
    output.write_text(report, encoding="utf-8")
    history = summary["history"]
    per_day = history["alerts_per_day"]
    typer.echo(f"Report written to {output}.")
    typer.echo(
        "False alerts per day: " + ("n/a" if per_day is None else f"{per_day:.2f}") + " (target 2)."
    )
    for row in summary["injection"]:
        rate = row["success_rate"]
        typer.echo(
            f"Injection success, {row['model']}, thinking {'on' if row['think'] else 'off'}, "
            f"defences {'on' if row['defences'] else 'off'}: "
            + ("n/a" if rate is None else f"{rate:.0%}")
        )
    for error in summary["errors"]:
        typer.echo(f"Note: {error}", err=True)


async def _purge(database_url: str, settings: Settings, *, everything: bool) -> Purged:
    store = Store.open(database_url)
    try:
        if everything:
            return await purge_all(store.engine)
        return await purge_expired(
            store.engine,
            now=datetime.now(UTC),
            events_days=settings.retention.events_days,
            findings_days=settings.retention.findings_days,
        )
    finally:
        await store.close()


@app.command()
def purge(
    everything: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Delete all local data: events, findings, digests, decisions, caches.",
        ),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the VEDETTE_CONFIG_FILE environment variable.",
        ),
    ] = None,
) -> None:
    """Delete data older than the retention settings now, or everything with --all.

    The pipeline also purges old data on its own every hour. Stop the service
    before --all (docker compose stop vedette); on its next start the
    collector reads the backfill window from NextDNS again.
    """
    settings = _load_or_exit(config)
    database_url = settings.storage.database_url
    if _database_missing(database_url) is not None:
        typer.echo("No local data to purge.")
        return
    if everything:
        question = (
            "Delete ALL local data (events, findings, digests, decisions)? This cannot be undone."
        )
    else:
        retention = settings.retention
        question = (
            f"Delete events older than {retention.events_days} days and findings older than "
            f"{retention.findings_days} days?"
        )
    if not yes and not typer.confirm(question, default=False):
        raise typer.Exit(code=1)
    run_migrations(database_url)
    purged = asyncio.run(_purge(database_url, settings, everything=everything))
    if not purged.total:
        typer.echo("Nothing to delete.")
        return
    details = ", ".join(f"{count} {table}" for table, count in sorted(purged.counts.items()))
    typer.echo(f"Deleted {purged.total} rows: {details}.")
