"""The ``sentinel`` command-line interface."""

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any
from zoneinfo import ZoneInfo

import typer
from sqlalchemy.engine import make_url

from sentinel import __version__
from sentinel.config import ConfigError, Settings, load_settings
from sentinel.log import configure_logging
from sentinel.notify.defang import clean_text, defang
from sentinel.pipeline.runner import run_until_signalled
from sentinel.rules.model import Severity
from sentinel.sources.base import DnsEvent
from sentinel.sources.nextdns_export import ExportFormatError, read_export
from sentinel.storage.migrate import run_migrations
from sentinel.storage.store import Store, StoredFinding

app = typer.Typer(
    name="sentinel",
    help="NextDNS Sentinel: watch NextDNS logs for suspicious DNS activity.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


def _print_version(requested: bool) -> None:
    if requested:
        typer.echo(f"sentinel {__version__}")
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
    if settings.nextdns_api_key is None:
        return []
    return [settings.nextdns_api_key.get_secret_value()]


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
    """NextDNS Sentinel: watch NextDNS logs for suspicious DNS activity."""


@app.command()
def run(
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="YAML config file. Defaults to the SENTINEL_CONFIG_FILE environment variable.",
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
) -> list[StoredFinding]:
    store = Store.open(database_url)
    try:
        return await store.list_findings(
            profile_id=profile_id, rule_id=rule, min_severity=min_severity, limit=limit
        )
    finally:
        await store.close()


def _as_json(item: StoredFinding) -> dict[str, Any]:
    return {
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


def _as_text(item: StoredFinding, settings: Settings) -> str:
    labels = {profile.id: profile.label for profile in settings.profiles}
    when = item.last_ts.astimezone(ZoneInfo(settings.timezone)).strftime("%Y-%m-%d %H:%M")
    profile = clean_text(labels.get(item.profile_id, item.profile_id), limit=64)
    who = f"device {_safe(item.subject)}" if item.device_mode else "device attribution unavailable"
    target = profile if item.target == item.profile_id else _safe(item.target)
    lines = [
        f"{when}  {item.severity.value.upper():<8}  {item.rule_id}  {target}"
        f"  [{profile}, {who}]  x{item.event_count}"
    ]
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
            help="YAML config file. Defaults to the SENTINEL_CONFIG_FILE environment variable.",
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
        typer.echo(f"No database yet at {missing}: start the pipeline with 'sentinel run' first.")
        return
    run_migrations(database_url)
    items = asyncio.run(_load_findings(database_url, profile_id, rule, severity, limit))

    if as_json:
        typer.echo(json.dumps([_as_json(item) for item in items], indent=2))
    elif not items:
        typer.echo("No findings.")
    else:
        typer.echo("\n\n".join(_as_text(item, settings) for item in items))


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
            help="YAML config file. Defaults to the SENTINEL_CONFIG_FILE environment variable.",
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
