"""The ``sentinel`` command-line interface."""

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from sentinel import __version__
from sentinel.config import ConfigError, Settings, load_settings
from sentinel.log import configure_logging
from sentinel.pipeline.runner import run_until_signalled

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
