import json
import os
import signal
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel import __version__
from sentinel.cli import app

runner = CliRunner()


def test_version_flag_prints_the_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"sentinel {__version__}"


def test_run_with_a_missing_config_file_exits_2_without_a_traceback(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--config", str(tmp_path / "nope.yaml")])

    assert result.exit_code == 2
    assert "nope.yaml" in result.output
    assert "Traceback" not in result.output


def test_run_with_an_invalid_config_names_the_bad_field(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("llm:\n  temperature: 0.9\n", encoding="utf-8")

    result = runner.invoke(app, ["run", "--config", str(config)])

    assert result.exit_code == 2
    assert "llm.temperature" in result.output


def test_run_starts_the_pipeline_and_exits_0_on_sigterm(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXTDNS_API_KEY", "k-cli-test-secret")
    monkeypatch.setenv("SENTINEL_PROFILES", "[]")  # keep the collector idle: no network
    timer = threading.Timer(0.5, os.kill, args=(os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        result = runner.invoke(app, ["run", "--config", str(repo_root / "config.example.yaml")])
    finally:
        timer.cancel()

    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.output.strip().splitlines()]
    names = [event["event"] for event in events]
    assert names[0] == "pipeline_started"
    assert names[-1] == "pipeline_stopped"
    assert "shutdown_requested" in names
    assert "k-cli-test-secret" not in result.output
