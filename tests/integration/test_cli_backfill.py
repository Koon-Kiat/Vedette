"""``vedette backfill`` reads history through the API and stores it once."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.integration.fake_nextdns import API_KEY, FakeNextDns
from vedette.cli import app

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXTDNS_API_KEY", API_KEY)
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'b.db'}")
    monkeypatch.setenv("VEDETTE_PROFILES", '[{"id": "abc123", "label": "router"}]')


def test_backfill_stores_history_and_recognises_it_the_second_time(
    server: FakeNextDns, env: None
) -> None:
    server.add_entries(5)

    first = runner.invoke(app, ["backfill", "--days", "2"])
    second = runner.invoke(app, ["backfill", "--days", "2", "--profile", "router"])

    assert first.exit_code == 0, first.output
    assert "router: read 5 events, 5 new." in first.output
    assert "router: read 5 events, 0 new." in second.output
    assert API_KEY not in first.output + second.output


def test_backfill_needs_the_api_key(env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NEXTDNS_API_KEY")

    result = runner.invoke(app, ["backfill"])

    assert result.exit_code == 2
    assert "NEXTDNS_API_KEY is not set." in result.output


def test_backfill_will_not_read_past_the_retention(env: None) -> None:
    result = runner.invoke(app, ["backfill", "--days", "31"])

    assert result.exit_code == 2
    assert "longer than the retention of 30 days" in result.output


def test_a_rejected_key_is_reported_without_a_traceback(
    server: FakeNextDns, env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXTDNS_API_KEY", "a-wrong-key")

    result = runner.invoke(app, ["backfill", "--days", "1"])

    assert result.exit_code == 1
    assert "NextDNS: NextDNS answered HTTP 403" in result.output
    assert "Traceback" not in result.output
