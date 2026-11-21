import asyncio
import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from tests.digest_fixture import build_fixture
from vedette.cli import app
from vedette.storage.migrate import run_migrations
from vedette.storage.store import Store

runner = CliRunner()
TOPIC = "vedette-cli-test"


@pytest.fixture
def ntfy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VEDETTE_NOTIFY__CHANNEL", "ntfy")
    monkeypatch.setenv("VEDETTE_NOTIFY__NTFY__URL", "https://ntfy.example")
    monkeypatch.setenv("NTFY_TOPIC", TOPIC)


def test_notify_needs_the_test_flag() -> None:
    result = runner.invoke(app, ["notify"])

    assert result.exit_code == 2
    assert "--test" in result.output


def test_notify_test_without_a_channel_says_how_to_set_one_up() -> None:
    result = runner.invoke(app, ["notify", "--test"])

    assert result.exit_code == 2
    assert "notify.channel" in result.output


def test_notify_test_sends_one_message(ntfy: None) -> None:
    with respx.mock(assert_all_mocked=True) as web:
        route = web.post("https://ntfy.example/").mock(return_value=httpx.Response(200, json={}))
        result = runner.invoke(app, ["notify", "--test"])

    assert result.exit_code == 0, result.output
    assert "Test notification sent via ntfy." in result.output
    sent = json.loads(route.calls.last.request.content)
    assert sent["topic"] == TOPIC
    assert "test" in sent["title"].lower()


def test_notify_test_reports_a_failure_without_secrets(ntfy: None) -> None:
    with respx.mock(assert_all_mocked=True) as web:
        web.post("https://ntfy.example/").mock(return_value=httpx.Response(403))
        result = runner.invoke(app, ["notify", "--test"])

    assert result.exit_code == 1
    assert "rejected the credentials" in result.output
    assert TOPIC not in result.output


def test_digest_prints_a_preview(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv(
        "VEDETTE_PROFILES",
        '[{"id": "abc123", "label": "router"}, {"id": "def456", "label": "pc"}]',
    )
    run_migrations(url)

    async def fill() -> None:
        store = Store.open(url)
        try:
            await build_fixture(store)
        finally:
            await store.close()

    asyncio.run(fill())

    result = runner.invoke(app, ["digest", "--at", "2026-03-15T08:00"])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("Vedette digest 2026-03-15: 1 critical, 2 high")
    assert "QUERIES AND BLOCKING" in result.output
    assert "bad.example" not in result.output


def test_digest_without_a_database_explains_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'x.db'}")

    result = runner.invoke(app, ["digest"])

    assert result.exit_code == 0
    assert "no database yet" in result.output.lower()


def test_digest_rejects_a_bad_time() -> None:
    assert runner.invoke(app, ["digest", "--at", "yesterday"]).exit_code == 2
