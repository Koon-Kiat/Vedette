import asyncio
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vedette.cli import app
from vedette.storage.store import Store

runner = CliRunner()
FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nextdns" / "export.csv"


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    url = f"sqlite+aiosqlite:///{tmp_path / 'vedette.db'}"
    monkeypatch.setenv("VEDETTE_STORAGE__DATABASE_URL", url)
    monkeypatch.setenv(
        "VEDETTE_PROFILES",
        '[{"id": "abc123", "label": "router"}, {"id": "def456", "label": "pc", "enabled": false}]',
    )
    return url


def stored(url: str, profile_id: str) -> tuple[int, int]:
    async def read() -> tuple[int, int]:
        store = Store.open(url)
        try:
            return await store.count_events(profile_id), await store.count_unprocessed(profile_id)
        finally:
            await store.close()

    return asyncio.run(read())


def test_import_stores_the_files_events_for_the_named_profile(database: str) -> None:
    result = runner.invoke(app, ["import", str(FIXTURE), "--profile", "pc"])

    assert result.exit_code == 0, result.output
    assert stored(database, "def456") == (3, 3), "stored, and waiting for the rules"
    assert stored(database, "abc123") == (0, 0)
    assert "7 rows read" in result.output
    assert "3 new events stored" in result.output
    assert "1 skipped (other query types)" in result.output
    assert "2 skipped (unreadable)" in result.output


def test_importing_the_same_file_twice_adds_nothing(database: str) -> None:
    runner.invoke(app, ["import", str(FIXTURE), "--profile", "pc"])

    again = runner.invoke(app, ["import", str(FIXTURE), "--profile", "pc"])

    assert again.exit_code == 0
    assert "0 new events stored" in again.output
    assert "3 already stored" in again.output
    assert stored(database, "def456")[0] == 3


def test_import_follows_the_raw_setting(database: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VEDETTE_INGEST__RAW", "true")

    result = runner.invoke(app, ["import", str(FIXTURE), "--profile", "pc"])

    assert "5 new events stored" in result.output
    assert stored(database, "def456")[0] == 5


def test_import_warns_that_a_file_holds_more_than_the_default_api_view(database: str) -> None:
    result = runner.invoke(app, ["import", str(FIXTURE), "--profile", "pc"])

    assert "raw" in result.output.lower()


def test_import_tells_how_to_get_a_disabled_profile_evaluated(database: str) -> None:
    result = runner.invoke(app, ["import", str(FIXTURE), "--profile", "pc"])

    assert "enabled: true" in result.output


def test_import_needs_a_known_profile(database: str) -> None:
    result = runner.invoke(app, ["import", str(FIXTURE), "--profile", "phone"])

    assert result.exit_code == 2
    assert "phone" in result.output
    assert stored_or_none(database) is None


def stored_or_none(url: str) -> int | None:
    path = Path(url.split("///", 1)[1])
    return stored(url, "def456")[0] if path.exists() else None


def test_import_of_a_missing_file_is_a_usage_error(database: str, tmp_path: Path) -> None:
    result = runner.invoke(app, ["import", str(tmp_path / "nope.csv"), "--profile", "pc"])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_import_of_a_file_in_the_wrong_format_is_explained(database: str, tmp_path: Path) -> None:
    wrong = tmp_path / "wrong.csv"
    wrong.write_text("when,name\n2026-03-15,www.example.org\n", encoding="utf-8")

    result = runner.invoke(app, ["import", str(wrong), "--profile", "pc"])

    assert result.exit_code == 2
    assert "timestamp" in result.output
    assert "Traceback" not in result.output
