from pathlib import Path

import pytest

from vedette.config import ConfigError, load_settings

TOKEN = "a-dashboard-token-of-enough-length-1234"


def test_dashboard_defaults() -> None:
    settings = load_settings()

    assert settings.dashboard.enabled is True
    assert settings.dashboard.host == "127.0.0.1"
    assert settings.dashboard.port == 8080
    assert settings.dashboard.session_hours == 12
    assert settings.dashboard.allowed_hosts == ["127.0.0.1", "localhost"]
    assert settings.dashboard_token is None


def test_the_dashboard_token_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASHBOARD_TOKEN", TOKEN)

    settings = load_settings()

    assert settings.dashboard_token is not None
    assert TOKEN in settings.secret_values()


def test_a_short_dashboard_token_is_rejected_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DASHBOARD_TOKEN", "short-token")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    assert "at least 24 characters" in str(excinfo.value)
    assert "short-token" not in str(excinfo.value)


def test_the_dashboard_token_is_refused_in_the_yaml_file(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(f"dashboard_token: {TOKEN}\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="environment variable"):
        load_settings(path)


@pytest.mark.parametrize(
    ("text", "field"),
    [
        ("dashboard:\n  port: 0\n", "dashboard.port"),
        ("dashboard:\n  session_hours: 0\n", "dashboard.session_hours"),
        ("dashboard:\n  allowed_hosts: []\n", "dashboard.allowed_hosts"),
    ],
)
def test_invalid_dashboard_settings_are_rejected(tmp_path: Path, text: str, field: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ConfigError) as excinfo:
        load_settings(path)

    assert field in str(excinfo.value)
