"""The heartbeat URL: a secret like the channel secrets, and https only."""

from pathlib import Path

import pytest

from vedette.config import ConfigError, load_settings

PING = "https://hc-ping.com/0f0c1d2e-not-a-real-check"


def write_yaml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_there_is_no_heartbeat_by_default() -> None:
    settings = load_settings()

    assert settings.heartbeat_url is None
    assert settings.health.heartbeat_minutes == 5


def test_the_heartbeat_url_comes_from_the_environment_and_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEARTBEAT_URL", PING)

    settings = load_settings()

    assert settings.heartbeat_url is not None
    assert settings.heartbeat_url.get_secret_value() == PING
    assert PING in settings.secret_values()
    assert PING not in repr(settings)


def test_the_heartbeat_url_is_read_from_a_docker_secret(tmp_path: Path) -> None:
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "HEARTBEAT_URL").write_text(PING, encoding="utf-8")

    settings = load_settings(secrets_dir=secrets)

    assert settings.heartbeat_url is not None
    assert settings.heartbeat_url.get_secret_value() == PING


def test_the_heartbeat_url_in_the_yaml_file_is_rejected(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, f"heartbeat_url: {PING}\n")

    with pytest.raises(ConfigError, match="heartbeat_url must not be set"):
        load_settings(path)


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        (PING, True),
        ("http://uptime-kuma:3001/api/push/abc", True),  # a server on the Docker network
        ("http://hc-ping.com/0f0c1d2e", False),
        ("ftp://hc-ping.com/0f0c1d2e", False),
        ("hc-ping.com/0f0c1d2e", False),
    ],
)
def test_the_heartbeat_url_must_be_https_unless_the_server_is_local(
    monkeypatch: pytest.MonkeyPatch, url: str, ok: bool
) -> None:
    monkeypatch.setenv("HEARTBEAT_URL", url)

    if ok:
        assert load_settings().heartbeat_url is not None
    else:
        with pytest.raises(ConfigError, match="heartbeat_url") as raised:
            load_settings()
        assert url not in str(raised.value), "the URL is a secret and never echoed"


def test_a_blank_heartbeat_url_means_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEARTBEAT_URL", "  ")

    assert load_settings().heartbeat_url is None
