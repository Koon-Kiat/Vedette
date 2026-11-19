"""Settings for notification channels, health checks and per-profile options."""

from pathlib import Path

import pytest

from sentinel.config import ConfigError, load_settings

WEBHOOK = "https://discord.com/api/webhooks/123456789/not-a-real-token_value"


def write_yaml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_notification_and_health_defaults() -> None:
    settings = load_settings()

    assert settings.notify.channel == "none"
    assert settings.notify.alert_max_age_minutes == 60
    assert settings.notify.analysis_wait_seconds == 60
    assert settings.notify.ntfy.url == "https://ntfy.sh"
    assert settings.notify.email.security == "starttls"
    assert settings.health.stale_after_minutes == 120
    assert settings.health.api_error_minutes == 5
    assert settings.health.ollama_down_minutes == 5
    assert settings.health.healthz_port == 8081


def test_the_spec_placeholder_channel_means_none(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, "notify:\n  channel: NOTIFY_CHANNEL\n")

    assert load_settings(path).notify.channel == "none"


def test_ntfy_needs_a_topic_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_NOTIFY__CHANNEL", "ntfy")

    with pytest.raises(ConfigError, match="NTFY_TOPIC is not set"):
        load_settings()

    monkeypatch.setenv("NTFY_TOPIC", "sentinel-alerts_42")
    assert load_settings().ntfy_topic is not None


def test_a_malformed_ntfy_topic_is_rejected_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_NOTIFY__CHANNEL", "ntfy")
    monkeypatch.setenv("NTFY_TOPIC", "bad topic/../x")

    with pytest.raises(ConfigError) as excinfo:
        load_settings()

    assert "bad topic" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://ntfy.sh", True),
        ("https://ntfy.example.org/base", True),
        ("http://ntfy", True),
        ("http://localhost:8090", True),
        ("http://ntfy.example.org", False),
        ("ftp://ntfy.example.org", False),
        ("https://user:pass@ntfy.example.org", False),
    ],
)
def test_ntfy_url_must_be_https_unless_the_server_is_local(
    tmp_path: Path, url: str, ok: bool
) -> None:
    path = write_yaml(tmp_path, f"notify:\n  ntfy:\n    url: '{url}'\n")

    if ok:
        assert load_settings(path).notify.ntfy.url == url.rstrip("/")
    else:
        with pytest.raises(ConfigError, match=r"notify\.ntfy\.url"):
            load_settings(path)


def test_discord_needs_a_real_webhook_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_NOTIFY__CHANNEL", "discord")

    with pytest.raises(ConfigError, match="DISCORD_WEBHOOK_URL is not set"):
        load_settings()

    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://evil.example/api/webhooks/1/secret-part")
    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    assert "not a Discord webhook URL" in str(excinfo.value)
    assert "secret-part" not in str(excinfo.value)

    monkeypatch.setenv("DISCORD_WEBHOOK_URL", WEBHOOK)
    assert load_settings().discord_webhook_url is not None


def test_email_needs_a_server_sender_and_recipients(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    incomplete = write_yaml(
        tmp_path, "notify:\n  channel: email\n  email:\n    host: smtp.example.org\n"
    )
    with pytest.raises(ConfigError, match="sender or recipients"):
        load_settings(incomplete)

    complete = write_yaml(
        tmp_path,
        "notify:\n  channel: email\n  email:\n    host: smtp.example.org\n"
        "    username: me@example.org\n    sender: me@example.org\n"
        "    recipients: [me@example.org]\n",
    )
    with pytest.raises(ConfigError, match="SMTP_PASSWORD"):
        load_settings(complete)

    monkeypatch.setenv("SMTP_PASSWORD", "not-a-real-password")
    assert load_settings(complete).notify.email.recipients == ["me@example.org"]


@pytest.mark.parametrize(
    "address", ["not an address", "a@b.example\r\nBcc: x@y.example", "", "Me <me@example.org>"]
)
def test_bad_email_addresses_are_rejected(tmp_path: Path, address: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "notify:\n  email:\n    recipients:\n      - " + repr(address) + "\n", encoding="utf-8"
    )

    with pytest.raises(ConfigError, match=r"notify\.email\.recipients"):
        load_settings(path)


@pytest.mark.parametrize(
    "key", ["ntfy_topic", "NTFY_TOKEN", "discord_webhook_url", "smtp_password"]
)
def test_notification_secrets_in_the_yaml_file_are_rejected(tmp_path: Path, key: str) -> None:
    with pytest.raises(ConfigError, match="environment variable"):
        load_settings(write_yaml(tmp_path, f"{key}: leaked-value\n"))


def test_every_secret_is_offered_for_log_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "NEXTDNS_API_KEY": "k1-not-real",
        "NTFY_TOPIC": "topic2",
        "NTFY_TOKEN": "tk3-not-real",
        "DISCORD_WEBHOOK_URL": WEBHOOK,
        "SMTP_PASSWORD": "pw5-not-real",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    assert sorted(load_settings().secret_values()) == sorted(values.values())


def test_profiles_accept_their_own_silence_window_and_quiet_hours(tmp_path: Path) -> None:
    path = write_yaml(
        tmp_path,
        "profiles:\n  - id: a\n    label: laptop\n    stale_after_minutes: 0\n"
        "    quiet_hours: '23:00-07:00'\n",
    )

    (profile,) = load_settings(path).profiles

    assert (profile.stale_after_minutes, profile.quiet_hours) == (0, "23:00-07:00")


@pytest.mark.parametrize(
    ("text", "field"),
    [
        ("health:\n  check_interval_seconds: 1\n", "health.check_interval_seconds"),
        ("health:\n  max_disk_percent: 101\n", "health.max_disk_percent"),
        ("notify:\n  channel: pigeon\n", "notify.channel"),
        ("notify:\n  email:\n    security: none\n", "notify.email.security"),
        ("profiles:\n  - id: a\n    label: b\n    quiet_hours: night\n", "profiles.0.quiet_hours"),
    ],
)
def test_invalid_notification_and_health_settings_are_rejected(
    tmp_path: Path, text: str, field: str
) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings(write_yaml(tmp_path, text))

    assert field in str(excinfo.value)
