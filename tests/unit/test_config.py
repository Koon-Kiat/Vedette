from pathlib import Path

import pytest

from sentinel.config import ConfigError, load_settings


def write_yaml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_match_the_spec_when_no_file_is_given() -> None:
    settings = load_settings()

    assert settings.profiles == []
    assert settings.timezone == "Asia/Singapore"
    assert settings.ingest.backfill_days == 7
    assert settings.ingest.raw is False
    assert settings.ingest.page_size == 1000
    assert settings.storage.database_url == "sqlite+aiosqlite:////data/sentinel.db"
    assert settings.llm.base_url == "http://ollama:11434"
    assert settings.llm.model == "qwen3:8b"
    assert settings.llm.think is False
    assert settings.llm.temperature == 0.1
    assert settings.llm.num_ctx == 8192
    assert settings.llm.keep_alive == "5m"
    assert settings.llm.max_findings_per_batch == 20
    assert settings.llm.cache_ttl_hours == 168
    assert settings.notify.digest_time == "08:00"
    assert settings.notify.quiet_hours == "23:00-07:00"
    assert settings.notify.alert_cooldown_minutes == 60
    assert settings.retention.events_days == 30
    assert settings.retention.findings_days == 180
    assert settings.nextdns_write_enabled is False
    assert settings.nextdns_api_key is None
    assert settings.log_level == "INFO"


def test_example_config_file_loads(repo_root: Path) -> None:
    settings = load_settings(repo_root / "config.example.yaml")

    assert [(p.id, p.label, p.enabled) for p in settings.profiles] == [
        ("ROUTER_PROFILE_ID", "router", True),
        ("PC_PROFILE_ID", "pc", False),
        ("PHONE_PROFILE_ID", "phone", False),
    ]
    assert [p.label for p in settings.enabled_profiles] == ["router"]
    assert settings.notify.channel == "NOTIFY_CHANNEL"


def test_yaml_values_replace_defaults(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, "ingest:\n  backfill_days: 3\n")

    settings = load_settings(path)

    assert settings.ingest.backfill_days == 3
    assert settings.ingest.raw is False


def test_env_var_overrides_a_nested_yaml_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_yaml(tmp_path, "llm:\n  model: from-yaml\n  num_ctx: 4096\n")
    monkeypatch.setenv("SENTINEL_LLM__MODEL", "from-env")

    settings = load_settings(path)

    assert settings.llm.model == "from-env"
    assert settings.llm.num_ctx == 4096


def test_env_var_overrides_a_top_level_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_NEXTDNS_WRITE_ENABLED", "true")

    assert load_settings().nextdns_write_enabled is True


def test_env_var_overrides_the_profile_list_with_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_PROFILES", '[{"id": "abc123", "label": "router"}]')

    settings = load_settings()

    assert [(p.id, p.label, p.enabled) for p in settings.profiles] == [("abc123", "router", True)]


def test_config_file_path_comes_from_env_when_not_passed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_yaml(tmp_path, "timezone: Europe/London\n")
    monkeypatch.setenv("SENTINEL_CONFIG_FILE", str(path))

    assert load_settings().timezone == "Europe/London"


def test_api_key_is_read_from_env_and_hidden_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXTDNS_API_KEY", "k-very-secret-value")

    settings = load_settings()

    assert settings.nextdns_api_key is not None
    assert settings.nextdns_api_key.get_secret_value() == "k-very-secret-value"
    assert "k-very-secret-value" not in repr(settings)
    assert "k-very-secret-value" not in str(settings.model_dump())


def test_blank_api_key_counts_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXTDNS_API_KEY", "  ")

    assert load_settings().nextdns_api_key is None


def test_api_key_is_read_from_a_docker_secret_file(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "NEXTDNS_API_KEY").write_text("k-from-secret-file\n", encoding="utf-8")

    settings = load_settings(secrets_dir=secrets_dir)

    assert settings.nextdns_api_key is not None
    assert settings.nextdns_api_key.get_secret_value() == "k-from-secret-file"


@pytest.mark.parametrize("key", ["nextdns_api_key", "NEXTDNS_API_KEY"])
def test_api_key_in_the_yaml_file_is_rejected(tmp_path: Path, key: str) -> None:
    path = write_yaml(tmp_path, f"{key}: k-leaked-into-yaml\n")

    with pytest.raises(ConfigError) as excinfo:
        load_settings(path)

    assert "environment variable" in str(excinfo.value)
    assert "k-leaked-into-yaml" not in str(excinfo.value)


def test_missing_config_file_is_an_error_naming_the_path(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"

    with pytest.raises(ConfigError, match=r"nope\.yaml"):
        load_settings(missing)


def test_yaml_that_is_not_a_mapping_is_rejected(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, "- just\n- a list\n")

    with pytest.raises(ConfigError, match="mapping"):
        load_settings(path)


def test_malformed_yaml_is_rejected(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, "llm: [unclosed\n")

    with pytest.raises(ConfigError, match=r"config\.yaml"):
        load_settings(path)


@pytest.mark.parametrize(
    ("text", "field"),
    [
        ("not_a_setting: 1\n", "not_a_setting"),
        ("llm:\n  modle: typo\n", "llm.modle"),
        ("llm:\n  temperature: 0.5\n", "llm.temperature"),
        ("llm:\n  num_ctx: 0\n", "llm.num_ctx"),
        ("ingest:\n  backfill_days: 0\n", "ingest.backfill_days"),
        ("ingest:\n  page_size: 5\n", "ingest.page_size"),
        ("ingest:\n  page_size: 1001\n", "ingest.page_size"),
        ("storage:\n  database_url: ''\n", "storage.database_url"),
        ("timezone: Mars/Olympus\n", "timezone"),
        ("notify:\n  digest_time: '25:00'\n", "notify.digest_time"),
        ("notify:\n  quiet_hours: 'evening'\n", "notify.quiet_hours"),
        ("retention:\n  events_days: 0\n", "retention.events_days"),
        ("log_level: LOUD\n", "log_level"),
        ("profiles:\n  - id: ''\n    label: router\n", "profiles.0.id"),
    ],
)
def test_invalid_values_are_rejected_naming_the_field(
    tmp_path: Path, text: str, field: str
) -> None:
    path = write_yaml(tmp_path, text)

    with pytest.raises(ConfigError) as excinfo:
        load_settings(path)

    assert field in str(excinfo.value)


def test_duplicate_profile_ids_are_rejected(tmp_path: Path) -> None:
    path = write_yaml(
        tmp_path,
        "profiles:\n  - id: same\n    label: a\n  - id: same\n    label: b\n",
    )

    with pytest.raises(ConfigError, match="duplicate profile id"):
        load_settings(path)


def test_duplicate_profile_labels_are_rejected(tmp_path: Path) -> None:
    path = write_yaml(
        tmp_path,
        "profiles:\n  - id: one\n    label: same\n  - id: two\n    label: same\n",
    )

    with pytest.raises(ConfigError, match="duplicate profile label"):
        load_settings(path)


def test_enrichment_and_rule_defaults_match_the_documented_ones() -> None:
    settings = load_settings()

    assert settings.enrich.popularity.url == "https://tranco-list.eu/top-1m.csv.zip"
    assert settings.enrich.popularity.refresh_days == 7
    assert settings.enrich.rdap.enabled is True
    assert settings.enrich.rdap.bootstrap_url == "https://data.iana.org/rdap/dns.json"
    assert settings.enrich.rdap.max_event_age_hours == 24
    assert settings.enrich.rdap.max_lookups_per_batch == 20
    assert settings.enrich.threat_intel.refresh_hours == 24
    assert [(feed.name, feed.format) for feed in settings.enrich.threat_intel.feeds] == [
        ("phishing_army", "domains"),
        ("cert_pl", "domains"),
    ]
    assert settings.rules.file is None
    assert settings.rules.learning_days == 3
    assert settings.allowlist == []


def test_allowlist_and_feeds_load_from_yaml(tmp_path: Path) -> None:
    path = write_yaml(
        tmp_path,
        "allowlist:\n"
        "  - root: Example.ORG.\n"
        "  - root: intranet.example\n"
        "    profile: router\n"
        "    device: D1\n"
        "enrich:\n"
        "  threat_intel:\n"
        "    feeds:\n"
        "      - name: mine\n"
        "        url: https://feeds.test/x.txt\n"
        "        format: hosts\n",
    )

    settings = load_settings(path)

    assert [(e.root, e.profile, e.device) for e in settings.allowlist] == [
        ("example.org", None, None),
        ("intranet.example", "router", "D1"),
    ]
    assert [(feed.name, feed.format) for feed in settings.enrich.threat_intel.feeds] == [
        ("mine", "hosts")
    ]


FEED = "enrich:\n  threat_intel:\n    feeds:\n      - name: {name}\n        url: https://x.test/\n"


@pytest.mark.parametrize(
    ("text", "field"),
    [
        ("enrich:\n  popularity:\n    refresh_days: 0\n", "enrich.popularity.refresh_days"),
        (
            "enrich:\n  rdap:\n    max_lookups_per_batch: -1\n",
            "enrich.rdap.max_lookups_per_batch",
        ),
        (FEED.format(name="Bad Name"), "enrich.threat_intel.feeds.0.name"),
        (FEED.format(name="a") + "        format: csv\n", "enrich.threat_intel.feeds.0.format"),
        ("rules:\n  learning_days: -1\n", "rules.learning_days"),
        ("allowlist:\n  - profile: router\n", "allowlist.0.root"),
    ],
)
def test_invalid_enrichment_and_rule_settings_are_rejected(
    tmp_path: Path, text: str, field: str
) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings(write_yaml(tmp_path, text))

    assert field in str(excinfo.value)


def test_duplicate_feed_names_are_rejected(tmp_path: Path) -> None:
    path = write_yaml(tmp_path, FEED.format(name="a") + FEED.format(name="a").split("feeds:\n")[1])

    with pytest.raises(ConfigError, match="duplicate feed name"):
        load_settings(path)
