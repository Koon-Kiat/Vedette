"""Configuration loading.

Settings come from four places, highest priority first:

1. environment variables (``SENTINEL_`` prefix, ``__`` between nesting levels);
2. Docker secret files (``/run/secrets/<NAME>``);
3. the YAML config file;
4. the defaults defined here, which match ``config.example.yaml``.

Secrets are accepted only from the first two, never from the YAML file.
"""

import os
import re
from email.utils import parseaddr
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from sentinel.enrich.threat_intel import Feed
from sentinel.rules.allowlist import AllowlistEntry

CONFIG_FILE_ENV = "SENTINEL_CONFIG_FILE"
DEFAULT_SECRETS_DIR = Path("/run/secrets")

_SECRET_FIELDS = frozenset(
    {
        "nextdns_api_key",
        "ntfy_topic",
        "ntfy_token",
        "discord_webhook_url",
        "smtp_password",
        "dashboard_token",
    }
)
_DISCORD_WEBHOOK = re.compile(
    r"^https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+$"
)
_NTFY_TOPIC = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_CLOCK = r"([01]\d|2[0-3]):[0-5]\d"

NonEmptyStr = Annotated[str, Field(min_length=1)]


class ConfigError(Exception):
    """The configuration is missing, unreadable or invalid."""


class _Section(BaseModel):
    """Base for config sections: unknown keys are errors, so typos surface early."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProfileConfig(_Section):
    """One NextDNS profile to watch.

    ``stale_after_minutes`` overrides the health check's silence window for this
    profile (0 switches the check off), and ``quiet_hours`` are local times when
    silence is expected, for example while a laptop is usually off.
    """

    id: NonEmptyStr
    label: NonEmptyStr
    enabled: bool = True
    stale_after_minutes: int | None = Field(default=None, ge=0)
    quiet_hours: str | None = Field(default=None, pattern=rf"^{_CLOCK}-{_CLOCK}$")


class IngestConfig(_Section):
    """How logs are pulled from NextDNS."""

    backfill_days: int = Field(default=7, ge=1)
    raw: bool = False
    page_size: int = Field(default=1000, ge=10, le=1000)


class StorageConfig(_Section):
    """Where events and findings are stored."""

    database_url: NonEmptyStr = "sqlite+aiosqlite:////data/sentinel.db"


class PopularityConfig(_Section):
    """The downloadable top-sites list used as the popularity rank."""

    url: NonEmptyStr = "https://tranco-list.eu/top-1m.csv.zip"
    refresh_days: int = Field(default=7, ge=1)


class RdapConfig(_Section):
    """Domain registration age lookups.

    RDAP tells the registry which domain is being looked at, so lookups are
    limited to recent, allowed, unpopular roots and can be disabled entirely.
    """

    enabled: bool = True
    bootstrap_url: NonEmptyStr = "https://data.iana.org/rdap/dns.json"
    max_event_age_hours: int = Field(default=24, ge=0)
    max_lookups_per_batch: int = Field(default=20, ge=0)


def _default_feeds() -> list[Feed]:
    return [
        Feed(
            name="phishing_army",
            url="https://phishing.army/download/phishing_army_blocklist.txt",
            format="domains",
        ),
        Feed(name="cert_pl", url="https://hole.cert.pl/domains/v2/domains.txt", format="domains"),
    ]


class ThreatIntelConfig(_Section):
    """Free threat-intelligence feeds, downloaded on a schedule."""

    refresh_hours: int = Field(default=24, ge=1)
    feeds: list[Feed] = Field(default_factory=_default_feeds)

    @model_validator(mode="after")
    def _feed_names_are_unique(self) -> Self:
        names = [feed.name for feed in self.feeds]
        for name in names:
            if names.count(name) > 1:
                raise ValueError(f"duplicate feed name: {name!r}")
        return self


class EnrichConfig(_Section):
    """Sources of local context added to each event."""

    popularity: PopularityConfig = Field(default_factory=PopularityConfig)
    rdap: RdapConfig = Field(default_factory=RdapConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)


class RulesConfig(_Section):
    """Detection rule settings."""

    file: Path | None = None
    learning_days: int = Field(default=3, ge=0)


class LlmConfig(_Section):
    """The local Ollama model used to explain findings."""

    base_url: NonEmptyStr = "http://ollama:11434"
    model: NonEmptyStr = "qwen3:8b"
    think: bool = False
    temperature: float = Field(default=0.1, ge=0.0, le=0.2)
    num_ctx: int = Field(default=8192, gt=0)
    keep_alive: NonEmptyStr = "5m"
    max_findings_per_batch: int = Field(default=20, ge=1)
    cache_ttl_hours: int = Field(default=168, ge=0)


def _is_address(value: str) -> bool:
    _, address = parseaddr(value)
    return (
        bool(address)
        and address == value.strip()
        and "@" in address
        and not any(ch.isspace() for ch in address)
    )


class NtfyConfig(_Section):
    """An ntfy server. The topic and optional token come from the environment."""

    url: NonEmptyStr = "https://ntfy.sh"

    @field_validator("url")
    @classmethod
    def _secure_url(cls, value: str) -> str:
        parts = urlsplit(value)
        host = parts.hostname or ""
        internal = "." not in host or host in _LOCAL_HOSTS
        if parts.scheme not in ("https", "http") or not host:
            raise ValueError("must be an https:// URL")
        if parts.scheme == "http" and not internal:
            raise ValueError(
                "must use https; plain http is allowed only for a server on the local "
                "Docker network (a name without dots, such as http://ntfy)"
            )
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("must not contain a user name, password, query or fragment")
        return value.rstrip("/")


class EmailConfig(_Section):
    """An SMTP server. The password comes from the environment (SMTP_PASSWORD)."""

    host: str = ""
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "ssl"] = "starttls"
    username: str = ""
    sender: str = ""
    recipients: list[str] = Field(default_factory=list)

    @field_validator("sender")
    @classmethod
    def _sender_is_an_address(cls, value: str) -> str:
        if value and not _is_address(value):
            raise ValueError("must be a plain e-mail address")
        return value

    @field_validator("recipients")
    @classmethod
    def _recipients_are_addresses(cls, value: list[str]) -> list[str]:
        if not all(_is_address(item) for item in value):
            raise ValueError("must be plain e-mail addresses")
        return value


class NotifyConfig(_Section):
    """Alert and digest delivery.

    ``channel`` is ``none`` (alerts and digests are kept but not sent),
    ``ntfy``, ``discord`` or ``email``.
    """

    channel: Literal["none", "ntfy", "discord", "email"] = "none"
    digest_time: str = Field(default="08:00", pattern=rf"^{_CLOCK}$")
    quiet_hours: str = Field(default="23:00-07:00", pattern=rf"^{_CLOCK}-{_CLOCK}$")
    alert_cooldown_minutes: int = Field(default=60, ge=0)
    alert_max_age_minutes: int = Field(default=60, ge=1)
    analysis_wait_seconds: int = Field(default=60, ge=0)
    ntfy: NtfyConfig = Field(default_factory=NtfyConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)

    @field_validator("channel", mode="before")
    @classmethod
    def _placeholder_means_none(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip().lower()
            return "none" if value in ("", "notify_channel") else value
        return value


class HealthConfig(_Section):
    """Health check windows and thresholds."""

    check_interval_seconds: int = Field(default=60, ge=5)
    stale_after_minutes: int = Field(default=120, ge=0)
    api_error_minutes: int = Field(default=5, ge=1)
    ollama_down_minutes: int = Field(default=5, ge=1)
    max_backlog_events: int = Field(default=20000, ge=1)
    backlog_minutes: int = Field(default=15, ge=1)
    max_disk_percent: int = Field(default=90, ge=1, le=100)
    healthz_port: int = Field(default=8081, ge=1, le=65535)


class DashboardConfig(_Section):
    """The local web dashboard. Its login token comes from DASHBOARD_TOKEN.

    ``host`` is where the server listens inside the process. Docker Compose sets
    it to 0.0.0.0 inside the container and publishes the port on 127.0.0.1 only.
    """

    enabled: bool = True
    host: NonEmptyStr = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    session_hours: int = Field(default=12, ge=1, le=168)
    allowed_hosts: list[NonEmptyStr] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost"], min_length=1
    )


class RetentionConfig(_Section):
    """How long local data is kept before the scheduled purge."""

    events_days: int = Field(default=30, ge=1)
    findings_days: int = Field(default=180, ge=1)


class Settings(BaseSettings):
    """All Sentinel settings. Build one with :func:`load_settings`."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_nested_delimiter="__",
        extra="forbid",
        frozen=True,
    )

    profiles: list[ProfileConfig] = Field(default_factory=list)
    timezone: str = "Asia/Singapore"
    ingest: IngestConfig = Field(default_factory=IngestConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    enrich: EnrichConfig = Field(default_factory=EnrichConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    allowlist: list[AllowlistEntry] = Field(default_factory=list)
    llm: LlmConfig = Field(default_factory=LlmConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    health: HealthConfig = Field(default_factory=HealthConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    nextdns_write_enabled: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    nextdns_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("NEXTDNS_API_KEY", "nextdns_api_key"),
    )
    ntfy_topic: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("NTFY_TOPIC", "ntfy_topic")
    )
    ntfy_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("NTFY_TOKEN", "ntfy_token")
    )
    discord_webhook_url: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("DISCORD_WEBHOOK_URL", "discord_webhook_url"),
    )
    smtp_password: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("SMTP_PASSWORD", "smtp_password")
    )
    dashboard_token: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("DASHBOARD_TOKEN", "dashboard_token")
    )

    @field_validator("timezone")
    @classmethod
    def _timezone_exists(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown IANA time zone: {value!r}") from exc
        return value

    @field_validator(
        "nextdns_api_key",
        "ntfy_topic",
        "ntfy_token",
        "discord_webhook_url",
        "smtp_password",
        "dashboard_token",
        mode="before",
    )
    @classmethod
    def _blank_key_is_unset(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @model_validator(mode="after")
    def _profiles_are_unique(self) -> Self:
        for attr in ("id", "label"):
            seen: set[str] = set()
            for profile in self.profiles:
                value = getattr(profile, attr)
                if value in seen:
                    raise ValueError(f"duplicate profile {attr}: {value!r}")
                seen.add(value)
        return self

    @field_validator("dashboard_token")
    @classmethod
    def _token_is_long_enough(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 24:
            raise ValueError("DASHBOARD_TOKEN must be at least 24 characters")
        return value

    @model_validator(mode="after")
    def _channel_is_complete(self) -> Self:
        channel = self.notify.channel
        if channel == "ntfy":
            if self.ntfy_topic is None:
                raise ValueError("notify.channel is ntfy but NTFY_TOPIC is not set")
            if not _NTFY_TOPIC.match(self.ntfy_topic.get_secret_value()):
                raise ValueError("NTFY_TOPIC may contain only letters, digits, - and _ (max 64)")
        elif channel == "discord":
            if self.discord_webhook_url is None:
                raise ValueError("notify.channel is discord but DISCORD_WEBHOOK_URL is not set")
            if not _DISCORD_WEBHOOK.match(self.discord_webhook_url.get_secret_value()):
                raise ValueError("DISCORD_WEBHOOK_URL is not a Discord webhook URL")
        elif channel == "email":
            email = self.notify.email
            if not (email.host and email.sender and email.recipients):
                raise ValueError(
                    "notify.channel is email but notify.email.host, sender or recipients is empty"
                )
            if email.username and self.smtp_password is None:
                raise ValueError("notify.email.username is set but SMTP_PASSWORD is not")
        return self

    def secret_values(self) -> list[str]:
        """Every secret that is set, for scrubbing from logs."""
        secrets = (
            self.nextdns_api_key,
            self.ntfy_topic,
            self.ntfy_token,
            self.discord_webhook_url,
            self.smtp_password,
            self.dashboard_token,
        )
        return [secret.get_secret_value() for secret in secrets if secret is not None]

    @property
    def enabled_profiles(self) -> list[ProfileConfig]:
        """Profiles the collector should watch."""
        return [profile for profile in self.profiles if profile.enabled]


class _YamlSource(PydanticBaseSettingsSource):
    """Feeds an already-parsed YAML mapping into pydantic-settings."""

    def __init__(self, settings_cls: type[BaseSettings], data: dict[str, Any]) -> None:
        super().__init__(settings_cls)
        self._data = data

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        return self._data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._data)


def _read_yaml(path: Path) -> dict[str, Any]:
    """Parse the YAML config file into a mapping, refusing secrets."""
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config file {path}: {type(exc).__name__}") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigError(f"config file {path} must contain a mapping at the top level")
    data = {str(key): value for key, value in loaded.items()}
    for key in data:
        if key.lower() in _SECRET_FIELDS:
            raise ConfigError(
                f"{key} must not be set in {path}: supply it as an environment variable "
                "or Docker secret instead"
            )
    return data


def _describe(exc: ValidationError) -> str:
    """Summarise validation errors without echoing the offending input values."""
    problems = []
    for error in exc.errors(include_input=False, include_url=False):
        location = ".".join(str(part) for part in error["loc"])
        problems.append(f"{location}: {error['msg']}" if location else error["msg"])
    return "invalid configuration: " + "; ".join(problems)


def load_settings(config_file: Path | None = None, *, secrets_dir: Path | None = None) -> Settings:
    """Load and validate settings.

    Args:
        config_file: YAML file to read. Falls back to the ``SENTINEL_CONFIG_FILE``
            environment variable; with neither, only defaults, secrets and
            environment variables apply.
        secrets_dir: Directory of Docker secret files. Defaults to
            ``/run/secrets`` when that directory exists.

    Raises:
        ConfigError: The file is missing or unreadable, a value is invalid, or a
            secret was placed in the YAML file.
    """
    if config_file is None and (from_env := os.environ.get(CONFIG_FILE_ENV, "").strip()):
        config_file = Path(from_env)
    data = _read_yaml(config_file) if config_file is not None else {}
    if secrets_dir is None and DEFAULT_SECRETS_DIR.is_dir():
        secrets_dir = DEFAULT_SECRETS_DIR

    class _Loaded(Settings):
        @classmethod
        def settings_customise_sources(
            cls,
            settings_cls: type[BaseSettings],
            init_settings: PydanticBaseSettingsSource,
            env_settings: PydanticBaseSettingsSource,
            dotenv_settings: PydanticBaseSettingsSource,
            file_secret_settings: PydanticBaseSettingsSource,
        ) -> tuple[PydanticBaseSettingsSource, ...]:
            return (env_settings, file_secret_settings, _YamlSource(settings_cls, data))

    try:
        return _Loaded(_secrets_dir=secrets_dir)
    except ValidationError as exc:
        raise ConfigError(_describe(exc)) from None
