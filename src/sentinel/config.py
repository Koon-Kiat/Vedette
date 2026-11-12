"""Configuration loading.

Settings come from four places, highest priority first:

1. environment variables (``SENTINEL_`` prefix, ``__`` between nesting levels);
2. Docker secret files (``/run/secrets/<NAME>``);
3. the YAML config file;
4. the defaults defined here, which match ``config.example.yaml``.

Secrets are accepted only from the first two, never from the YAML file.
"""

import os
from pathlib import Path
from typing import Annotated, Any, Literal, Self
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

_SECRET_FIELDS = frozenset({"nextdns_api_key"})
_CLOCK = r"([01]\d|2[0-3]):[0-5]\d"

NonEmptyStr = Annotated[str, Field(min_length=1)]


class ConfigError(Exception):
    """The configuration is missing, unreadable or invalid."""


class _Section(BaseModel):
    """Base for config sections: unknown keys are errors, so typos surface early."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProfileConfig(_Section):
    """One NextDNS profile to watch."""

    id: NonEmptyStr
    label: NonEmptyStr
    enabled: bool = True


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


class NotifyConfig(_Section):
    """Alert and digest delivery. The channel itself has not been chosen yet."""

    channel: NonEmptyStr = "NOTIFY_CHANNEL"
    digest_time: str = Field(default="08:00", pattern=rf"^{_CLOCK}$")
    quiet_hours: str = Field(default="23:00-07:00", pattern=rf"^{_CLOCK}-{_CLOCK}$")
    alert_cooldown_minutes: int = Field(default=60, ge=0)


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
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    nextdns_write_enabled: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    nextdns_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("NEXTDNS_API_KEY", "nextdns_api_key"),
    )

    @field_validator("timezone")
    @classmethod
    def _timezone_exists(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown IANA time zone: {value!r}") from exc
        return value

    @field_validator("nextdns_api_key", mode="before")
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
