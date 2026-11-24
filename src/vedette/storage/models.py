"""Database tables.

Changing a table here requires a new migration under ``migrations/versions``;
a test checks that the migrations and these definitions agree.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware datetime stored as naive UTC.

    SQLite has no timezone support, so values are converted to UTC on the way
    in and tagged as UTC on the way out. Naive datetimes are refused.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        """Convert an aware datetime to naive UTC for storage."""
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime refused: timestamps must be timezone-aware")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        """Tag a stored naive UTC datetime as UTC."""
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


metadata = MetaData()

events = Table(
    "events",
    metadata,
    Column("event_id", String(64), primary_key=True),
    Column("profile_id", String(64), nullable=False),
    Column("ts", UtcDateTime, nullable=False),
    Column("fqdn", String(255), nullable=False),
    Column("root", String(255)),
    Column("status", String(32), nullable=False),
    Column("reasons", JSON, nullable=False),
    Column("device_id", String(256)),
    Column("device_name", String(256)),
    Column("client_ip", String(64)),
    Column("protocol", String(64)),
    Column("encrypted", Boolean),
    Column("tracker", String(256)),
    Column("source", String(32), nullable=False),
    Column("ingested_at", UtcDateTime, nullable=False),
    Index("ix_events_profile_ts", "profile_id", "ts"),
)

collector_state = Table(
    "collector_state",
    metadata,
    Column("profile_id", String(64), primary_key=True),
    Column("stream_cursor", String(255)),
    Column("synced_through", UtcDateTime),
    Column("backfill_completed_at", UtcDateTime),
    Column("updated_at", UtcDateTime, nullable=False),
)

# Set once an event has been through enrichment and the rule engine.
events.append_column(Column("processed_at", UtcDateTime))
Index("ix_events_unprocessed", events.c.profile_id, events.c.processed_at, events.c.ts)

findings = Table(
    "findings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("dedupe_key", String(600), nullable=False, unique=True),
    Column("rule_id", String(64), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("profile_id", String(64), nullable=False),
    Column("subject", String(256)),
    Column("device_mode", Boolean, nullable=False),
    Column("target", String(256), nullable=False),
    Column("first_ts", UtcDateTime, nullable=False),
    Column("last_ts", UtcDateTime, nullable=False),
    Column("event_count", Integer, nullable=False),
    Column("evidence", JSON, nullable=False),
    Column("event_id", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    Index("ix_findings_profile_last", "profile_id", "last_ts"),
)

first_seen = Table(
    "first_seen",
    metadata,
    Column("profile_id", String(64), primary_key=True),
    Column("kind", String(16), primary_key=True),
    Column("subject", String(256), primary_key=True),
    Column("value", String(256), primary_key=True),
    Column("first_ts", UtcDateTime, nullable=False),
    Column("first_event_id", String(64), nullable=False),
)

popularity = Table(
    "popularity",
    metadata,
    Column("domain", String(255), primary_key=True),
    Column("rank", Integer, nullable=False),
)

# Popular full hostnames (Cisco Umbrella's list), used only by `vedette eval` as
# known-good names the rules do not skip.
eval_hostnames = Table(
    "eval_hostnames",
    metadata,
    Column("name", String(255), primary_key=True),
    Column("rank", Integer, nullable=False),
)

# Public Suffix List rules ("co.uk", "*.ck", "!www.ck"); private marks the
# section for platforms such as github.io, whose customers get names of their own.
public_suffixes = Table(
    "public_suffixes",
    metadata,
    Column("rule", String(255), primary_key=True),
    Column("private", Boolean, nullable=False),
)

threat_intel = Table(
    "threat_intel",
    metadata,
    Column("domain", String(255), primary_key=True),
    Column("feed", String(64), primary_key=True),
)

domain_age = Table(
    "domain_age",
    metadata,
    Column("root", String(255), primary_key=True),
    Column("status", String(16), nullable=False),
    Column("registered_at", UtcDateTime),
    Column("fetched_at", UtcDateTime, nullable=False),
)

reference_state = Table(
    "reference_state",
    metadata,
    Column("name", String(64), primary_key=True),
    Column("refreshed_at", UtcDateTime, nullable=False),
    Column("entries", Integer, nullable=False),
)

finding_analysis = Table(
    "finding_analysis",
    metadata,
    Column("finding_id", Integer, primary_key=True),
    Column("summary", String(400), nullable=False),
    Column("likely_cause", String(300), nullable=False),
    Column("recommended_action", String(300), nullable=False),
    Column("priority", String(16), nullable=False),
    Column("group_key", String(64), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("source", String(16), nullable=False),
    Column("model", String(128)),
    Column("created_at", UtcDateTime, nullable=False),
)

llm_cache = Table(
    "llm_cache",
    metadata,
    Column("cache_key", String(64), primary_key=True),
    Column("payload", JSON, nullable=False),
    Column("model", String(128), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("expires_at", UtcDateTime, nullable=False),
)

llm_calls = Table(
    "llm_calls",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("started_at", UtcDateTime, nullable=False),
    Column("duration_ms", Integer, nullable=False),
    Column("findings", Integer, nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("model", String(128), nullable=False),
)

# Outbox: every alert, health message and digest, whether sent or not.
notifications = Table(
    "notifications",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("kind", String(16), nullable=False),
    Column("dedupe_key", String(600), nullable=False),
    Column("finding_id", Integer, unique=True),
    Column("title", String(300), nullable=False),
    Column("body", Text, nullable=False),
    Column("priority", String(16), nullable=False),
    Column("tags", JSON, nullable=False),
    Column("status", String(16), nullable=False),
    Column("reason", String(200)),
    Column("attempts", Integer, nullable=False),
    Column("next_attempt_at", UtcDateTime, nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("sent_at", UtcDateTime),
    Index("ix_notifications_due", "status", "next_attempt_at"),
    Index("ix_notifications_key", "dedupe_key", "created_at"),
)

digests = Table(
    "digests",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("period_start", UtcDateTime, nullable=False),
    Column("period_end", UtcDateTime, nullable=False, unique=True),
    Column("generated_at", UtcDateTime, nullable=False),
    Column("title", String(300), nullable=False),
    Column("body", Text, nullable=False),
    Column("data", JSON, nullable=False),
    Column("notification_id", Integer),
)

health_checks = Table(
    "health_checks",
    metadata,
    Column("check_key", String(128), primary_key=True),
    Column("position", Integer, nullable=False),
    Column("label", String(128), nullable=False),
    Column("ok", Boolean, nullable=False),
    Column("detail", String(300), nullable=False),
    Column("since", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
)

# Roots marked benign from the dashboard or CLI. Entries from config.yaml are not
# stored here; the rule engine combines both.
allowlist = Table(
    "allowlist",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("root", String(255), nullable=False),
    Column("profile_id", String(64)),
    Column("device_id", String(256)),
    Column("finding_id", Integer),
    Column("created_at", UtcDateTime, nullable=False),
    Column("created_by", String(32), nullable=False),
)

# Every change made from the dashboard or CLI.
audit_log = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("at", UtcDateTime, nullable=False),
    Column("actor", String(32), nullable=False),
    Column("action", String(32), nullable=False),
    Column("finding_id", Integer),
    Column("detail", String(300), nullable=False),
    Index("ix_audit_log_finding", "finding_id", "id"),
)

# Results of `vedette eval`, newest last. The dashboard shows the latest run.
eval_runs = Table(
    "eval_runs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("started_at", UtcDateTime, nullable=False),
    Column("finished_at", UtcDateTime, nullable=False),
    Column("summary", JSON, nullable=False),
    Column("report", Text, nullable=False),
)
