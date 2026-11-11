"""Database tables.

Changing a table here requires a new migration under ``migrations/versions``;
a test checks that the migrations and these definitions agree.
"""

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Index, MetaData, String, Table
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
