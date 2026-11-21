"""Create the events and collector_state tables.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "events",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("profile_id", sa.String(64), nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("fqdn", sa.String(255), nullable=False),
        sa.Column("root", sa.String(255)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("device_id", sa.String(256)),
        sa.Column("device_name", sa.String(256)),
        sa.Column("client_ip", sa.String(64)),
        sa.Column("protocol", sa.String(64)),
        sa.Column("encrypted", sa.Boolean()),
        sa.Column("tracker", sa.String(256)),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("ingested_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_events_profile_ts", "events", ["profile_id", "ts"])
    op.create_table(
        "collector_state",
        sa.Column("profile_id", sa.String(64), primary_key=True),
        sa.Column("stream_cursor", sa.String(255)),
        sa.Column("synced_through", sa.DateTime()),
        sa.Column("backfill_completed_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    """Revert this migration."""
    op.drop_table("collector_state")
    op.drop_index("ix_events_profile_ts", table_name="events")
    op.drop_table("events")
