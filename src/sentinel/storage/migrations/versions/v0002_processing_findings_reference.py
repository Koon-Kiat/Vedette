"""Add event processing state, findings and reference-data tables.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.add_column("events", sa.Column("processed_at", sa.DateTime()))
    op.create_index("ix_events_unprocessed", "events", ["profile_id", "processed_at", "ts"])
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("dedupe_key", sa.String(600), nullable=False, unique=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("profile_id", sa.String(64), nullable=False),
        sa.Column("subject", sa.String(256)),
        sa.Column("device_mode", sa.Boolean(), nullable=False),
        sa.Column("target", sa.String(256), nullable=False),
        sa.Column("first_ts", sa.DateTime(), nullable=False),
        sa.Column("last_ts", sa.DateTime(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_findings_profile_last", "findings", ["profile_id", "last_ts"])
    op.create_table(
        "first_seen",
        sa.Column("profile_id", sa.String(64), primary_key=True),
        sa.Column("kind", sa.String(16), primary_key=True),
        sa.Column("subject", sa.String(256), primary_key=True),
        sa.Column("value", sa.String(256), primary_key=True),
        sa.Column("first_ts", sa.DateTime(), nullable=False),
        sa.Column("first_event_id", sa.String(64), nullable=False),
    )
    op.create_table(
        "popularity",
        sa.Column("domain", sa.String(255), primary_key=True),
        sa.Column("rank", sa.Integer(), nullable=False),
    )
    op.create_table(
        "threat_intel",
        sa.Column("domain", sa.String(255), primary_key=True),
        sa.Column("feed", sa.String(64), primary_key=True),
    )
    op.create_table(
        "domain_age",
        sa.Column("root", sa.String(255), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("registered_at", sa.DateTime()),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "reference_state",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("refreshed_at", sa.DateTime(), nullable=False),
        sa.Column("entries", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    """Revert this migration."""
    for table in ("reference_state", "domain_age", "threat_intel", "popularity", "first_seen"):
        op.drop_table(table)
    op.drop_index("ix_findings_profile_last", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_events_unprocessed", table_name="events")
    with op.batch_alter_table("events") as batch:
        batch.drop_column("processed_at")
