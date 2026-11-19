"""Add the notification outbox, the digest archive and health check results.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("dedupe_key", sa.String(600), nullable=False),
        sa.Column("finding_id", sa.Integer(), unique=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(200)),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime()),
    )
    op.create_index("ix_notifications_due", "notifications", ["status", "next_attempt_at"])
    op.create_index("ix_notifications_key", "notifications", ["dedupe_key", "created_at"])
    op.create_table(
        "digests",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("period_start", sa.DateTime(), nullable=False),
        sa.Column("period_end", sa.DateTime(), nullable=False, unique=True),
        sa.Column("generated_at", sa.DateTime(), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("notification_id", sa.Integer()),
    )
    op.create_table(
        "health_checks",
        sa.Column("check_key", sa.String(128), primary_key=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("detail", sa.String(300), nullable=False),
        sa.Column("since", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    """Revert this migration."""
    op.drop_table("health_checks")
    op.drop_table("digests")
    op.drop_index("ix_notifications_key", table_name="notifications")
    op.drop_index("ix_notifications_due", table_name="notifications")
    op.drop_table("notifications")
