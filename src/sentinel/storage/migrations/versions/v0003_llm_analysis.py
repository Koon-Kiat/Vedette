"""Add finding analyses, the verdict cache and model call records.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "finding_analysis",
        sa.Column("finding_id", sa.Integer(), primary_key=True),
        sa.Column("summary", sa.String(400), nullable=False),
        sa.Column("likely_cause", sa.String(300), nullable=False),
        sa.Column("recommended_action", sa.String(300), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("group_key", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("model", sa.String(128)),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "llm_cache",
        sa.Column("cache_key", sa.String(64), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "llm_calls",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("findings", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
    )


def downgrade() -> None:
    """Revert this migration."""
    op.drop_table("llm_calls")
    op.drop_table("llm_cache")
    op.drop_table("finding_analysis")
