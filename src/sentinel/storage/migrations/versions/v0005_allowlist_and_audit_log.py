"""Add the stored allowlist and the audit log.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "allowlist",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("root", sa.String(255), nullable=False),
        sa.Column("profile_id", sa.String(64)),
        sa.Column("device_id", sa.String(256)),
        sa.Column("finding_id", sa.Integer()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(32), nullable=False),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("at", sa.DateTime(), nullable=False),
        sa.Column("actor", sa.String(32), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("finding_id", sa.Integer()),
        sa.Column("detail", sa.String(300), nullable=False),
    )
    op.create_index("ix_audit_log_finding", "audit_log", ["finding_id", "id"])


def downgrade() -> None:
    """Revert this migration."""
    op.drop_index("ix_audit_log_finding", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("allowlist")
