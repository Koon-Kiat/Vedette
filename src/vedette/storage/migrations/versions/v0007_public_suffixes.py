"""Add the table of Public Suffix List rules.

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "public_suffixes",
        sa.Column("rule", sa.String(255), primary_key=True),
        sa.Column("private", sa.Boolean(), nullable=False),
    )


def downgrade() -> None:
    """Revert this migration."""
    op.drop_table("public_suffixes")
