"""Add the table of popular hostnames the evaluation uses as known-good names.

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "eval_hostnames",
        sa.Column("name", sa.String(255), primary_key=True),
        sa.Column("rank", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    """Revert this migration."""
    op.drop_table("eval_hostnames")
