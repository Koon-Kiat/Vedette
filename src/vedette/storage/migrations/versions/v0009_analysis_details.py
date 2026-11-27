"""Add the leaning and the lists of an explanation to stored analyses.

Analyses stored before keep NULL in both columns and still display.

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    with op.batch_alter_table("finding_analysis") as batch:
        batch.add_column(sa.Column("assessment", sa.String(16), nullable=True))
        batch.add_column(sa.Column("details", sa.JSON(), nullable=True))


def downgrade() -> None:
    """Revert this migration."""
    with op.batch_alter_table("finding_analysis") as batch:
        batch.drop_column("details")
        batch.drop_column("assessment")
