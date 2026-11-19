"""Add the table of evaluation runs.

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Apply this migration."""
    op.create_table(
        "eval_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("report", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    """Revert this migration."""
    op.drop_table("eval_runs")
