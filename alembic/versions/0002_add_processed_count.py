"""Add processed_count and initial_inbox_count to scan_state.

processed_count: cumulative emails Claven has filtered since last connect.
initial_inbox_count: inbox size at connect time; used to compute pending backlog.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-28
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_state",
        sa.Column(
            "processed_count",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "scan_state",
        sa.Column("initial_inbox_count", sa.BigInteger(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_state", "initial_inbox_count")
    op.drop_column("scan_state", "processed_count")
