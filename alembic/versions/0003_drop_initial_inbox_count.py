"""Drop initial_inbox_count from scan_state.

The pending count is now computed live as max(0, inbox_count - processed_count)
using the fresh inbox_count fetched from Gmail on every /api/me call.
A stale snapshot column is not needed.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-28
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("scan_state", "initial_inbox_count")


def downgrade() -> None:
    op.add_column(
        "scan_state",
        sa.Column("initial_inbox_count", sa.BigInteger(), nullable=True),
    )
