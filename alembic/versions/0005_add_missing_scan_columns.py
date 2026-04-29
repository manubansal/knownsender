"""Add columns that were amended into 0004 after it was applied in prod.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-29
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # These columns were added to 0004 locally but 0004 was already applied
    # in prod with the original schema. Use IF NOT EXISTS for idempotency.
    conn = op.get_bind()
    for col_def in [
        "inbox_scan_completed BOOLEAN DEFAULT false NOT NULL",
        "last_processed_at TIMESTAMPTZ",
        "newest_labeled_at TIMESTAMPTZ",
        "inbox_scan_status TEXT",
    ]:
        conn.execute(sa.text(
            f"ALTER TABLE scan_state ADD COLUMN IF NOT EXISTS {col_def}"
        ))


def downgrade() -> None:
    op.drop_column("scan_state", "inbox_scan_status")
    op.drop_column("scan_state", "newest_labeled_at")
    op.drop_column("scan_state", "last_processed_at")
    op.drop_column("scan_state", "inbox_scan_completed")
