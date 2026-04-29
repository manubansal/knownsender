"""Add sent scan columns to scan_state for known senders job.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-29
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_state",
        sa.Column("sent_scan_cursor", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "scan_state",
        sa.Column("sent_messages_scanned", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "scan_state",
        sa.Column("sent_messages_total", sa.Integer(), nullable=True),
    )
    op.add_column(
        "scan_state",
        sa.Column("sent_scan_status", sa.Text(), nullable=True),
    )
    op.add_column(
        "scan_state",
        sa.Column("inbox_scan_completed", sa.Boolean(), server_default="false", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("scan_state", "inbox_scan_completed")
    op.drop_column("scan_state", "sent_scan_status")
    op.drop_column("scan_state", "sent_messages_total")
    op.drop_column("scan_state", "sent_messages_scanned")
    op.drop_column("scan_state", "sent_scan_cursor")
