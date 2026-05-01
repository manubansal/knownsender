"""Rename last_processed_at to last_labeled_at, add last_fetched_at.

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"


def upgrade():
    op.alter_column("scan_state", "last_processed_at", new_column_name="last_labeled_at")
    op.add_column("scan_state", sa.Column("last_fetched_at", sa.TIMESTAMP(timezone=True), nullable=True))


def downgrade():
    op.drop_column("scan_state", "last_fetched_at")
    op.alter_column("scan_state", "last_labeled_at", new_column_name="last_processed_at")
