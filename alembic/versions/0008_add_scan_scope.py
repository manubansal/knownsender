"""Add scan_scope column to scan_state.

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"


def upgrade():
    op.add_column("scan_state", sa.Column("scan_scope", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("scan_state", "scan_scope")
