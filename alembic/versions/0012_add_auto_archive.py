"""Add auto_archive_unknown setting to scan_state.

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"


def upgrade():
    op.add_column("scan_state", sa.Column("auto_archive_unknown", sa.Boolean(), server_default="false", nullable=False))


def downgrade():
    op.drop_column("scan_state", "auto_archive_unknown")
