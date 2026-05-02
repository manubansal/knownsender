"""Add archive job state columns to scan_state.

Revision ID: 0007
Revises: 0006
"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"


def upgrade():
    op.add_column("scan_state", sa.Column("archive_job_id", sa.Text(), nullable=True))
    op.add_column("scan_state", sa.Column("archive_job_status", sa.Text(), nullable=True))
    op.add_column("scan_state", sa.Column("archive_job_total", sa.Integer(), nullable=True))
    op.add_column("scan_state", sa.Column("archive_job_progress", sa.Integer(), nullable=True))


def downgrade():
    op.drop_column("scan_state", "archive_job_progress")
    op.drop_column("scan_state", "archive_job_total")
    op.drop_column("scan_state", "archive_job_status")
    op.drop_column("scan_state", "archive_job_id")
