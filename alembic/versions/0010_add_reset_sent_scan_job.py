"""Add cancel flag and reset sent scan job state to scan_state.

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"


def upgrade():
    op.add_column("scan_state", sa.Column("cancel_state", sa.Text(), nullable=True))
    op.add_column("scan_state", sa.Column("reset_sent_job_id", sa.Text(), nullable=True))
    op.add_column("scan_state", sa.Column("reset_sent_job_status", sa.Text(), nullable=True))
    op.add_column("scan_state", sa.Column("reset_sent_job_total", sa.Integer(), nullable=True))
    op.add_column("scan_state", sa.Column("reset_sent_job_progress", sa.Integer(), nullable=True))


def downgrade():
    op.drop_column("scan_state", "reset_sent_job_progress")
    op.drop_column("scan_state", "reset_sent_job_total")
    op.drop_column("scan_state", "reset_sent_job_status")
    op.drop_column("scan_state", "reset_sent_job_id")
    op.drop_column("scan_state", "cancel_state")
