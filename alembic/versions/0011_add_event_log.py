"""Add event_log table.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"


def upgrade():
    op.create_table(
        "event_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.TIMESTAMP(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
    )
    op.create_index("ix_event_log_user_ts", "event_log", ["user_id", "timestamp"])


def downgrade():
    op.drop_index("ix_event_log_user_ts")
    op.drop_table("event_log")
