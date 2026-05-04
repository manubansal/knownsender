"""Add relabel_status to sent_recipients.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"


def upgrade():
    op.add_column("sent_recipients", sa.Column("relabel_status", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("sent_recipients", "relabel_status")
