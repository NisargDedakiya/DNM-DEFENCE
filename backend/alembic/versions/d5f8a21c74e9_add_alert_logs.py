"""add alert_logs table (downloadable notification/alert history)

Revision ID: d5f8a21c74e9
Revises: c8e4a17f9d52
Create Date: 2026-07-06 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd5f8a21c74e9'
down_revision: Union[str, Sequence[str], None] = 'c8e4a17f9d52'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'alert_logs',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('finding_id', sa.UUID(as_uuid=False), sa.ForeignKey('findings.id'), nullable=True),
        sa.Column('alert_type', sa.String(length=50), nullable=False),
        sa.Column('subject', sa.String(length=500), nullable=False),
        sa.Column('channel_email_sent', sa.Boolean(), nullable=True),
        sa.Column('channel_slack_sent', sa.Boolean(), nullable=True),
        sa.Column('sent_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('alert_logs')
