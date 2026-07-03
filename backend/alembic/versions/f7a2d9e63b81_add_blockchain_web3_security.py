"""add WEB3-1/WEB3-2/WEB3-3 tables: smart_contract_audits, onchain_monitors

Revision ID: f7a2d9e63b81
Revises: e5f8c3b47a12
Create Date: 2026-07-03 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f7a2d9e63b81'
down_revision: Union[str, Sequence[str], None] = 'e5f8c3b47a12'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'smart_contract_audits',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('contract_name', sa.String(length=255), nullable=True),
        sa.Column('contract_source', sa.Text(), nullable=True),
        sa.Column('network', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('solc_version_hint', sa.String(length=50), nullable=True),
        sa.Column('findings', sa.JSON()),
        sa.Column('report_path', sa.String(length=500), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table(
        'onchain_monitors',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('contract_address', sa.String(length=255), nullable=False),
        sa.Column('network', sa.String(length=50), nullable=True),
        sa.Column('alert_thresholds', sa.JSON()),
        sa.Column('telegram_chat_id', sa.String(length=100), nullable=True),
        sa.Column('last_checked_block', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('last_alerts', sa.JSON()),
        sa.Column('created_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('onchain_monitors')
    op.drop_table('smart_contract_audits')
