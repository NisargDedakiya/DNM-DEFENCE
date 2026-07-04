"""add red team operations tables (RT-1)

Revision ID: e1a7c92f4d83
Revises: c3f9a2d64b17
Create Date: 2026-07-04 09:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e1a7c92f4d83'
down_revision: Union[str, Sequence[str], None] = 'c3f9a2d64b17'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'red_team_operations',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('objective', sa.Text(), nullable=True),
        sa.Column('threat_actor', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('start_date', sa.DateTime(), nullable=True),
        sa.Column('end_date', sa.DateTime(), nullable=True),
        sa.Column('roe_signed', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )
    op.create_table(
        'red_team_timeline_entries',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('operation_id', sa.String(), sa.ForeignKey('red_team_operations.id'), nullable=False, index=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('phase', sa.String(length=30), nullable=False),
        sa.Column('action', sa.Text(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=True),
        sa.Column('user_context', sa.String(length=255), nullable=True),
        sa.Column('tool_used', sa.String(length=255), nullable=True),
        sa.Column('outcome', sa.Text(), nullable=True),
        sa.Column('detected', sa.String(length=20), nullable=True),
        sa.Column('attack_technique_id', sa.String(length=20), nullable=True),
        sa.Column('evidence_path', sa.String(length=500), nullable=True),
    )
    op.create_table(
        'red_team_implants',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('operation_id', sa.String(), sa.ForeignKey('red_team_operations.id'), nullable=False, index=True),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('implant_type', sa.String(length=100), nullable=True),
        sa.Column('persistence', sa.String(length=255), nullable=True),
        sa.Column('checkin_freq_seconds', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('deployed_at', sa.DateTime()),
    )
    op.create_table(
        'red_team_infrastructure',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('operation_id', sa.String(), sa.ForeignKey('red_team_operations.id'), nullable=False, index=True),
        sa.Column('infra_type', sa.String(length=30), nullable=False),
        sa.Column('identifier', sa.String(length=255), nullable=False),
        sa.Column('provider', sa.String(length=255), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('red_team_infrastructure')
    op.drop_table('red_team_implants')
    op.drop_table('red_team_timeline_entries')
    op.drop_table('red_team_operations')
