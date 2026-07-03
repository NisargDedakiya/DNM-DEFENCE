"""add DSO-1/DSO-3 tables: pipeline_integrations, developer_scorecard_snapshots

Revision ID: b6d3f8a01e57
Revises: a1c4e7f92d38
Create Date: 2026-07-03 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b6d3f8a01e57'
down_revision: Union[str, Sequence[str], None] = 'a1c4e7f92d38'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'pipeline_integrations',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('provider', sa.String(length=20), nullable=True),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('gate_config', sa.JSON()),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('last_synced_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table(
        'developer_scorecard_snapshots',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('snapshot_date', sa.DateTime(), nullable=False, index=True),
        sa.Column('metrics', sa.JSON()),
    )


def downgrade() -> None:
    op.drop_table('developer_scorecard_snapshots')
    op.drop_table('pipeline_integrations')
