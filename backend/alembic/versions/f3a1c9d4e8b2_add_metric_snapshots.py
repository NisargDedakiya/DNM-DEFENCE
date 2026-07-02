"""add metric_snapshots table

Revision ID: f3a1c9d4e8b2
Revises: 8d2b7ca2c7e3
Create Date: 2026-07-02 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f3a1c9d4e8b2'
down_revision: Union[str, Sequence[str], None] = '8d2b7ca2c7e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'metric_snapshots',
        sa.Column('id', sa.UUID(as_uuid=False), nullable=False),
        sa.Column('client_id', sa.UUID(as_uuid=False), nullable=False),
        sa.Column('snapshot_date', sa.DateTime(), nullable=False),
        sa.Column('critical_count', sa.Integer(), nullable=True),
        sa.Column('high_count', sa.Integer(), nullable=True),
        sa.Column('medium_count', sa.Integer(), nullable=True),
        sa.Column('low_count', sa.Integer(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['clients.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_metric_snapshots_client_id'), 'metric_snapshots', ['client_id'], unique=False)
    op.create_index(op.f('ix_metric_snapshots_snapshot_date'), 'metric_snapshots', ['snapshot_date'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_metric_snapshots_snapshot_date'), table_name='metric_snapshots')
    op.drop_index(op.f('ix_metric_snapshots_client_id'), table_name='metric_snapshots')
    op.drop_table('metric_snapshots')
