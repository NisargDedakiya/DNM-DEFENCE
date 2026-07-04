"""add threat hunting tables (TH-1)

Revision ID: c8e4a17f9d52
Revises: b7c3f9a52e18
Create Date: 2026-07-04 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c8e4a17f9d52'
down_revision: Union[str, Sequence[str], None] = 'b7c3f9a52e18'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'hunt_hypotheses',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('attack_technique', sa.String(length=20), nullable=True),
        sa.Column('data_sources', sa.JSON(), nullable=True),
        sa.Column('industries', sa.JSON(), nullable=True),
        sa.Column('priority', sa.String(length=20), nullable=True),
        sa.Column('hunt_count', sa.Integer(), nullable=True),
        sa.Column('last_positive_at', sa.DateTime(), nullable=True),
        sa.Column('source', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )
    op.create_table(
        'hunt_operations',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('hypothesis_id', sa.String(), sa.ForeignKey('hunt_hypotheses.id'), nullable=False, index=True),
        sa.Column('analyst_id', sa.String(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('outcome', sa.String(length=20), nullable=True),
        sa.Column('hours_spent', sa.Integer(), nullable=True),
    )
    op.create_table(
        'hunt_findings',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('hunt_id', sa.String(), sa.ForeignKey('hunt_operations.id'), nullable=False, index=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('iocs', sa.JSON(), nullable=True),
        sa.Column('attack_technique_id', sa.String(length=20), nullable=True),
        sa.Column('confirmed', sa.Boolean(), nullable=True),
        sa.Column('escalated_to_ir', sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('hunt_findings')
    op.drop_table('hunt_operations')
    op.drop_table('hunt_hypotheses')
