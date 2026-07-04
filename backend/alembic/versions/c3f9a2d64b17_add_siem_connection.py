"""add siem_connections table (shared by TH-1 Threat Hunting)

Revision ID: c3f9a2d64b17
Revises: b6d3f8a01e57
Create Date: 2026-07-04 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3f9a2d64b17'
down_revision: Union[str, Sequence[str], None] = 'b6d3f8a01e57'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'siem_connections',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('provider', sa.String(length=20), nullable=False),
        sa.Column('base_url', sa.String(length=500), nullable=True),
        sa.Column('encrypted_credentials', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('siem_connections')
