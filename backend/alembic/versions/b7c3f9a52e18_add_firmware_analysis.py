"""add firmware analysis jobs table (IOT-1)

Revision ID: b7c3f9a52e18
Revises: a4d9e2c71f36
Create Date: 2026-07-04 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7c3f9a52e18'
down_revision: Union[str, Sequence[str], None] = 'a4d9e2c71f36'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'firmware_analysis_jobs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('original_filename', sa.String(length=255), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('component_summary', sa.JSON(), nullable=True),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('executive_summary', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('firmware_analysis_jobs')
