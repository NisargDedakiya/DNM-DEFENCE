"""add MOB-1/MOB-2/MOB-3 tables: mobile_app_scans, mobile_traffic_imports

Revision ID: e5f8c3b47a12
Revises: d4e7b1a29f63
Create Date: 2026-07-03 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5f8c3b47a12'
down_revision: Union[str, Sequence[str], None] = 'd4e7b1a29f63'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'mobile_app_scans',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('platform', sa.String(length=20), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('app_label', sa.String(length=255), nullable=True),
        sa.Column('findings', sa.JSON()),
        sa.Column('masvs_score', sa.Integer(), nullable=True),
        sa.Column('executive_summary', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table(
        'mobile_traffic_imports',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('mobile_app_scan_id', sa.UUID(as_uuid=False), sa.ForeignKey('mobile_app_scans.id'), nullable=True, index=True),
        sa.Column('discovered_endpoints', sa.JSON()),
        sa.Column('sensitive_data_hits', sa.JSON()),
        sa.Column('auth_classification', sa.JSON()),
        sa.Column('openapi_lite', sa.JSON()),
        sa.Column('created_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('mobile_traffic_imports')
    op.drop_table('mobile_app_scans')
