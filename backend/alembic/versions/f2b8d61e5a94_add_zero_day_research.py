"""add zero day research tables (ZD-1)

Revision ID: f2b8d61e5a94
Revises: e1a7c92f4d83
Create Date: 2026-07-04 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f2b8d61e5a94'
down_revision: Union[str, Sequence[str], None] = 'e1a7c92f4d83'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'research_targets',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('vendor', sa.String(length=255), nullable=True),
        sa.Column('version', sa.String(length=100), nullable=True),
        sa.Column('language', sa.String(length=100), nullable=True),
        sa.Column('source_url', sa.String(length=500), nullable=True),
        sa.Column('bug_bounty_url', sa.String(length=500), nullable=True),
        sa.Column('max_bounty', sa.Integer(), nullable=True),
        sa.Column('priority', sa.String(length=20), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('total_hours', sa.Integer(), nullable=True),
        sa.Column('total_earned', sa.Integer(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )
    op.create_table(
        'research_findings',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('target_id', sa.UUID(as_uuid=False), sa.ForeignKey('research_targets.id'), nullable=False, index=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('cve_id', sa.String(length=20), nullable=True, index=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('vuln_class', sa.String(length=255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('poc_path', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('vendor_notified', sa.DateTime(), nullable=True),
        sa.Column('patch_released', sa.DateTime(), nullable=True),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('bounty_amount', sa.Integer(), nullable=True),
        sa.Column('bounty_platform', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )
    op.create_table(
        'fuzzing_jobs',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('target_id', sa.UUID(as_uuid=False), sa.ForeignKey('research_targets.id'), nullable=False, index=True),
        sa.Column('fuzzer', sa.String(length=50), nullable=False),
        sa.Column('target_binary_path', sa.String(length=500), nullable=True),
        sa.Column('corpus_path', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('crashes_found', sa.Integer(), nullable=True),
        sa.Column('execs_per_sec', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('ended_at', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('fuzzing_jobs')
    op.drop_table('research_findings')
    op.drop_table('research_targets')
