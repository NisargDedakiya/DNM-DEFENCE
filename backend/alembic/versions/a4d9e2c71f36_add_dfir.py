"""add DFIR-1/DFIR-2 tables

Revision ID: a4d9e2c71f36
Revises: f2b8d61e5a94
Create Date: 2026-07-04 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a4d9e2c71f36'
down_revision: Union[str, Sequence[str], None] = 'f2b8d61e5a94'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'dfir_cases',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('case_number', sa.String(length=50), nullable=False, unique=True),
        sa.Column('incident_type', sa.String(length=255), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), nullable=True),
        sa.Column('contained_at', sa.DateTime(), nullable=True),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('initial_vector', sa.String(length=255), nullable=True),
        sa.Column('affected_systems', sa.JSON(), nullable=True),
        sa.Column('data_exfiltrated', sa.Boolean(), nullable=True),
        sa.Column('retainer_hours_used', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )
    op.create_table(
        'dfir_evidence',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('case_id', sa.UUID(as_uuid=False), sa.ForeignKey('dfir_cases.id'), nullable=False, index=True),
        sa.Column('evidence_type', sa.String(length=100), nullable=True),
        sa.Column('source_host', sa.String(length=255), nullable=True),
        sa.Column('acquisition_tool', sa.String(length=255), nullable=True),
        sa.Column('md5_hash', sa.String(length=32), nullable=True),
        sa.Column('sha256_hash', sa.String(length=64), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True),
        sa.Column('storage_path', sa.String(length=500), nullable=True),
        sa.Column('acquired_at', sa.DateTime()),
        sa.Column('acquired_by', sa.UUID(as_uuid=False), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('chain_of_custody', sa.JSON(), nullable=True),
    )
    op.create_table(
        'dfir_iocs',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('case_id', sa.UUID(as_uuid=False), sa.ForeignKey('dfir_cases.id'), nullable=False, index=True),
        sa.Column('ioc_type', sa.String(length=50), nullable=False),
        sa.Column('value', sa.String(length=500), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('context', sa.Text(), nullable=True),
        sa.Column('attack_technique_id', sa.String(length=20), nullable=True),
    )
    op.create_table(
        'dfir_timeline_entries',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('case_id', sa.UUID(as_uuid=False), sa.ForeignKey('dfir_cases.id'), nullable=False, index=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('event_description', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=True),
        sa.Column('host', sa.String(length=255), nullable=True),
        sa.Column('attack_technique_id', sa.String(length=20), nullable=True),
    )
    op.create_table(
        'ir_retainers',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('tier', sa.String(length=50), nullable=True),
        sa.Column('hours_included_per_year', sa.Integer(), nullable=True),
        sa.Column('hours_used', sa.Integer(), nullable=True),
        sa.Column('response_sla_hours', sa.Integer(), nullable=True),
        sa.Column('last_tabletop_at', sa.DateTime(), nullable=True),
    )
    op.create_table(
        'dfir_log_analysis_jobs',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('case_id', sa.UUID(as_uuid=False), sa.ForeignKey('dfir_cases.id'), nullable=False, index=True),
        sa.Column('original_filename', sa.String(length=255), nullable=True),
        sa.Column('log_type', sa.String(length=50), nullable=True),
        sa.Column('events_count', sa.Integer(), nullable=True),
        sa.Column('anomalies', sa.JSON(), nullable=True),
        sa.Column('iocs', sa.JSON(), nullable=True),
        sa.Column('narrative', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('dfir_log_analysis_jobs')
    op.drop_table('ir_retainers')
    op.drop_table('dfir_timeline_entries')
    op.drop_table('dfir_iocs')
    op.drop_table('dfir_evidence')
    op.drop_table('dfir_cases')
