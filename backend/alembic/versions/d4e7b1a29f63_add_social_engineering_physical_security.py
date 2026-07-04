"""add SE-1/SE-2/SE-3 tables: osint_profiles, phishing_targets, vishing_engagements, physical_security_assessments/checklist_items

Revision ID: d4e7b1a29f63
Revises: c9e1a4f83d27
Create Date: 2026-07-03 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4e7b1a29f63'
down_revision: Union[str, Sequence[str], None] = 'c9e1a4f83d27'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('phishing_campaigns') as batch_op:
        batch_op.add_column(sa.Column('campaign_type', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('template_html', sa.Text(), nullable=True))

    op.create_table(
        'osint_profiles',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('generated_at', sa.DateTime()),
        sa.Column('findings', sa.JSON()),
        sa.Column('report_path', sa.String(length=500), nullable=True),
    )

    op.create_table(
        'phishing_targets',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('campaign_id', sa.UUID(as_uuid=False), sa.ForeignKey('phishing_campaigns.id'), nullable=False, index=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.String(length=255), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('tracking_token', sa.String(length=64), nullable=False, unique=True, index=True),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.Column('opened', sa.Boolean(), nullable=True),
        sa.Column('opened_at', sa.DateTime(), nullable=True),
        sa.Column('clicked', sa.Boolean(), nullable=True),
        sa.Column('clicked_at', sa.DateTime(), nullable=True),
        sa.Column('submitted_credentials', sa.Boolean(), nullable=True),
        sa.Column('submitted_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table(
        'vishing_engagements',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('scenario', sa.String(length=500), nullable=True),
        sa.Column('recording_path', sa.String(length=500), nullable=True),
        sa.Column('transcript', sa.Text(), nullable=True),
        sa.Column('analysis', sa.JSON()),
        sa.Column('risk_rating', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table(
        'physical_security_assessments',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('site_name', sa.String(length=255), nullable=True),
        sa.Column('scheduled_date', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table(
        'physical_security_checklist_items',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('assessment_id', sa.UUID(as_uuid=False), sa.ForeignKey('physical_security_assessments.id'), nullable=False, index=True),
        sa.Column('test_type', sa.String(length=30), nullable=False),
        sa.Column('attempted', sa.Boolean(), nullable=True),
        sa.Column('outcome_notes', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('physical_security_checklist_items')
    op.drop_table('physical_security_assessments')
    op.drop_table('vishing_engagements')
    op.drop_table('phishing_targets')
    op.drop_table('osint_profiles')
    with op.batch_alter_table('phishing_campaigns') as batch_op:
        batch_op.drop_column('template_html')
        batch_op.drop_column('campaign_type')
