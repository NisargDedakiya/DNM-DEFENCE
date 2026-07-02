"""add cvss_vector, assigned_to, escalation fields to findings; is_internal to assets

Revision ID: a7c2e5f19d34
Revises: f3a1c9d4e8b2
Create Date: 2026-07-02 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7c2e5f19d34'
down_revision: Union[str, Sequence[str], None] = 'f3a1c9d4e8b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('assets', sa.Column('is_internal', sa.Boolean(), nullable=True))
    # batch mode: sqlite can't ALTER in a foreign key constraint directly
    # (no support for ALTER of constraints), so this uses a copy-and-move
    # strategy there; on Postgres (the real deployment target) it collapses
    # to plain ALTER TABLE statements.
    with op.batch_alter_table('findings') as batch_op:
        batch_op.add_column(sa.Column('cvss_vector', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('assigned_to', sa.UUID(as_uuid=False), nullable=True))
        batch_op.add_column(sa.Column('escalated_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('escalation_count', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_findings_assigned_to_users', 'users', ['assigned_to'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_constraint('fk_findings_assigned_to_users', type_='foreignkey')
        batch_op.drop_column('escalation_count')
        batch_op.drop_column('escalated_at')
        batch_op.drop_column('assigned_to')
        batch_op.drop_column('cvss_vector')
    op.drop_column('assets', 'is_internal')
