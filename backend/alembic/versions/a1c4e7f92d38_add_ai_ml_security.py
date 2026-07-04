"""add AI-1/AI-2 tables: prompt_injection_tests, ai_feature_inventory; owasp_llm compliance framework

Revision ID: a1c4e7f92d38
Revises: f7a2d9e63b81
Create Date: 2026-07-03 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1c4e7f92d38'
down_revision: Union[str, Sequence[str], None] = 'f7a2d9e63b81'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ComplianceFramework.owasp_llm is a new value on an EXISTING Postgres
    # native enum type (compliance_controls.framework, type name
    # "complianceframework" per the initial migration). Postgres enums
    # need an explicit ALTER TYPE, and that statement can't run inside the
    # same transaction Alembic normally wraps migrations in -- hence the
    # autocommit_block. SQLite doesn't create a native enum/CHECK
    # constraint for this column (create_constraint defaults to False
    # there), so no action is needed on that dialect.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE complianceframework ADD VALUE IF NOT EXISTS 'owasp_llm'")

    op.create_table(
        'prompt_injection_tests',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('target_url', sa.String(length=500), nullable=False),
        sa.Column('results', sa.JSON()),
        sa.Column('success_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime()),
    )

    op.create_table(
        'ai_feature_inventory',
        sa.Column('id', sa.UUID(as_uuid=False), primary_key=True),
        sa.Column('client_id', sa.UUID(as_uuid=False), sa.ForeignKey('clients.id'), nullable=False, index=True),
        sa.Column('feature_name', sa.String(length=255), nullable=False),
        sa.Column('feature_type', sa.String(length=100), nullable=True),
        sa.Column('library_stack', sa.JSON()),
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
    )


def downgrade() -> None:
    op.drop_table('ai_feature_inventory')
    op.drop_table('prompt_injection_tests')
    # Note: intentionally not removing 'owasp_llm' from the Postgres enum
    # type on downgrade -- Postgres has no ALTER TYPE ... DROP VALUE, so
    # doing this safely would require rebuilding the enum type entirely.
    # Any rows already using owasp_llm would need to be handled manually
    # first; not something a mechanical downgrade should attempt.
