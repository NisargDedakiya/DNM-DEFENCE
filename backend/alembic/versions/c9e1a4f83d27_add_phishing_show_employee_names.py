"""add phishing_show_employee_names to clients

Revision ID: c9e1a4f83d27
Revises: b3d8f2a71c56
Create Date: 2026-07-02 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c9e1a4f83d27'
down_revision: Union[str, Sequence[str], None] = 'b3d8f2a71c56'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('clients', sa.Column('phishing_show_employee_names', sa.Boolean(), nullable=True))


def downgrade() -> None:
    op.drop_column('clients', 'phishing_show_employee_names')
