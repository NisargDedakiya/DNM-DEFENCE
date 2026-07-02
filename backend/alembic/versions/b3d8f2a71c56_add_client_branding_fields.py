"""add logo_url, brand_color to clients

Revision ID: b3d8f2a71c56
Revises: a7c2e5f19d34
Create Date: 2026-07-02 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b3d8f2a71c56'
down_revision: Union[str, Sequence[str], None] = 'a7c2e5f19d34'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('clients', sa.Column('logo_url', sa.String(length=500), nullable=True))
    op.add_column('clients', sa.Column('brand_color', sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column('clients', 'brand_color')
    op.drop_column('clients', 'logo_url')
