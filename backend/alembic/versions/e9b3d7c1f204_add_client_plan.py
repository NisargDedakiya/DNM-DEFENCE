"""add client subscription plan

Revision ID: e9b3d7c1f204
Revises: d5f8a21c74e9
Create Date: 2026-07-18

Adds the subscription tier to each client. Existing clients backfill to
'enterprise' (full access) via the server_default, so introducing tiers
never removes access from anyone already onboarded.
"""
from alembic import op
import sqlalchemy as sa

revision = "e9b3d7c1f204"
down_revision = "d5f8a21c74e9"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "clients",
        sa.Column("plan", sa.String(length=20), nullable=False, server_default="enterprise"),
    )


def downgrade():
    op.drop_column("clients", "plan")
