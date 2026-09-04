"""add project_model.external_dependencies and .scope_mismatches

B3 produces two things the section 3 table has nowhere to put: the outbound
third-party dependencies found in the code, and the declared-vs-observed scope
mismatches that B5 penalises. Both are lists of objects, so JSONB, consistent
with the rest of this table.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("project_model", sa.Column("external_dependencies", postgresql.JSONB(), nullable=True))
    op.add_column("project_model", sa.Column("scope_mismatches", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("project_model", "scope_mismatches")
    op.drop_column("project_model", "external_dependencies")
