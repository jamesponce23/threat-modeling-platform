"""add submission.warnings

A scanner that fails, or one that quietly skips a file it cannot parse, made
the technical score *lower* and the tier *better*. Both were recorded only in
the RQ job's return value, which lives in Redis for 500 seconds and is shown
to nobody. `estate_scan.warnings` already exists for the Track A side of the
same problem; this is the Track B half.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "submission",
        sa.Column("warnings", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("submission", "warnings")
