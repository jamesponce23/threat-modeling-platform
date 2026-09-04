"""add submission.ref

The B1 form posts a branch/ref and B2 clones it, but the section 3 table has
nowhere to put it. Nullable because webhook-created submissions carry a commit
SHA instead, and archive uploads have no ref at all.

Revision ID: a1b2c3d4e5f6
Revises: cb16f4415a6d
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "cb16f4415a6d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("submission", sa.Column("ref", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("submission", "ref")
