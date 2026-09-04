"""add submission.error

A failed scan with no reason recorded is undiagnosable: the status column says
`failed` and nothing says why. The worker writes the exception text here.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("submission", sa.Column("error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("submission", "error")
