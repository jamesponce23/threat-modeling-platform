"""Track A: source + estate_scan tables, and finding.source_id gets its FK

`finding.source_id` has carried Track A rows since the first migration but had
no foreign key, because the table it pointed at did not exist yet. It does now,
so the constraint goes on and the column stops being a bare integer nobody
enforces.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("account_identifier", sa.String(100), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.CheckConstraint("provider in ('aws', 'azure')", name="ck_source_provider"),
    )
    op.create_index(
        "ix_source_provider_account", "source", ["provider", "account_identifier"], unique=True
    )

    op.create_table(
        "estate_scan",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("resource_count", sa.Integer()),
        sa.Column("finding_count", sa.Integer()),
        sa.Column("error", sa.Text()),
        # What the scan could not read or map, the tag attribution counts,
        # and the rated-vs-observed divergences - the risk report's data.
        sa.Column("warnings", postgresql.JSONB(), nullable=True),
        sa.Column("attribution", postgresql.JSONB(), nullable=True),
        sa.Column("divergences", postgresql.JSONB(), nullable=True),
        sa.Column(
            "started_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.CheckConstraint(
            "status in ('queued', 'collecting', 'analyzing', 'storing', 'complete', 'failed')",
            name="ck_estate_scan_status",
        ),
        sa.ForeignKeyConstraint(["source_id"], ["source.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_estate_scan_source_id", "estate_scan", ["source_id"])
    op.create_index("ix_estate_scan_status", "estate_scan", ["status"])

    op.create_foreign_key(
        "finding_source_id_fkey", "finding", "source", ["source_id"], ["id"], ondelete="CASCADE"
    )


def downgrade() -> None:
    op.drop_constraint("finding_source_id_fkey", "finding", type_="foreignkey")
    op.drop_index("ix_estate_scan_status", table_name="estate_scan")
    op.drop_index("ix_estate_scan_source_id", table_name="estate_scan")
    op.drop_table("estate_scan")
    op.drop_index("ix_source_provider_account", table_name="source")
    op.drop_table("source")
