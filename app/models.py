"""All DB tables for the threat modeling platform.

`finding` is deliberately shared between Track A (cloud posture) and
Track B (project intake) so the correlation and reporting stages work
against a single store.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


SUBMISSION_STATUSES = (
    "queued",
    "cloning",
    "scoping",
    "scanning",
    "classifying",
    "complete",
    "failed",
)


class Project(Base):
    """The registry entry: one row per project under review."""

    __tablename__ = "project"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    owner_email: Mapped[str] = mapped_column(String(320), nullable=False)
    repo_url: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    submissions: Mapped[list["Submission"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Submission(Base):
    """One row per scan run against a project."""

    __tablename__ = "submission"
    __table_args__ = (
        CheckConstraint(
            "status in (" + ", ".join(f"'{s}'" for s in SUBMISSION_STATUSES) + ")",
            name="ck_submission_status",
        ),
        CheckConstraint(
            "source_type in ('git', 'archive')", name="ck_submission_source_type"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True
    )
    commit_sha: Mapped[str | None] = mapped_column(String(40))
    ref: Mapped[str | None] = mapped_column(String(255))
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="queued", index=True
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    error: Mapped[str | None] = mapped_column(Text)

    project: Mapped["Project"] = relationship(back_populates="submissions")


class QuestionnaireResponse(Base):
    """Raw scoping answers, one row per question."""

    __tablename__ = "questionnaire_response"

    id: Mapped[int] = mapped_column(primary_key=True)
    submission_id: Mapped[int] = mapped_column(
        ForeignKey("submission.id", ondelete="CASCADE"), nullable=False, index=True
    )
    question_key: Mapped[str] = mapped_column(String(100), nullable=False)
    answer_value: Mapped[str | None] = mapped_column(Text)


class ProjectModel(Base):
    """Output of B3: the canonical project model derived from repo + answers."""

    __tablename__ = "project_model"

    id: Mapped[int] = mapped_column(primary_key=True)
    submission_id: Mapped[int] = mapped_column(
        ForeignKey("submission.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    languages: Mapped[dict | list | None] = mapped_column(JSONB)
    entry_points: Mapped[dict | list | None] = mapped_column(JSONB)
    data_stores: Mapped[dict | list | None] = mapped_column(JSONB)
    trust_boundaries: Mapped[dict | list | None] = mapped_column(JSONB)
    iac_files: Mapped[dict | list | None] = mapped_column(JSONB)
    external_dependencies: Mapped[dict | list | None] = mapped_column(JSONB)
    scope_mismatches: Mapped[dict | list | None] = mapped_column(JSONB)


SOURCE_PROVIDERS = ("aws", "azure")

ESTATE_SCAN_STATUSES = ("queued", "collecting", "analyzing", "storing", "complete", "failed")


class Source(Base):
    """One AWS account or Azure subscription under review (Track A)."""

    __tablename__ = "source"
    __table_args__ = (
        CheckConstraint(
            "provider in (" + ", ".join(f"'{p}'" for p in SOURCE_PROVIDERS) + ")",
            name="ck_source_provider",
        ),
        # AWS account id or Azure subscription id. Unique per provider, not globally.
        Index("ix_source_provider_account", "provider", "account_identifier", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    account_identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scans: Mapped[list["EstateScan"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class EstateScan(Base):
    """One Track A scan run. Mirrors `submission` on the Track B side."""

    __tablename__ = "estate_scan"
    __table_args__ = (
        CheckConstraint(
            "status in (" + ", ".join(f"'{s}'" for s in ESTATE_SCAN_STATUSES) + ")",
            name="ck_estate_scan_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(
        ForeignKey("source.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="queued", index=True
    )
    resource_count: Mapped[int | None] = mapped_column(Integer)
    finding_count: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    # What the connector could not read, rules that failed, unmapped rule ids.
    warnings: Mapped[dict | list | None] = mapped_column(JSONB)
    # How much of the estate carries a project tag Track B knows about.
    attribution: Mapped[dict | list | None] = mapped_column(JSONB)
    # The correlation loop: projects rated LOW/MEDIUM with exposed resources.
    divergences: Mapped[dict | list | None] = mapped_column(JSONB)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    source: Mapped["Source"] = relationship(back_populates="scans")


class Finding(Base):
    """Shared store. Track B rows carry submission_id; Track A rows carry source_id."""

    __tablename__ = "finding"
    __table_args__ = (
        CheckConstraint(
            "submission_id is not null or source_id is not null",
            name="ck_finding_has_origin",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    submission_id: Mapped[int | None] = mapped_column(
        ForeignKey("submission.id", ondelete="CASCADE"), index=True
    )
    # Track A origin. See Source above.
    source_id: Mapped[int | None] = mapped_column(
        ForeignKey("source.id", ondelete="CASCADE"), index=True
    )
    scanner: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    file_path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text)
    stride: Mapped[str | None] = mapped_column(String(40))
    cis_control: Mapped[str | None] = mapped_column(String(40))


class RiskAssessment(Base):
    """Output of B5: scoring and tier decision."""

    __tablename__ = "risk_assessment"

    id: Mapped[int] = mapped_column(primary_key=True)
    submission_id: Mapped[int] = mapped_column(
        ForeignKey("submission.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    inherent_score: Mapped[int] = mapped_column(Integer, nullable=False)
    technical_score: Mapped[int] = mapped_column(Integer, nullable=False)
    total_score: Mapped[int] = mapped_column(Integer, nullable=False)
    tier: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    drivers: Mapped[dict | list | None] = mapped_column(JSONB)
    overrides_fired: Mapped[dict | list | None] = mapped_column(JSONB)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)


class GateDecision(Base):
    """Output of B7: the review gate outcome and the controls it requires."""

    __tablename__ = "gate_decision"

    id: Mapped[int] = mapped_column(primary_key=True)
    submission_id: Mapped[int] = mapped_column(
        ForeignKey("submission.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    decision: Mapped[str] = mapped_column(String(30), nullable=False)
    required_controls: Mapped[dict | list | None] = mapped_column(JSONB)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    decided_by: Mapped[str | None] = mapped_column(String(320))
