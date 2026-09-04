"""B7 — the rating page, its JSON twin for CI, a PDF export, and the SBOM download."""

from __future__ import annotations

import io
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_api_client, require_user
from app.config import settings
from app.db import get_db
from app.models import Finding, GateDecision, RiskAssessment, Submission
from app.templating import templates

router = APIRouter()


def _load(db: Session, submission_id: int) -> tuple[Submission, RiskAssessment, GateDecision]:
    submission = db.get(Submission, submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="submission not found")
    assessment = db.scalar(select(RiskAssessment).where(RiskAssessment.submission_id == submission_id))
    gate_decision = db.scalar(select(GateDecision).where(GateDecision.submission_id == submission_id))
    if assessment is None or gate_decision is None:
        raise HTTPException(
            status_code=404,
            detail="rating not ready - submission has not finished classifying",
        )
    return submission, assessment, gate_decision


def _sbom_path(submission_id: int) -> Path:
    return Path(settings.artifact_root) / str(submission_id) / "sbom.json"


@router.get("/rating/{submission_id}", response_class=HTMLResponse)
def rating_page(
    submission_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_user),
):
    submission, assessment, gate_decision = _load(db, submission_id)
    findings = db.scalars(
        select(Finding).where(Finding.submission_id == submission_id).order_by(Finding.severity)
    ).all()
    return templates.TemplateResponse(
        request,
        "rating.html",
        {
            "submission": submission,
            "project": submission.project,
            "assessment": assessment,
            "gate": gate_decision,
            "findings": findings,
            "has_sbom": _sbom_path(submission_id).exists(),
            "user": user,
        },
    )


@router.get("/api/v1/submissions/{submission_id}/rating")
def api_rating(
    submission_id: int,
    db: Session = Depends(get_db),
    client: str = Depends(require_api_client),
):
    _, assessment, gate_decision = _load(db, submission_id)
    return {
        "submission_id": submission_id,
        "tier": assessment.tier,
        "gate": gate_decision.decision,
        "inherent_score": assessment.inherent_score,
        "technical_score": assessment.technical_score,
        "total_score": assessment.total_score,
        "drivers": assessment.drivers,
        "overrides_fired": assessment.overrides_fired,
        "required_controls": gate_decision.required_controls,
        "model_version": assessment.model_version,
    }


@router.get("/reports/{submission_id}.pdf")
def rating_pdf(
    submission_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_user),
):
    submission, assessment, gate_decision = _load(db, submission_id)

    buf = io.BytesIO()
    pdf = canvas.Canvas(buf, pagesize=letter)
    _, height = letter
    y = height - 72

    def line(text: str, size: int = 11, gap: int = 16) -> None:
        nonlocal y
        pdf.setFont("Helvetica", size)
        pdf.drawString(72, y, text[:100])
        y -= gap

    line(f"{submission.project.name} - submission #{submission.id}", size=16, gap=26)
    line(f"Tier: {assessment.tier}    Gate: {gate_decision.decision}", size=13, gap=22)
    line(
        f"Inherent {assessment.inherent_score} + Technical {assessment.technical_score} "
        f"= Total {assessment.total_score}"
    )
    line(f"Model version: {assessment.model_version}")
    line("")

    if assessment.overrides_fired:
        line("Hard overrides fired: " + ", ".join(assessment.overrides_fired))
        line("")

    line("Top drivers:", size=12, gap=18)
    for driver in assessment.drivers or []:
        line(f"  - {driver['factor']}: {driver['points']} pts ({driver['evidence']})")
    line("")

    line("Required controls:", size=12, gap=18)
    for control in gate_decision.required_controls or []:
        line(f"  - {control}")

    pdf.showPage()
    pdf.save()
    return Response(content=buf.getvalue(), media_type="application/pdf")


@router.get("/reports/{submission_id}/sbom.json")
def sbom_download(
    submission_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(require_user),
):
    _load(db, submission_id)  # 404s if the submission doesn't exist / isn't rated
    path = _sbom_path(submission_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="no SBOM was generated for this submission")
    return FileResponse(path, media_type="application/json", filename=f"sbom-{submission_id}.json")
