"""Track A in the portal: sources, scans, and the three reports."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_api_client, require_user
from app.db import get_db
from app.estate_worker import ACTIVE_STATUSES
from app.models import EstateScan, Source
from app.queue import scan_queue
from app.reporting import estate as reporting
from app.templating import templates

router = APIRouter()


@router.get("/estate", response_class=HTMLResponse)
def estate_index(request: Request, db: Session = Depends(get_db), user: str = Depends(require_user)):
    rows = reporting.posture_summary(db)
    refreshing = any(row["scan"] and row["scan"].status in ACTIVE_STATUSES for row in rows)
    return templates.TemplateResponse(
        request, "estate.html", {"rows": rows, "refreshing": refreshing, "user": user}
    )


@router.post("/estate/sources")
def add_source(
    provider: str = Form(...),
    account_identifier: str = Form(...),
    display_name: str = Form(...),
    db: Session = Depends(get_db),
    user: str = Depends(require_user),
):
    if provider not in ("aws", "azure"):
        raise HTTPException(status_code=400, detail="provider must be aws or azure")
    account_identifier = account_identifier.strip()
    display_name = display_name.strip()
    if not account_identifier or not display_name:
        raise HTTPException(status_code=400, detail="account identifier and display name are required")

    existing = db.scalar(
        select(Source).where(
            Source.provider == provider, Source.account_identifier == account_identifier
        )
    )
    if existing is None:
        existing = Source(
            provider=provider,
            account_identifier=account_identifier,
            display_name=display_name,
        )
        db.add(existing)
        db.commit()
        db.refresh(existing)

    return RedirectResponse(f"/estate/{existing.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/estate/{source_id}/scan")
def start_scan(source_id: int, db: Session = Depends(get_db), user: str = Depends(require_user)):
    source = db.get(Source, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="source not found")

    scan = EstateScan(source_id=source.id, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Enqueued by dotted path, same as B1 does, so this module never imports
    # the worker's pipeline. Reuses the "scans" queue - one queue, one worker,
    # two tracks.
    scan_queue.enqueue("app.estate_worker.run_estate_scan", scan.id, job_timeout=3600)
    return RedirectResponse(f"/estate/{source_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/estate/{source_id}", response_class=HTMLResponse)
def source_detail(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_user),
):
    if db.get(Source, source_id) is None:
        raise HTTPException(status_code=404, detail="source not found")

    executive = reporting.executive_report(db, source_id)
    return templates.TemplateResponse(
        request,
        "estate_detail.html",
        {
            "executive": executive,
            "technical": reporting.technical_report(db, source_id),
            "risk": reporting.risk_report(db, source_id),
            "refreshing": bool(executive["scan"] and executive["scan"].status in ACTIVE_STATUSES),
            "user": user,
        },
    )


@router.get("/api/v1/estate/{source_id}/report")
def api_estate_report(
    source_id: int,
    db: Session = Depends(get_db),
    client: str = Depends(require_api_client),
):
    if db.get(Source, source_id) is None:
        raise HTTPException(status_code=404, detail="source not found")

    report = reporting.executive_report(db, source_id)
    risk = reporting.risk_report(db, source_id)
    scan = report["scan"]
    return {
        "source_id": source_id,
        "provider": report["source"].provider,
        "account": report["source"].account_identifier,
        "counts": report["counts"],
        "total_findings": report["total"],
        "top_rules": report["top_rules"],
        "cis_coverage_percent": report["cis_coverage_percent"],
        "unmapped_rules": report["unmapped"],
        "last_scan_status": scan.status if scan else None,
        "last_scan_error": scan.error if scan else None,
        "divergences": risk["divergences"],
        "attribution": risk["attribution"],
        "warnings": risk["warnings"],
    }
