"""B1 intake: the project list, the submission form, and the JSON equivalents."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_api_client, require_user
from app.config import settings
from app.db import get_db
from app.models import Project, QuestionnaireResponse, Submission
from app.queue import enqueue_scan
from app.repo_url import normalize_repo_url
from app.schemas import ProjectOut, SubmissionCreate, SubmissionOut
from app.scoping.questionnaire import QUESTIONS, QUESTION_KEYS, validate_answers
from app.templating import templates

router = APIRouter()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")


def _get_or_create_project(db: Session, name: str, owner_email: str, repo_url: str | None) -> Project:
    # Stored in one canonical spelling so the webhook can find it again,
    # whatever form the push payload uses.
    repo_url = normalize_repo_url(repo_url)
    project = db.scalar(select(Project).where(Project.name == name))
    if project is None:
        project = Project(name=name, owner_email=owner_email, repo_url=repo_url)
        db.add(project)
        db.flush()  # assigns project.id without ending the transaction
    elif repo_url and project.repo_url != repo_url:
        project.repo_url = repo_url
    return project


def _create_submission(
    db: Session,
    *,
    project: Project,
    source_type: str,
    ref: str | None,
    answers: dict[str, str],
) -> Submission:
    """Create submission + its six answer rows in one transaction.

    All of it commits or none of it does — a submission without answers is not
    scoreable, and would sit in the queue forever waiting for B5 to fail.
    """
    submission = Submission(
        project_id=project.id,
        source_type=source_type,
        ref=ref,
        status="queued",
    )
    db.add(submission)
    db.flush()

    for key in QUESTION_KEYS:
        db.add(
            QuestionnaireResponse(
                submission_id=submission.id,
                question_key=key,
                answer_value=answers[key],
            )
        )
    db.commit()
    db.refresh(submission)
    return submission


@router.get("/", response_class=HTMLResponse)
def project_list(request: Request, db: Session = Depends(get_db), user: str = Depends(require_user)):
    projects = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    latest = {
        p.id: db.scalar(
            select(Submission)
            .where(Submission.project_id == p.id)
            .order_by(Submission.submitted_at.desc())
            .limit(1)
        )
        for p in projects
    }
    return templates.TemplateResponse(
        request, "index.html", {"projects": projects, "latest": latest, "user": user}
    )


@router.get("/submit", response_class=HTMLResponse)
def submit_form(request: Request, user: str = Depends(require_user)):
    return templates.TemplateResponse(
        request, "submit.html", {"questions": QUESTIONS, "errors": [], "form": {}, "user": user}
    )


@router.post("/submit")
async def submit(request: Request, db: Session = Depends(get_db), user: str = Depends(require_user)):
    form = await request.form()
    name = (form.get("project_name") or "").strip()
    owner_email = (form.get("owner_email") or "").strip()
    repo_url = (form.get("repo_url") or "").strip()
    ref = (form.get("ref") or "").strip() or "main"
    upload = form.get("archive")
    has_upload = bool(getattr(upload, "filename", ""))

    errors: list[str] = []
    if not name:
        errors.append("Project name is required.")
    if not EMAIL_RE.match(owner_email):
        errors.append("A valid owner email is required.")
    if bool(repo_url) == has_upload:
        errors.append("Provide either a repository URL or an archive upload — one, not both.")
    if has_upload and not upload.filename.lower().endswith(ARCHIVE_SUFFIXES):
        errors.append("Archive must be one of: " + ", ".join(ARCHIVE_SUFFIXES))

    answers = {key: (form.get(key) or "").strip() for key in QUESTION_KEYS}
    try:
        answers = validate_answers(answers)
    except ValueError as exc:
        errors.append(str(exc))

    if errors:
        return templates.TemplateResponse(
            request,
            "submit.html",
            {"questions": QUESTIONS, "errors": errors, "form": dict(form), "user": user},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    project = _get_or_create_project(db, name, owner_email, repo_url or None)
    submission = _create_submission(
        db,
        project=project,
        source_type="archive" if has_upload else "git",
        ref=None if has_upload else ref,
        answers=answers,
    )

    if has_upload:
        workspace = Path(settings.workspace_root) / str(submission.id)
        workspace.mkdir(parents=True, exist_ok=True)
        target = workspace / Path(upload.filename).name
        target.write_bytes(await upload.read())

    enqueue_scan(submission.id)
    return RedirectResponse(f"/status/{submission.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/status/{submission_id}", response_class=HTMLResponse)
def submission_status(
    submission_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: str = Depends(require_user),
):
    submission = db.get(Submission, submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="submission not found")
    return templates.TemplateResponse(
        request,
        "status.html",
        {"submission": submission, "project": submission.project, "user": user},
    )


# --- JSON API, so CI can submit -------------------------------------------


@router.get("/api/v1/projects", response_model=list[ProjectOut])
def api_projects(db: Session = Depends(get_db), client: str = Depends(require_api_client)):
    return db.scalars(select(Project).order_by(Project.created_at.desc())).all()


@router.post("/api/v1/submissions", response_model=SubmissionOut, status_code=201)
def api_create_submission(
    payload: SubmissionCreate,
    db: Session = Depends(get_db),
    client: str = Depends(require_api_client),
):
    try:
        answers = validate_answers(payload.answers)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    project = _get_or_create_project(db, payload.project_name, str(payload.owner_email), payload.repo_url)
    submission = _create_submission(
        db, project=project, source_type="git", ref=payload.ref, answers=answers
    )
    enqueue_scan(submission.id)
    return submission
