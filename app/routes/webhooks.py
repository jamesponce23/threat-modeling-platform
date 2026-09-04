"""Git webhook: re-scan a registered project when it changes.

Signature verification happens before anything else. The payload is not
parsed, not logged, and no database row is touched until the HMAC matches —
an unauthenticated caller must not be able to make this service do work.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import Project, QuestionnaireResponse, Submission
from app.queue import enqueue_scan
from app.repo_url import normalize_repo_url

router = APIRouter()

SIGNATURE_HEADER = "x-hub-signature-256"


def verify_signature(body: bytes, header_value: str | None) -> None:
    if not header_value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing signature")

    scheme, _, sent = header_value.partition("=")
    if scheme != "sha256" or not sent:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="malformed signature")

    expected = hmac.new(settings.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    # compare_digest, not ==, so the comparison does not leak the secret
    # through how long it takes to fail.
    if not hmac.compare_digest(sent, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bad signature")


def _extract(payload: dict) -> tuple[str | None, str | None, str | None]:
    """Pull (repo_url, commit_sha, ref) out of a push or pull_request payload."""
    repo = payload.get("repository") or {}
    # Normalised, because clone_url ends in .git and a browser-pasted URL does
    # not — matching them raw makes this endpoint silently ignore real pushes.
    repo_url = normalize_repo_url(
        repo.get("clone_url") or repo.get("html_url") or repo.get("url") or repo.get("ssh_url")
    )

    if "pull_request" in payload:
        head = payload["pull_request"].get("head") or {}
        return repo_url, head.get("sha"), head.get("ref")

    ref = payload.get("ref")
    if ref and ref.startswith("refs/heads/"):
        ref = ref[len("refs/heads/") :]
    return repo_url, payload.get("after") or payload.get("head_commit", {}).get("id"), ref


@router.post("/webhooks/git", status_code=202)
async def git_webhook(request: Request, db: Session = Depends(get_db)):
    body = await request.body()
    verify_signature(body, request.headers.get(SIGNATURE_HEADER))

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="payload is not JSON") from exc

    repo_url, commit_sha, ref = _extract(payload)
    if not repo_url:
        raise HTTPException(status_code=400, detail="no repository URL in payload")

    project = db.scalar(select(Project).where(Project.repo_url == repo_url))
    if project is None:
        # Not an error: plenty of repos are not registered here. Say so and stop.
        return {"status": "ignored", "reason": "repository is not a registered project"}

    submission = Submission(
        project_id=project.id,
        source_type="git",
        ref=ref,
        commit_sha=commit_sha,
        status="queued",
    )
    db.add(submission)
    db.flush()

    # Carry the previous submission's answers forward. The questionnaire is a
    # property of the project, not of the commit, and a submission with no
    # answers is not scoreable.
    previous = db.scalar(
        select(Submission)
        .where(Submission.project_id == project.id, Submission.id != submission.id)
        .order_by(Submission.submitted_at.desc())
        .limit(1)
    )
    if previous is None:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="project has no prior submission to copy questionnaire answers from",
        )

    prior_answers = db.scalars(
        select(QuestionnaireResponse).where(QuestionnaireResponse.submission_id == previous.id)
    ).all()
    for answer in prior_answers:
        db.add(
            QuestionnaireResponse(
                submission_id=submission.id,
                question_key=answer.question_key,
                answer_value=answer.answer_value,
            )
        )

    db.commit()
    db.refresh(submission)
    enqueue_scan(submission.id)
    return {"status": "queued", "submission_id": submission.id}
