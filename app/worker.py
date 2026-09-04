"""RQ worker entrypoint: the pipeline that turns a submission into findings.

    clone -> detect -> scope -> scan (parallel) -> classify -> report

`submission.status` is advanced at each step, so the poll page from B1 shows
real progress rather than a spinner. Any exception marks the submission
`failed` and records the reason — a failed scan with no reason is
undiagnosable.
"""

from __future__ import annotations

import shutil
import tempfile
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import SessionLocal
from app.ingestion import archive, detect, git_fetch, workspace
from app.models import Finding as FindingRow
from app.models import GateDecision, ProjectModel, RiskAssessment, Submission
from app.risk import classifier, gate, overrides
from app.scanners import sbom
from app.scanners.base import Finding, ScannerError
from app.scanners.checkov import CheckovScanner
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner
from app.scoping import project_model

SCANNERS = (GitleaksScanner(), SemgrepScanner(), TrivyScanner(), CheckovScanner())


def _set_status(db: Session, submission: Submission, status: str) -> None:
    submission.status = status
    db.commit()


def _rescue_upload(submission_id: int) -> Path | None:
    """Copy an uploaded archive out of the workspace before it is recreated.

    B1 writes the upload into WORKSPACE_ROOT/<id>/, and creating the sandbox
    clears that directory. Without this the archive would be deleted a moment
    before it was needed.
    """
    existing = workspace.workspace_path(submission_id)
    if not existing.exists():
        return None
    for candidate in existing.iterdir():
        if candidate.is_file():
            holding = Path(tempfile.mkdtemp(prefix="tmp-upload-")) / candidate.name
            shutil.copy2(candidate, holding)
            return holding
    return None


def _fetch_source(db: Session, submission: Submission, upload: Path | None) -> Path:
    """Populate the sandbox from git or from the uploaded archive."""
    if submission.source_type == "archive":
        if upload is None:
            raise RuntimeError("submission is an archive upload but no file was found")
        return archive.unpack(upload, submission.id)

    repo_url = submission.project.repo_url
    if not repo_url:
        raise RuntimeError("submission is a git clone but the project has no repo_url")

    # A webhook submission pins a commit; a form submission names a branch.
    ref = submission.ref
    sha = git_fetch.clone(repo_url, ref, submission.id)
    submission.commit_sha = sha
    db.commit()
    return workspace.source_path(submission.id)


def _run_scanners(model: ProjectModel | None, source: Path) -> tuple[list[Finding], dict[str, str]]:
    """Run every applicable scanner in parallel. Returns findings and failures.

    A scanner that fails is recorded, not swallowed: 'no findings' and 'the
    tool never ran' must never look the same to whoever reads the report.
    """
    applicable = [s for s in SCANNERS if s.applicable(model)]
    findings: list[Finding] = []
    failures: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=len(applicable) or 1) as pool:
        futures = {pool.submit(s.run, source): s for s in applicable}
        for future, scanner in futures.items():
            try:
                findings.extend(future.result())
            except ScannerError as exc:
                failures[scanner.name] = str(exc)
            except Exception as exc:  # a broken adapter must not kill the run
                failures[scanner.name] = f"{type(exc).__name__}: {exc}"

    return findings, failures


def _store_findings(db: Session, submission_id: int, findings: list[Finding]) -> int:
    db.query(FindingRow).filter(FindingRow.submission_id == submission_id).delete()
    for finding in findings:
        db.add(
            FindingRow(
                submission_id=submission_id,
                scanner=finding.scanner,
                rule_id=finding.rule_id[:200],
                severity=finding.severity,
                file_path=finding.file_path,
                line=finding.line,
                title=finding.title,
                evidence=finding.evidence,
                stride=finding.stride,
                cis_control=finding.cis_control,
            )
        )
    db.commit()
    return len(findings)


def _store_risk_assessment(db: Session, submission_id: int, result: classifier.ScoreResult) -> None:
    row = db.scalar(select(RiskAssessment).where(RiskAssessment.submission_id == submission_id))
    if row is None:
        row = RiskAssessment(submission_id=submission_id)
        db.add(row)
    row.inherent_score = result.inherent_score
    row.technical_score = result.technical_score
    row.total_score = result.total_score
    row.tier = result.tier
    row.drivers = [d.as_dict() for d in result.drivers]
    row.overrides_fired = result.overrides_fired
    row.model_version = result.model_version
    db.commit()


def _store_gate_decision(db: Session, submission_id: int, tier: str) -> None:
    decision, required_controls = gate.decide(tier)
    row = db.scalar(select(GateDecision).where(GateDecision.submission_id == submission_id))
    if row is None:
        row = GateDecision(submission_id=submission_id)
        db.add(row)
    row.decision = decision
    row.required_controls = required_controls
    db.commit()


def _generate_sbom(submission_id: int, source: Path) -> str | None:
    """Best-effort. An SBOM failure must not fail an otherwise-complete scan."""
    try:
        sbom.generate(source, Path(settings.artifact_root) / str(submission_id))
        return None
    except Exception as exc:  # recorded, not swallowed
        return f"{type(exc).__name__}: {exc}"


def run_scan(submission_id: int) -> dict:
    """The RQ job. Enqueued by B1 as the dotted path 'app.worker.run_scan'."""
    db = SessionLocal()
    submission = db.get(Submission, submission_id)
    if submission is None:
        db.close()
        raise RuntimeError(f"submission {submission_id} does not exist")

    summary: dict = {"submission_id": submission_id}
    try:
        upload = _rescue_upload(submission_id)

        # The sandbox wraps the whole pipeline: B2 fills it, B3 reads it, B4
        # scans it. Its `finally` is what guarantees cleanup even on failure.
        with workspace.sandbox(submission_id):
            _set_status(db, submission, "cloning")
            source = _fetch_source(db, submission, upload)

            _set_status(db, submission, "scoping")
            detection = detect.detect(source)
            detect.store(db, submission_id, detection)
            model = project_model.build(db, submission_id, source)
            summary["scope_mismatches"] = [m["key"] for m in (model.scope_mismatches or [])]

            _set_status(db, submission, "scanning")
            findings, failures = _run_scanners(model, source)
            summary["findings"] = _store_findings(db, submission_id, findings)
            summary["scanner_failures"] = failures

            summary["sbom_error"] = _generate_sbom(submission_id, source)

            _set_status(db, submission, "classifying")
            answers = project_model.declared_scope(db, submission_id)
            result = classifier.classify(answers, findings, model.scope_mismatches)
            result = overrides.apply(result, answers, findings, model.scope_mismatches)
            _store_risk_assessment(db, submission_id, result)
            _store_gate_decision(db, submission_id, result.tier)
            summary["tier"] = result.tier
            summary["total_score"] = result.total_score

        _set_status(db, submission, "complete")
        return summary

    except Exception as exc:
        submission.status = "failed"
        submission.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"[:4000]
        db.commit()
        raise
    finally:
        db.close()
