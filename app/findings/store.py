"""Stage 6: persist Track A findings, deduplicated, and correlate to Track B.

Deduplication is by (source_id, rule_id, evidence): the same misconfiguration
on the same resource is one row no matter how many times it is scanned. The
delete-then-insert pattern matches how Track B stores per-submission findings,
so the two tracks behave the same way in the shared table.

Correlation is the payoff of running both tracks against one store: a Track B
project rated LOW whose deployed resources are publicly exposed is the single
highest-signal output this platform produces.
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.rules import evidence_for
from app.models import Finding as FindingRow
from app.models import Project, RiskAssessment, Submission
from app.normalize.schema import Resource
from app.scanners.base import Finding

# Tiers that claim the project is not a serious exposure. A public resource
# attributed to one of these is the divergence worth reporting.
LOW_RISK_TIERS = ("LOW", "MEDIUM")

# Rule ids that mean "the internet can reach this".
EXPOSURE_RULES = (
    "estate.storage.public_access",
    "estate.database.public_access",
    "estate.network.open_ingress",
    "estate.identity.role_trusts_any_principal",
)


def store(db: Session, source_id: int, findings: list[Finding]) -> int:
    """Replace this source's findings with the current scan's. Returns count."""
    db.query(FindingRow).filter(FindingRow.source_id == source_id).delete()

    seen: set[tuple] = set()
    stored = 0
    for finding in findings:
        signature = (finding.rule_id, finding.evidence)
        if signature in seen:
            continue
        seen.add(signature)
        db.add(
            FindingRow(
                source_id=source_id,
                submission_id=None,
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
        stored += 1

    db.commit()
    return stored


def attribute(resources: list[Resource]) -> tuple[dict[str, list[Resource]], list[Resource]]:
    """Split resources by their `project` tag. Returns (by_project, untagged).

    Untagged resources are returned, not discarded: an estate where nothing is
    tagged cannot be correlated at all, and that is a finding about the estate,
    not a reason to report success.
    """
    by_project: dict[str, list[Resource]] = defaultdict(list)
    untagged: list[Resource] = []

    for resource in resources:
        tag = resource.project_tag()
        if tag:
            by_project[tag].append(resource)
        else:
            untagged.append(resource)

    return dict(by_project), untagged


def attribution_summary(db: Session, resources: list[Resource]) -> dict:
    """Counts for the report: what could be tied to a Track B project, what
    carries a tag that names no known project, and what carries no tag at all.
    Stored on the scan row so the estate page can say how much of the estate
    the correlation loop can even see."""
    by_project, untagged = attribute(resources)
    known = {
        name for name in by_project
        if db.scalar(select(Project.id).where(Project.name == name)) is not None
    }
    return {
        "total": len(resources),
        "attributed": {name: len(items) for name, items in by_project.items() if name in known},
        "unknown_project_tags": {name: len(items) for name, items in by_project.items() if name not in known},
        "unattributed": len(untagged),
    }


def correlate(db: Session, resources: list[Resource], findings: list[Finding]) -> list[dict]:
    """Compare each project's Track B rating against its observed posture.

    Returns one row per divergence: a project rated LOW or MEDIUM that has at
    least one internet-exposed resource deployed under its tag.
    """
    by_project, _ = attribute(resources)

    # Which resource ids are implicated in an exposure finding.
    exposed_evidence = {
        f.evidence for f in findings if f.rule_id in EXPOSURE_RULES and f.evidence
    }

    divergences: list[dict] = []
    for project_name, project_resources in by_project.items():
        project = db.scalar(select(Project).where(Project.name == project_name))
        if project is None:
            continue

        assessment = _latest_assessment(db, project.id)
        if assessment is None or assessment.tier not in LOW_RISK_TIERS:
            continue

        # dict.fromkeys: one entry per resource id, first-seen order kept.
        exposed = list(dict.fromkeys(
            r.resource_id for r in project_resources if evidence_for(r) in exposed_evidence
        ))
        if not exposed:
            continue

        divergences.append(
            {
                "project": project_name,
                "project_id": project.id,
                "submission_id": assessment.submission_id,
                "rated_tier": assessment.tier,
                "rated_total_score": assessment.total_score,
                "exposed_resources": exposed[:20],
                "exposed_count": len(exposed),
            }
        )

    return divergences


def _latest_assessment(db: Session, project_id: int) -> RiskAssessment | None:
    return db.scalar(
        select(RiskAssessment)
        .join(Submission, Submission.id == RiskAssessment.submission_id)
        .where(Submission.project_id == project_id)
        .order_by(Submission.submitted_at.desc())
        .limit(1)
    )
