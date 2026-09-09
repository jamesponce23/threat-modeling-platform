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
from app.normalize import schema
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

    Grouping is by `schema.project_key`, not by the raw tag, so one project
    tagged in two spellings ("Payments", "payments", "pay-ments") is one group
    rather than three - three groups would each be matched against the project
    registry separately and all but one would be reported as naming no known
    project. The group is labelled with the first spelling seen, so the report
    still shows an operator the string that is actually on their resources.

    Untagged resources are returned, not discarded: an estate where nothing is
    tagged cannot be correlated at all, and that is a finding about the estate,
    not a reason to report success.
    """
    by_key: dict[str, list[Resource]] = defaultdict(list)
    labels: dict[str, str] = {}
    untagged: list[Resource] = []

    for resource in resources:
        tag = resource.project_tag()
        if not tag:
            untagged.append(resource)
            continue
        key = schema.project_key(tag)
        labels.setdefault(key, tag)
        by_key[key].append(resource)

    return {labels[key]: items for key, items in by_key.items()}, untagged


def _project_index(db: Session) -> tuple[dict[str, Project], set[str]]:
    """Every registered project, keyed for comparison against a tag value.

    Two projects whose names differ only in case or separators cannot be told
    apart by a tag, so neither is matched: the key is dropped from the index
    and returned as ambiguous. Attributing to whichever row happened to be
    created first would silently hang one team's exposure on another's rating.
    """
    index: dict[str, Project] = {}
    ambiguous: set[str] = set()

    for project in db.scalars(select(Project).order_by(Project.id)).all():
        key = schema.project_key(project.name)
        if not key:
            continue
        if key in index:
            ambiguous.add(key)
            continue
        index[key] = project

    for key in ambiguous:
        index.pop(key, None)

    return index, ambiguous


def attribution_summary(db: Session, resources: list[Resource]) -> dict:
    """Counts for the report: what could be tied to a Track B project, what
    carries a tag that names no known project, and what carries no tag at all.
    Stored on the scan row so the estate page can say how much of the estate
    the correlation loop can even see."""
    by_project, untagged = attribute(resources)
    index, ambiguous = _project_index(db)

    attributed: dict[str, int] = {}
    unknown: dict[str, int] = {}
    contested: dict[str, int] = {}
    for label, items in by_project.items():
        key = schema.project_key(label)
        if key in ambiguous:
            contested[label] = len(items)
        elif key in index:
            attributed[label] = len(items)
        else:
            unknown[label] = len(items)

    return {
        "total": len(resources),
        "attributed": attributed,
        "unknown_project_tags": unknown,
        "ambiguous_project_tags": contested,
        "unattributed": len(untagged),
    }


def correlate(db: Session, resources: list[Resource], findings: list[Finding]) -> list[dict]:
    """Compare each project's Track B rating against its observed posture.

    Returns one row per divergence: a project rated LOW or MEDIUM that has at
    least one internet-exposed resource deployed under its tag.
    """
    by_project, _ = attribute(resources)
    index, _ambiguous = _project_index(db)

    # Which resource ids are implicated in an exposure finding.
    exposed_evidence = {
        f.evidence for f in findings if f.rule_id in EXPOSURE_RULES and f.evidence
    }

    divergences: list[dict] = []
    for tag_label, project_resources in by_project.items():
        project = index.get(schema.project_key(tag_label))
        if project is None:
            continue
        project_name = project.name

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
                "project_tag": tag_label,
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
