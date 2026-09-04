"""Stage 7: technical, executive and risk views over Track A findings.

These build plain dicts rather than rendering directly, so the same data backs
the HTML page, the JSON API and any future PDF without three implementations
drifting apart.

Three audiences:

* technical_report - every finding, worst first, with its control reference.
* executive_report - counts, the worst offenders, control coverage.
* risk_report      - the correlation loop: projects Track B rated LOW or
                     MEDIUM whose deployed resources are internet-exposed,
                     plus how much of the estate could be attributed at all.
"""

from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import EstateScan, Finding as FindingRow, Source

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _findings(db: Session, source_id: int) -> list[FindingRow]:
    return list(
        db.scalars(
            select(FindingRow).where(FindingRow.source_id == source_id)
        ).all()
    )


def _latest_scan(db: Session, source_id: int) -> EstateScan | None:
    return db.scalar(
        select(EstateScan)
        .where(EstateScan.source_id == source_id)
        .order_by(EstateScan.started_at.desc(), EstateScan.id.desc())
        .limit(1)
    )


def technical_report(db: Session, source_id: int) -> dict:
    """Every finding, worst first, with its control reference."""
    findings = _findings(db, source_id)
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (rank.get(f.severity, 99), f.rule_id, f.evidence or ""))

    return {
        "source": db.get(Source, source_id),
        "findings": findings,
        "total": len(findings),
    }


def executive_report(db: Session, source_id: int) -> dict:
    """Counts, the worst offenders, and control coverage - no finding list."""
    findings = _findings(db, source_id)
    by_severity = Counter(f.severity for f in findings)
    by_rule = Counter(f.rule_id for f in findings)

    mapped = sum(1 for f in findings if f.cis_control)
    coverage = round(100 * mapped / len(findings)) if findings else 100

    return {
        "source": db.get(Source, source_id),
        "scan": _latest_scan(db, source_id),
        "counts": {s: by_severity.get(s, 0) for s in SEVERITY_ORDER},
        "total": len(findings),
        "top_rules": by_rule.most_common(5),
        "cis_coverage_percent": coverage,
        "unmapped": sorted({f.rule_id for f in findings if not f.cis_control})[:10],
    }


def risk_report(db: Session, source_id: int) -> dict:
    """The correlation loop, as stored by the last scan of this source."""
    scan = _latest_scan(db, source_id)
    if scan is None:
        return {"scan": None, "divergences": [], "attribution": None, "warnings": []}
    return {
        "scan": scan,
        "divergences": scan.divergences or [],
        "attribution": scan.attribution,
        "warnings": scan.warnings or [],
    }


def posture_summary(db: Session) -> list[dict]:
    """One row per source, for the estate index page."""
    rows = []
    for source in db.scalars(select(Source).order_by(Source.created_at.desc())).all():
        findings = _findings(db, source.id)
        by_severity = Counter(f.severity for f in findings)
        latest = _latest_scan(db, source.id)
        rows.append(
            {
                "source": source,
                "scan": latest,
                "critical": by_severity.get("critical", 0),
                "high": by_severity.get("high", 0),
                "total": len(findings),
                "divergences": len(latest.divergences or []) if latest else 0,
            }
        )
    return rows
