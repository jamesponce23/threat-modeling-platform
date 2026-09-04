"""RQ job: run one Track A scan end to end.

    collect -> analyze -> map controls -> store -> correlate

Mirrors app/worker.py's structure deliberately: status advanced at each step,
any exception recorded on the row rather than lost to the worker log. What
the connector could not read, what rules failed, and which findings have no
control mapping are all written to `estate_scan.warnings`, because a gap that
only exists in the RQ job's return value is a gap nobody will ever see.
"""

from __future__ import annotations

import traceback

from sqlalchemy.orm import Session

from app.analysis import rules
from app.cis import mapping
from app.db import SessionLocal
from app.findings import store
from app.models import EstateScan, Source

ACTIVE_STATUSES = ("queued", "collecting", "analyzing", "storing")


def _set_status(db: Session, scan: EstateScan, status: str) -> None:
    scan.status = status
    db.commit()


def _connector(source: Source):
    """Imported lazily: a missing Azure SDK must not break AWS-only scans."""
    if source.provider == "aws":
        from app.connectors.aws import AwsConnector

        return AwsConnector()
    if source.provider == "azure":
        from app.connectors.azure import AzureConnector

        return AzureConnector(source.account_identifier)
    raise RuntimeError(f"unknown provider {source.provider!r}")


def run_estate_scan(scan_id: int) -> dict:
    """Enqueued as the dotted path 'app.estate_worker.run_estate_scan'."""
    db = SessionLocal()
    scan = db.get(EstateScan, scan_id)
    if scan is None:
        db.close()
        raise RuntimeError(f"estate_scan {scan_id} does not exist")

    summary: dict = {"scan_id": scan_id}
    warnings: list[str] = []
    try:
        source = scan.source

        _set_status(db, scan, "collecting")
        connector = _connector(source)

        # The AWS connector scans whatever the worker's credentials point at.
        # If that is not the account this source row names, the findings
        # would be filed under the wrong account - refuse rather than mislabel.
        actual = str(connector.account_identifier())
        if actual != source.account_identifier.strip():
            raise RuntimeError(
                f"credentials resolve to {source.provider} account {actual!r}, "
                f"but this source is registered as {source.account_identifier!r}. "
                f"Fix the profile/subscription the worker runs with, or register the right account."
            )

        resources = connector.collect()
        scan.resource_count = len(resources)
        summary["resources"] = len(resources)
        warnings.extend(f"connector: {e}" for e in connector.errors)
        db.commit()

        _set_status(db, scan, "analyzing")
        findings, rule_errors = rules.analyze(resources)
        no_trail = rules.missing_audit_trail(resources, source.account_identifier)
        if no_trail is not None:
            findings.append(no_trail)
        warnings.extend(f"rule: {e}" for e in rule_errors)

        findings, unmapped = mapping.apply(findings, source.provider)
        warnings.extend(f"no CIS control for rule {r}" for r in unmapped)
        summary["mapping_version"] = mapping.mapping_version()

        _set_status(db, scan, "storing")
        scan.finding_count = store.store(db, source.id, findings)
        summary["findings"] = scan.finding_count

        scan.attribution = store.attribution_summary(db, resources)
        scan.divergences = store.correlate(db, resources, findings)
        scan.warnings = warnings[:200]
        summary["divergences"] = len(scan.divergences)
        summary["warnings"] = len(warnings)
        db.commit()

        _set_status(db, scan, "complete")
        return summary

    except Exception as exc:
        scan.status = "failed"
        scan.warnings = warnings[:200]
        scan.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"[:4000]
        db.commit()
        raise
    finally:
        db.close()
