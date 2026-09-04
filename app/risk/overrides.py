"""B5 hard overrides: promote a tier after scoring. Never lower one.

See the note in risk-model.yaml's write-up in the README: the `when:` strings
there are documentation, not code. Each override id here maps to an explicit
predicate over the real questionnaire values and finding data instead.
"""

from __future__ import annotations

from app.risk.classifier import ScoreResult, load_risk_model
from app.scanners.base import Finding
from app.scoping.boundaries import NON_PUBLIC_ANSWERS

TIER_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _regulated_public(answers, findings, scope_mismatches) -> bool:
    return (
        answers.get("data_classification") == "regulated"
        and answers.get("internet_exposure") == "public_unauthenticated"
    )


def _live_secret(answers, findings, scope_mismatches) -> bool:
    return any(f.scanner == "gitleaks" for f in findings)


def _reachable_critical_cve(answers, findings, scope_mismatches) -> bool:
    reachable = answers.get("internet_exposure") not in NON_PUBLIC_ANSWERS
    return reachable and any(
        f.scanner == "trivy" and f.severity == "critical" and f.rule_id.upper().startswith("CVE-")
        for f in findings
    )


def _control_plane_access(answers, findings, scope_mismatches) -> bool:
    return answers.get("blast_radius") == "prod_control_plane"


def _undeclared_public_exposure(answers, findings, scope_mismatches) -> bool:
    return any(m.get("key") == "scope_mismatch.exposure" for m in scope_mismatches)


PREDICATES = {
    "regulated_public": _regulated_public,
    "live_secret": _live_secret,
    "reachable_critical_cve": _reachable_critical_cve,
    "control_plane_access": _control_plane_access,
    "undeclared_public_exposure": _undeclared_public_exposure,
}


def apply(
    result: ScoreResult,
    answers: dict[str, str],
    findings: list[Finding],
    scope_mismatches: list[dict] | None = None,
    *,
    model: dict | None = None,
) -> ScoreResult:
    """Run hard_overrides against the already-scored result. Promote only."""
    model = model or load_risk_model()
    scope_mismatches = scope_mismatches or []

    tier = result.tier
    fired: list[str] = []

    for override in model["hard_overrides"]:
        override_id = override["id"]
        predicate = PREDICATES.get(override_id)
        if predicate is None:
            raise KeyError(
                f"hard_override {override_id!r} in risk-model.yaml has no "
                f"matching predicate in app/risk/overrides.PREDICATES"
            )
        if predicate(answers, findings, scope_mismatches):
            fired.append(override_id)
            if TIER_RANK[override["tier"]] > TIER_RANK[tier]:
                tier = override["tier"]

    result.tier = tier
    result.overrides_fired = fired
    return result
