"""Fixture tests for B5. Hand-built inputs only — no cloned repo, no scanner
subprocess — so these run in milliseconds and exercise exactly the numbers in
README section 8.
"""

from __future__ import annotations

from app.risk import classifier, overrides
from app.scanners.base import Finding

LOW_FLOOR_ANSWERS = {
    "data_classification": "public",
    "internet_exposure": "internal_only",
    "authentication": "sso_mfa",
    "blast_radius": "single_service",
    "compliance_scope": "none",
    "third_party": "none",
}

HIGH_CEILING_ANSWERS = {
    "data_classification": "regulated",
    "internet_exposure": "public_unauthenticated",
    "authentication": "none_or_shared",
    "blast_radius": "prod_control_plane",
    "compliance_scope": "regulated",
    "third_party": "vendor_prod_access",
}

BOUNDARY_33_ANSWERS = {
    "data_classification": "confidential",
    "internet_exposure": "authenticated_public",
    "authentication": "app_managed_creds",
    "blast_radius": "single_service",
    "compliance_scope": "soc2",
    "third_party": "none",
}


def _medium_finding(rule_id: str) -> Finding:
    return Finding(scanner="semgrep", rule_id=rule_id, severity="medium",
                    title="fixture medium finding")


def _secret_finding() -> Finding:
    return Finding(scanner="gitleaks", rule_id="generic-api-key", severity="high",
                    title="fixture secret")


def _classify(answers, findings, scope_mismatches=None):
    result = classifier.classify(answers, findings, scope_mismatches)
    return overrides.apply(result, answers, findings, scope_mismatches)


def test_low_floor():
    result = _classify(LOW_FLOOR_ANSWERS, [])
    assert result.total_score == 2
    assert result.tier == "LOW"


def test_high_ceiling():
    result = _classify(HIGH_CEILING_ANSWERS, [])
    # Two hard overrides fire on this input (regulated_public,
    # control_plane_access), so tier == HIGH passes even if the weighted sum
    # is broken. Assert the score too, or a broken weight table goes unnoticed.
    assert result.inherent_score == 65
    assert result.tier == "HIGH"


def test_secret_override():
    result = _classify(LOW_FLOOR_ANSWERS, [_secret_finding()])
    # Score alone says LOW (17 <= 34) — this is the one test where score and
    # tier disagree, which is what proves overrides run after scoring and can
    # promote independently of it.
    assert result.total_score == 17
    assert result.tier == "HIGH"
    assert "live_secret" in result.overrides_fired


def test_boundary_34_35():
    at_34 = _classify(BOUNDARY_33_ANSWERS, [_medium_finding("r1")])
    assert at_34.total_score == 34
    assert at_34.tier == "LOW"

    at_35 = _classify(BOUNDARY_33_ANSWERS, [_medium_finding("r1"), _medium_finding("r2")])
    assert at_35.total_score == 35
    assert at_35.tier == "MEDIUM"
