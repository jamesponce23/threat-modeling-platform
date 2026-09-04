"""B7 — turn a tier into a gate decision and the controls it requires."""

from __future__ import annotations

GATE_BY_TIER = {
    "LOW": "approved",
    "MEDIUM": "conditional",
    "HIGH": "blocked",
}

REQUIRED_CONTROLS = {
    "LOW": [
        "Self-serve hardening checklist",
        "Re-scan on every PR",
        "No human review required",
    ],
    "MEDIUM": [
        "All critical and high findings remediated or formally accepted",
        "Security peer review of the scoped model",
        "Re-scan clean before release",
    ],
    "HIGH": [
        "Full STRIDE threat model, seeded from the B3 project model and B4 STRIDE tags",
        "Named security architect review",
        "Penetration test before GA",
        "Documented executive risk acceptance for anything shipping with open critical findings",
    ],
}


def decide(tier: str) -> tuple[str, list[str]]:
    """(decision, required_controls) for a tier. Raises on an unknown tier —
    a rating with no gate mapping must not silently pass through as approved."""
    if tier not in GATE_BY_TIER:
        raise ValueError(f"no gate mapping for tier {tier!r}")
    return GATE_BY_TIER[tier], REQUIRED_CONTROLS[tier]
