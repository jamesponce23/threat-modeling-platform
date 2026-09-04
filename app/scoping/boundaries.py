"""Trust boundaries and declared-vs-observed scope mismatches.

The vocabulary below is the canonical one. The build guide says to reuse Track
A stage 3's tagging verbatim, but Track A is not written yet — so this module
defines it and stage 3 adopts these exact strings later. They are the contract
that lets the STRIDE engine consume a project model from either track, so
changing a string here is a breaking change in both.
"""

from __future__ import annotations

# A boundary is a place where trust changes. Four kinds, no more: the point is
# to be consumable by a threat-modelling engine, not to describe topology.
INTERNET_TO_APP = "internet->app"
APP_TO_DATA = "app->data"
APP_TO_THIRD_PARTY = "app->third-party"
LOW_TO_HIGH_PRIVILEGE = "low-priv->high-priv"

BOUNDARY_KINDS = (
    INTERNET_TO_APP,
    APP_TO_DATA,
    APP_TO_THIRD_PARTY,
    LOW_TO_HIGH_PRIVILEGE,
)

# Questionnaire answers that claim the system is not publicly reachable.
NON_PUBLIC_ANSWERS = {"internal_only", "partner_vpn"}


def _boundary(kind: str, source: str, target: str, evidence: list[str]) -> dict:
    return {
        "kind": kind,
        "from": source,
        "to": target,
        "evidence": sorted(set(evidence))[:10],  # capped: this lands in JSONB
    }


def derive(
    *,
    entry_points: list[dict],
    data_stores: list[dict],
    external_dependencies: list[dict],
    privileged_resources: list[dict],
) -> list[dict]:
    """Turn observed facts into tagged trust boundaries."""
    boundaries: list[dict] = []

    public = [e for e in entry_points if e.get("public")]
    if public:
        boundaries.append(
            _boundary(INTERNET_TO_APP, "internet", "application",
                      [e["evidence"] for e in public])
        )

    if data_stores:
        boundaries.append(
            _boundary(APP_TO_DATA, "application", "data store",
                      [d["evidence"] for d in data_stores])
        )

    if external_dependencies:
        boundaries.append(
            _boundary(APP_TO_THIRD_PARTY, "application", "third party",
                      [d["evidence"] for d in external_dependencies])
        )

    if privileged_resources:
        boundaries.append(
            _boundary(LOW_TO_HIGH_PRIVILEGE, "application", "cloud control plane",
                      [p["evidence"] for p in privileged_resources])
        )

    return boundaries


def detect_scope_mismatches(declared: dict[str, str], observed: dict) -> list[dict]:
    """Compare what the submitter said with what the code shows.

    This is the highest-value check in Track B. Self-declared scope is the
    thing people get wrong — usually honestly, because the person filling in
    the form is not the person who wrote the Terraform. Each mismatch is
    recorded as a driver and penalised in B5; the first one is a hard override
    to HIGH, because a project rated on a scope it does not actually have is
    worse than no rating at all.
    """
    mismatches: list[dict] = []

    exposure = declared.get("internet_exposure")
    public = [e for e in observed.get("entry_points", []) if e.get("public")]
    if exposure in NON_PUBLIC_ANSWERS and public:
        mismatches.append(
            {
                "key": "scope_mismatch.exposure",
                "declared": exposure,
                "observed": "publicly reachable entry point found in code or IaC",
                "severity": "high",
                "evidence": sorted({e["evidence"] for e in public})[:10],
            }
        )

    third_party = declared.get("third_party")
    external = observed.get("external_dependencies", [])
    if third_party == "none" and external:
        mismatches.append(
            {
                "key": "scope_mismatch.third_party",
                "declared": "none",
                "observed": f"{len(external)} outbound third-party dependencies found",
                "severity": "medium",
                "evidence": sorted({d["evidence"] for d in external})[:10],
            }
        )

    blast_radius = declared.get("blast_radius")
    privileged = observed.get("privileged_resources", [])
    if blast_radius == "single_service" and privileged:
        mismatches.append(
            {
                "key": "scope_mismatch.blast_radius",
                "declared": "single_service",
                "observed": "IaC creates identity or permission resources",
                "severity": "high",
                "evidence": sorted({p["evidence"] for p in privileged})[:10],
            }
        )

    return mismatches
