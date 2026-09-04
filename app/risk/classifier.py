"""B5 — risk classification: turn a questionnaire and a set of findings into
a score and a tier.

Scoring only. Hard overrides that can promote (never lower) the tier live in
app/risk/overrides.py and run on this module's output — keeping "how risky
does this look" separate from "what must always be HIGH regardless of the
math" is what makes the second one auditable on its own.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.config import settings
from app.scanners.base import Finding
from app.scoping.questionnaire import QUESTION_KEYS, score_for


@functools.lru_cache(maxsize=1)
def load_risk_model(path: str | None = None) -> dict:
    """Read policy/risk/risk-model.yaml once per process.

    Cached rather than re-read per submission: the file is deployed with the
    app, not edited live, and a submission mid-flight should not see the
    weights change under it.
    """
    text = Path(path or settings.risk_model_path).read_text()
    return yaml.safe_load(text)


@dataclass
class Driver:
    factor: str
    points: int
    evidence: str

    def as_dict(self) -> dict:
        return {"factor": self.factor, "points": self.points, "evidence": self.evidence}


@dataclass
class ScoreResult:
    inherent_score: int
    technical_score: int
    total_score: int
    tier: str
    drivers: list[Driver] = field(default_factory=list)
    model_version: str = ""
    overrides_fired: list[str] = field(default_factory=list)


def _tier_for(total: int, thresholds: dict) -> str:
    if total <= thresholds["low_max"]:
        return "LOW"
    if total <= thresholds["medium_max"]:
        return "MEDIUM"
    return "HIGH"


def score_inherent(answers: dict[str, str], model: dict) -> tuple[int, list[Driver]]:
    """0-65: the questionnaire, scored against policy weights.

    `score_for` raises on an answer value that is not a valid option, so a
    corrupt or hand-edited questionnaire row fails loudly here rather than
    silently scoring as zero.
    """
    weights = model["inherent"]["weights"]
    drivers: list[Driver] = []
    total = 0
    for key in QUESTION_KEYS:
        points = score_for(key, answers[key]) * weights[key]
        total += points
        if points:
            drivers.append(Driver(factor=f"questionnaire: {key}", points=points,
                                   evidence=f"{key} = {answers[key]}"))
    return total, drivers


SECRET_SCANNER = "gitleaks"


def _is_cve(finding: Finding) -> bool:
    return finding.rule_id.upper().startswith("CVE-")


def _is_iac_critical(finding: Finding) -> bool:
    """Checkov output, or a trivy misconfig (not a CVE), at critical severity.

    IaC misconfigurations get extra weight because one of them — a public
    bucket, an open security group — is a standing hole, not a library version
    waiting to be exploited. The generic severity band still applies too; this
    adds on top of it.
    """
    if finding.severity != "critical":
        return False
    if finding.scanner == "checkov":
        return True
    if finding.scanner == "trivy" and not _is_cve(finding):
        return True
    return False


def score_technical(
    findings: list[Finding], scope_mismatches: list[dict], model: dict
) -> tuple[int, list[Driver]]:
    """0-35: findings plus B3's declared-vs-observed scope check."""
    technical = model["technical"]
    points_table = technical["points"]
    caps = technical["caps"]
    extra = technical["extra"]

    band_totals: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    secret_count = 0
    iac_critical_count = 0

    for f in findings:
        if f.scanner == SECRET_SCANNER:
            secret_count += 1
            continue
        band_totals[f.severity] = band_totals.get(f.severity, 0) + points_table.get(f.severity, 0)
        if _is_iac_critical(f):
            iac_critical_count += 1

    drivers: list[Driver] = []
    total = 0

    for band in ("critical", "high", "medium"):
        cap = caps.get(f"{band}_total")
        raw = band_totals.get(band, 0)
        capped = min(raw, cap) if cap is not None else raw
        if capped:
            count = sum(1 for f in findings if f.scanner != SECRET_SCANNER and f.severity == band)
            drivers.append(Driver(factor=f"{band} severity findings", points=capped,
                                   evidence=f"{count} finding(s)"))
        total += capped

    if secret_count:
        secret_points = secret_count * extra["verified_secret"]
        drivers.append(Driver(factor="verified secret(s)", points=secret_points,
                               evidence=f"{secret_count} gitleaks finding(s)"))
        total += secret_points

    if iac_critical_count:
        iac_points = min(iac_critical_count * extra["iac_critical_misconfig"], extra["iac_misconfig_cap"])
        drivers.append(Driver(factor="critical IaC misconfiguration(s)", points=iac_points,
                               evidence=f"{iac_critical_count} finding(s)"))
        total += iac_points

    if scope_mismatches:
        drivers.append(Driver(factor="declared vs. observed scope mismatch",
                               points=extra["scope_mismatch"],
                               evidence=", ".join(m["key"] for m in scope_mismatches)[:200]))
        total += extra["scope_mismatch"]

    return min(total, technical["max_total"]), drivers


def classify(
    answers: dict[str, str],
    findings: list[Finding],
    scope_mismatches: list[dict] | None = None,
    *,
    model: dict | None = None,
) -> ScoreResult:
    """Score a submission. Overrides (app/risk/overrides.py) run on the result."""
    model = model or load_risk_model()
    scope_mismatches = scope_mismatches or []

    inherent, inherent_drivers = score_inherent(answers, model)
    technical, technical_drivers = score_technical(findings, scope_mismatches, model)
    total = inherent + technical

    drivers = sorted(inherent_drivers + technical_drivers, key=lambda d: d.points, reverse=True)[:5]

    return ScoreResult(
        inherent_score=inherent,
        technical_score=technical,
        total_score=total,
        tier=_tier_for(total, model["thresholds"]),
        drivers=drivers,
        model_version=model["model_version"],
    )
