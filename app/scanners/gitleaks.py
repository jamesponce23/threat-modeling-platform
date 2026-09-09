"""Gitleaks — secrets in the working tree."""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.models import ProjectModel
from app.scanners.base import (
    Finding,
    ScanOutcome,
    ScannerError,
    load_report,
    normalize_severity,
    run_tool,
    stderr_warnings,
)


class GitleaksScanner:
    name = "gitleaks"

    def applicable(self, model: ProjectModel | None) -> bool:
        return True  # every repository can leak a secret

    def run(self, workspace: Path) -> ScanOutcome:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "gitleaks.json"
            # `gitleaks detect` was deprecated in v8.19.0. `dir` is the current
            # filesystem scan and the direct replacement for `detect --no-git`;
            # B2 clones --depth 1 so there is no history worth walking anyway.
            result = run_tool(
                ["gitleaks", "dir", ".", "--report-format", "json",
                 "--report-path", str(report), "--no-banner", "--redact"],
                cwd=workspace,
            )
            data = load_report(report)

        findings = []
        for item in data or []:
            rule_id = item.get("RuleID") or "gitleaks.generic"
            title = item.get("Description") or rule_id
            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    # Gitleaks does not grade severity: a live credential in a
                    # repository is high by definition.
                    severity="high",
                    title=title,
                    file_path=item.get("File"),
                    line=item.get("StartLine"),
                    # --redact means Secret is masked; Match is the surrounding
                    # line, already redacted. Never store the raw secret.
                    evidence=(item.get("Match") or "")[:500] or None,
                    stride="I",  # a leaked credential is information disclosure
                )
            )
        return ScanOutcome(findings=findings, warnings=stderr_warnings(self.name, result, ignore=("leaks found",)))
