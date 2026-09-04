"""Checkov — infrastructure-as-code misconfiguration."""

from __future__ import annotations

import json
from pathlib import Path

from app.models import ProjectModel
from app.scanners.base import Finding, ScannerError, infer_stride, normalize_severity, run_tool


class CheckovScanner:
    name = "checkov"

    def applicable(self, model: ProjectModel | None) -> bool:
        # Only worth running when B2 actually found infrastructure code.
        return bool(model is None or model.iac_files)

    def run(self, workspace: Path) -> list[Finding]:
        result = run_tool(
            ["checkov", "-d", ".", "--framework", "terraform,cloudformation,kubernetes,dockerfile",
             "-o", "json", "--compact", "--quiet"],
            cwd=workspace,
        )
        try:
            data = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise ScannerError("checkov did not emit valid JSON") from exc

        # Checkov returns an object for one framework and a list for several.
        reports = data if isinstance(data, list) else [data]

        findings = []
        for report in reports:
            if not isinstance(report, dict):
                continue
            for check in (report.get("results") or {}).get("failed_checks", []):
                rule_id = check.get("check_id") or "checkov.unknown"
                title = check.get("check_name") or rule_id
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=rule_id,
                        severity=normalize_severity(check.get("severity") or "medium"),
                        title=title,
                        file_path=(check.get("file_path") or "").lstrip("/") or None,
                        line=(check.get("file_line_range") or [None])[0],
                        evidence=(check.get("resource") or None),
                        stride=infer_stride(rule_id, title),
                        cis_control=_cis_from_guideline(check.get("guideline")),
                    )
                )
        return findings


def _cis_from_guideline(guideline: str | None) -> str | None:
    if guideline and "cis" in guideline.lower():
        return guideline[:40]
    return None
