"""Trivy — dependency CVEs, IaC misconfiguration and licences."""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.models import ProjectModel
from app.scanners.base import Finding, infer_stride, load_report, normalize_severity, run_tool


class TrivyScanner:
    name = "trivy"

    def applicable(self, model: ProjectModel | None) -> bool:
        return True

    def run(self, workspace: Path) -> list[Finding]:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "trivy.json"
            run_tool(
                ["trivy", "fs", "--scanners", "vuln,misconfig,license",
                 "--format", "json", "--output", str(report), "--quiet", "."],
                cwd=workspace,
            )
            data = load_report(report)

        findings: list[Finding] = []
        for result in (data or {}).get("Results", []):
            target = result.get("Target")

            for vuln in result.get("Vulnerabilities") or []:
                rule_id = vuln.get("VulnerabilityID") or "trivy.vuln"
                title = f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')}: {vuln.get('Title') or rule_id}"
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=rule_id,
                        severity=normalize_severity(vuln.get("Severity")),
                        title=title[:500],
                        file_path=target,
                        evidence=f"fixed in {vuln.get('FixedVersion')}" if vuln.get("FixedVersion") else None,
                        # A known-vulnerable dependency is tampering with the
                        # integrity of what you are running.
                        stride="T",
                    )
                )

            for misc in result.get("Misconfigurations") or []:
                rule_id = misc.get("ID") or "trivy.misconfig"
                title = misc.get("Title") or rule_id
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=rule_id,
                        severity=normalize_severity(misc.get("Severity")),
                        title=title[:500],
                        file_path=target,
                        line=((misc.get("CauseMetadata") or {}).get("StartLine")),
                        evidence=(misc.get("Resolution") or "")[:500] or None,
                        stride=infer_stride(rule_id, title),
                    )
                )

            for lic in result.get("Licenses") or []:
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=f"license.{lic.get('Name', 'unknown')}",
                        severity=normalize_severity(lic.get("Severity")),
                        title=f"{lic.get('PkgName') or target}: {lic.get('Name')} licence",
                        file_path=lic.get("FilePath") or target,
                        stride=None,  # a licence problem is legal, not STRIDE
                    )
                )
        return findings
