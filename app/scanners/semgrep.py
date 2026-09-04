"""Semgrep — static analysis of the source itself."""

from __future__ import annotations

import json
from pathlib import Path

from app.models import ProjectModel
from app.scanners.base import Finding, ScannerError, infer_stride, normalize_severity, run_tool

# Registry rulesets. These are fetched over the network on first use and then
# cached, so an offline worker fails here rather than silently scanning with
# nothing — which is the correct behaviour: a scan with no rules is not a scan.
RULESETS = ("p/security-audit", "p/secrets")


class SemgrepScanner:
    name = "semgrep"

    def applicable(self, model: ProjectModel | None) -> bool:
        return bool(model is None or model.languages)

    def run(self, workspace: Path) -> list[Finding]:
        command = ["semgrep", "--json", "--quiet", "--no-git-ignore",
                   "--metrics", "off", "--disable-version-check"]
        for ruleset in RULESETS:
            command += ["--config", ruleset]
        command.append(".")

        result = run_tool(command, cwd=workspace)
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerError("semgrep did not emit valid JSON") from exc

        findings = []
        for item in data.get("results", []):
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            rule_id = item.get("check_id") or "semgrep.unknown"
            title = extra.get("message") or rule_id
            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    severity=normalize_severity(
                        metadata.get("impact") or extra.get("severity")
                    ),
                    title=title.strip()[:500],
                    file_path=item.get("path"),
                    line=(item.get("start") or {}).get("line"),
                    evidence=(extra.get("lines") or "").strip()[:500] or None,
                    # A rule can declare its own STRIDE category in metadata;
                    # otherwise fall back to keyword inference.
                    stride=metadata.get("stride") or infer_stride(rule_id, title),
                    cis_control=_first(metadata.get("cis")),
                )
            )
        return findings


def _first(value) -> str | None:
    if isinstance(value, list):
        return str(value[0])[:40] if value else None
    return str(value)[:40] if value else None
