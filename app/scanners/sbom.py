"""CycloneDX SBOM generation.

Not a scanner: it produces an artefact rather than findings, so it is not part
of the Scanner protocol. B7 offers the result as a download.
"""

from __future__ import annotations

from pathlib import Path

from app.scanners.base import load_report, run_tool


def generate(workspace: Path, output_dir: Path) -> Path:
    """Write a CycloneDX SBOM for the workspace. Returns the file path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    sbom = output_dir / "sbom.json"
    run_tool(
        ["trivy", "fs", "--format", "cyclonedx", "--output", str(sbom), "--quiet", "."],
        cwd=workspace,
    )
    load_report(sbom)  # raises if it was not written or is not JSON
    return sbom
