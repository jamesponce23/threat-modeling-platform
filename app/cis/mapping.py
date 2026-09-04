"""Stage 5: attach a CIS control reference to each finding.

Unmapped findings are counted, not dropped. A rule added without a control
mapping should show up as a gap in the coverage report rather than quietly
producing findings no auditor can place.
"""

from __future__ import annotations

import functools
from pathlib import Path

import yaml

from app.scanners.base import Finding

DEFAULT_PATH = "policy/cis/cis-mapping.yaml"


@functools.lru_cache(maxsize=1)
def load_mapping(path: str = DEFAULT_PATH) -> dict:
    return yaml.safe_load(Path(path).read_text())


def apply(findings: list[Finding], provider: str, *, path: str = DEFAULT_PATH) -> tuple[list[Finding], list[str]]:
    """Set `cis_control` on each finding. Returns (findings, unmapped rule ids)."""
    mapping = load_mapping(path)
    controls = mapping.get("controls", {})

    unmapped: list[str] = []
    for finding in findings:
        entry = controls.get(finding.rule_id)
        control = (entry or {}).get(provider)
        if control:
            finding.cis_control = control[:40]
        else:
            unmapped.append(finding.rule_id)

    return findings, sorted(set(unmapped))


def mapping_version(path: str = DEFAULT_PATH) -> str:
    return str(load_mapping(path).get("mapping_version", "unknown"))
