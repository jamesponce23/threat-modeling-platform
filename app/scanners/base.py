"""One interface, one finding shape, one place that knows about exit codes.

Adding a tool later should be a new file and nothing else. Everything that is
tool-specific — severity words, exit-code conventions, STRIDE category — is
normalised here so that B5 never sees a scanner's private vocabulary.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.config import settings
from app.models import ProjectModel

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Every tool spells severity differently. This table is the only place that is
# allowed to know that.
SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical", "blocker": "critical",
    "high": "high", "error": "high", "severe": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "medium_high": "medium",
    "low": "low", "minor": "low", "note": "low",
    "info": "info", "informational": "info", "unknown": "info", "none": "info",
}

# STRIDE: Spoofing, Tampering, Repudiation, Information disclosure,
# Denial of service, Elevation of privilege. Stored on the finding so the
# HIGH-tier threat model starts pre-populated rather than blank.
STRIDE_SPOOFING = "S"
STRIDE_TAMPERING = "T"
STRIDE_REPUDIATION = "R"
STRIDE_INFO_DISCLOSURE = "I"
STRIDE_DENIAL_OF_SERVICE = "D"
STRIDE_ELEVATION = "E"

STRIDE_KEYWORDS = (
    ("public", STRIDE_INFO_DISCLOSURE),
    ("encrypt", STRIDE_INFO_DISCLOSURE),
    ("secret", STRIDE_INFO_DISCLOSURE),
    ("credential", STRIDE_INFO_DISCLOSURE),
    ("logging", STRIDE_REPUDIATION),
    ("audit", STRIDE_REPUDIATION),
    ("auth", STRIDE_SPOOFING),
    ("iam", STRIDE_ELEVATION),
    ("privilege", STRIDE_ELEVATION),
    ("role", STRIDE_ELEVATION),
    ("ingress", STRIDE_INFO_DISCLOSURE),
    ("0.0.0.0", STRIDE_INFO_DISCLOSURE),
    ("unencrypted", STRIDE_INFO_DISCLOSURE),
    ("tls", STRIDE_INFO_DISCLOSURE),
    ("root", STRIDE_ELEVATION),
    ("injection", STRIDE_TAMPERING),
    ("sql", STRIDE_TAMPERING),
    ("deserial", STRIDE_TAMPERING),
    ("dos", STRIDE_DENIAL_OF_SERVICE),
    ("denial", STRIDE_DENIAL_OF_SERVICE),
)


def normalize_severity(raw: str | None) -> str:
    if not raw:
        return "info"
    return SEVERITY_ALIASES.get(str(raw).strip().lower(), "info")


def infer_stride(rule_id: str, title: str, default: str | None = None) -> str | None:
    """Best-effort STRIDE tag from the rule text. Never guesses beyond keywords."""
    haystack = f"{rule_id} {title}".lower()
    for keyword, category in STRIDE_KEYWORDS:
        if keyword in haystack:
            return category
    return default


@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: str
    title: str
    file_path: str | None = None
    line: int | None = None
    evidence: str | None = None
    stride: str | None = None
    cis_control: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@runtime_checkable
class Scanner(Protocol):
    name: str

    def applicable(self, model: ProjectModel | None) -> bool: ...

    def run(self, workspace: Path) -> list[Finding]: ...


class ScannerError(RuntimeError):
    """The tool did not produce a usable report. Distinct from 'found nothing'."""


# THE MOST IMPORTANT FOUR LINES IN THIS FILE.
#
# These tools exit non-zero when they FIND something. Gitleaks exits 1 on a
# leak; Checkov exits 1 on a failed check. Calling them with check=True means a
# successful scan of a genuinely vulnerable repository raises CalledProcessError
# and is recorded as a failed scan — so the dirtier the repository, the more
# reliably the platform reports nothing. That is the exact failure this project
# exists to prevent, sitting inside the project.
#
# 0 and 1 are both success. Anything else is a real error.
FINDINGS_EXIT_CODES = frozenset({0, 1})


def run_tool(command: list[str], cwd: Path, *, ok_codes: frozenset[int] = FINDINGS_EXIT_CODES):
    """Run a scanner. Never check=True. Returns the CompletedProcess."""
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_sec,
            check=False,  # deliberately: see the comment above
        )
    except FileNotFoundError as exc:
        # A missing binary must be loud. Silently returning no findings would
        # read as a clean scan, which is the worst possible failure here.
        raise ScannerError(f"{command[0]} is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{command[0]} exceeded SCAN_TIMEOUT_SEC") from exc

    if result.returncode not in ok_codes:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise ScannerError(
            f"{command[0]} exited {result.returncode}: {detail[-1] if detail else 'no output'}"
        )
    return result


def load_report(path: Path) -> dict | list:
    """Read a tool's JSON report. A missing or unparseable report is an error."""
    if not path.exists():
        raise ScannerError(f"{path.name} was not written")
    try:
        text = path.read_text()
        return json.loads(text) if text.strip() else []
    except json.JSONDecodeError as exc:
        raise ScannerError(f"{path.name} is not valid JSON") from exc


# NOTE ON SANDBOXING. These adapters invoke the tools directly, because they are
# installed locally and this is a single-user development box. The tools parse
# files from a repository nobody vetted, so a production deployment should run
# each one in a throwaway container with no network and a read-only mount:
#
#   docker run --rm --network none --read-only \
#     -v "$WORKSPACE:/src:ro" -v "$OUT:/out" \
#     aquasec/trivy:latest fs --scanners vuln,misconfig --format json --output /out/trivy.json /src
#
# Section 11 is where that belongs. Until then this is a known, deliberate gap
# rather than an oversight.
