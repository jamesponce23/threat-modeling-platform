"""A scan that covered less than it claims must say so.

Both of the failures pinned here exit **0**. `run_tool` cannot catch them —
the tool did its job on everything it could read, and reported success. What
it skipped produces no findings, which lowers the technical score and improves
the tier: the one file with a syntax error in it reads as the one file that was
clean. These tests exist because that is indistinguishable from a good result
unless something carries the gap out to the report.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from app.scanners.base import ScanOutcome, stderr_warnings
from app.scanners.checkov import CheckovScanner
from app.scanners.semgrep import _parse_warnings


def _completed(stderr: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["tool"], returncode=0, stdout="", stderr=stderr)


def test_scan_outcome_defaults_to_nothing_found_and_nothing_missed():
    outcome = ScanOutcome()
    assert outcome.findings == []
    assert outcome.warnings == []


def test_semgrep_partial_parsing_becomes_a_warning():
    """The exact shape semgrep 1.176 emits: `type` as [name, [spans]], the
    path alongside it, and exit code 0."""
    data = {
        "results": [],
        "errors": [
            {
                "level": "warn",
                "type": ["PartialParsing", [{"path": "app/pay.py"}]],
                "path": "app/pay.py",
                "message": "Syntax error at line app/pay.py:2:\n `nope ]]]` was unexpected",
            }
        ],
    }
    warnings = _parse_warnings(data)
    assert len(warnings) == 1
    assert "PartialParsing" in warnings[0]
    assert "app/pay.py" in warnings[0]
    # The newline in semgrep's message must not survive into a list item.
    assert "\n" not in warnings[0]


def test_semgrep_repeated_errors_for_one_file_collapse():
    error = {"level": "warn", "type": "PartialParsing", "path": "a.py", "message": "boom"}
    assert len(_parse_warnings({"errors": [error, dict(error), dict(error)]})) == 1


def test_semgrep_with_no_errors_warns_about_nothing():
    assert _parse_warnings({"results": [{"check_id": "x"}]}) == []


def test_checkov_parsing_errors_become_a_warning():
    """checkov --compact reports a count, not the file names, so the warning
    says how many files went unchecked and for which framework."""
    reports = [
        {"check_type": "terraform",
         "summary": {"parsing_errors": 2, "failed": 0, "passed": 3},
         "results": {"failed_checks": []}},
        {"check_type": "dockerfile",
         "summary": {"parsing_errors": 0, "failed": 1, "passed": 9},
         "results": {"failed_checks": [
             {"check_id": "CKV_DOCKER_1", "check_name": "root user", "file_path": "/Dockerfile"}]}},
    ]
    outcome = _checkov_outcome(reports)
    assert len(outcome.warnings) == 1
    assert "2 terraform file(s)" in outcome.warnings[0]
    # The framework that parsed cleanly must not produce a warning.
    assert "dockerfile" not in outcome.warnings[0]
    assert len(outcome.findings) == 1


def _checkov_outcome(reports: list[dict]) -> ScanOutcome:
    """Drive CheckovScanner.run's parsing without invoking the binary."""
    import json

    scanner = CheckovScanner()
    original = None
    try:
        import app.scanners.checkov as module

        original = module.run_tool
        module.run_tool = lambda *a, **k: _completed_with_stdout(json.dumps(reports))
        return scanner.run(Path("."))
    finally:
        if original is not None:
            module.run_tool = original


def _completed_with_stdout(stdout: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["checkov"], returncode=0, stdout=stdout, stderr="")


def test_stderr_warnings_keeps_problems_and_drops_progress():
    result = _completed("INF scanned ~49 bytes\nWRN could not read /opt/x: permission denied\nINF done")
    warnings = stderr_warnings("gitleaks", result)
    assert len(warnings) == 1
    assert warnings[0].startswith("gitleaks: ")
    assert "permission denied" in warnings[0]


def test_stderr_warnings_ignores_a_tool_announcing_success():
    """gitleaks logs `WRN leaks found: 2` when it works. A warning that fires
    on every successful detection is one nobody reads."""
    result = _completed("\x1b[90m7:48PM\x1b[0m \x1b[33mWRN\x1b[0m leaks found: 2")
    assert stderr_warnings("gitleaks", result, ignore=("leaks found",)) == []
    # Without the ignore list it would be kept — proving the filter is doing it.
    assert len(stderr_warnings("gitleaks", result)) == 1


def test_stderr_warnings_strips_colour_codes():
    result = _completed("\x1b[31mERROR\x1b[0m failed to fetch db")
    assert "\x1b" not in stderr_warnings("trivy", result)[0]


def test_stderr_warnings_dedupes_and_caps():
    result = _completed("\n".join([f"WARN file {i} unreadable" for i in range(15)] + ["WARN file 1 unreadable"]))
    warnings = stderr_warnings("trivy", result, limit=10)
    assert len(warnings) == 11               # 10 lines plus the "and N more" line
    assert "and 5 more" in warnings[-1]


# --- the worker's side: a scanner that never ran ---------------------------


class _FakeScanner:
    def __init__(self, name: str, outcome=None, error: Exception | None = None, applicable=True):
        self.name = name
        self._outcome = outcome or ScanOutcome()
        self._error = error
        self._applicable = applicable

    def applicable(self, model):
        return self._applicable

    def run(self, workspace):
        if self._error is not None:
            raise self._error
        return self._outcome


def _run_with(scanners):
    import app.worker as worker
    from app.scanners.base import ScannerError  # noqa: F401 - the type worker catches

    original = worker.SCANNERS
    try:
        worker.SCANNERS = tuple(scanners)
        return worker._run_scanners(None, Path("."))
    finally:
        worker.SCANNERS = original


def test_a_scanner_that_failed_is_carried_into_the_warnings():
    """It was already in `failures`, but `failures` only ever reached the RQ
    return value. The rating page reads warnings."""
    from app.scanners.base import Finding, ScannerError

    good = _FakeScanner("good", ScanOutcome(findings=[
        Finding(scanner="good", rule_id="r", severity="high", title="t")]))
    broken = _FakeScanner("broken", error=ScannerError("semgrep is not installed or not on PATH"))

    findings, failures, warnings = _run_with([good, broken])
    assert len(findings) == 1
    assert "broken" in failures
    assert any("DID NOT RUN" in w and "broken" in w for w in warnings)


def test_an_adapter_crash_is_a_warning_too_not_a_dead_scan():
    boom = _FakeScanner("boom", error=ValueError("bad json shape"))
    findings, failures, warnings = _run_with([_FakeScanner("ok"), boom])
    assert findings == []
    assert "ValueError" in failures["boom"]
    assert any("boom" in w for w in warnings)


def test_scanner_warnings_are_collected_from_every_scanner():
    a = _FakeScanner("a", ScanOutcome(warnings=["a: skipped x"]))
    b = _FakeScanner("b", ScanOutcome(warnings=["b: skipped y"]))
    _, failures, warnings = _run_with([a, b])
    assert failures == {}
    assert "a: skipped x" in warnings and "b: skipped y" in warnings


def test_a_not_applicable_scanner_is_named_rather_than_silently_absent():
    """'checkov did not run because there is no IaC' and 'checkov did not run'
    must not look the same on the report."""
    _, failures, warnings = _run_with([
        _FakeScanner("gitleaks"),
        _FakeScanner("checkov", applicable=False),
    ])
    assert failures == {}
    assert any("not applicable" in w and "checkov" in w for w in warnings)
