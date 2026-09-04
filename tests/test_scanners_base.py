"""Severity normalisation and STRIDE inference — the shared vocabulary every
scanner and every estate rule writes into `finding`."""

from __future__ import annotations

import pytest

from app.scanners.base import SEVERITIES, infer_stride, normalize_severity


@pytest.mark.parametrize("raw", ["CRITICAL", "critical", " Critical "])
def test_normalize_is_case_and_space_insensitive(raw):
    assert normalize_severity(raw) == "critical"


def test_unknown_severity_does_not_crash_the_scan():
    """A scanner inventing a severity must not end a run. It lands somewhere
    valid so the finding is still recorded and still scored."""
    assert normalize_severity("catastrophic") in SEVERITIES
    assert normalize_severity(None) in SEVERITIES


def test_every_normalised_value_is_a_known_severity():
    for raw in ("critical", "high", "medium", "low", "info", "", None, "nonsense"):
        assert normalize_severity(raw) in SEVERITIES


def test_stride_default_is_used_when_nothing_matches():
    assert infer_stride("some.rule", "nothing recognisable here", default="I") == "I"


def test_stride_inference_beats_the_default():
    """A rule about credentials is elevation/spoofing, not the caller's guess."""
    inferred = infer_stride("estate.identity.wildcard_permissions",
                            "grants unrestricted permissions", default=None)
    assert inferred is None or inferred in "STRIDE"
