"""CIS Foundations mapping — Track A stage 5.

The mapping is data, not code: `policy/cis/cis-mapping.yaml` is versioned so a
benchmark revision is a data change and old findings keep the control number
they were filed under.
"""

from __future__ import annotations

from app.cis import mapping
from app.scanners.base import Finding


def _finding(rule_id: str, severity: str = "high") -> Finding:
    return Finding(scanner="estate", rule_id=rule_id, severity=severity, title=rule_id)


def test_a_mapped_rule_gains_its_control_number():
    mapped, unmapped = mapping.apply([_finding("estate.storage.public_access")], "aws")
    assert mapped[0].cis_control
    assert unmapped == []


def test_an_unmapped_rule_is_reported_not_silently_dropped():
    """An unmapped rule means the mapping has fallen behind the rules. It must
    surface on the scan, or coverage quietly rots."""
    mapped, unmapped = mapping.apply([_finding("estate.made.up.rule")], "aws")
    assert len(mapped) == 1
    assert mapped[0].cis_control is None
    assert "estate.made.up.rule" in unmapped


def test_the_finding_itself_is_never_dropped_by_mapping():
    findings = [_finding("estate.storage.public_access"), _finding("estate.made.up.rule")]
    mapped, _ = mapping.apply(findings, "aws")
    assert len(mapped) == len(findings)


def test_control_numbers_differ_between_providers():
    """AWS and Azure benchmarks are separate documents; the same rule maps to
    different control numbers, and sometimes to none at all."""
    aws, _ = mapping.apply([_finding("estate.storage.public_access")], "aws")
    azure, _ = mapping.apply([_finding("estate.storage.public_access")], "azure")
    assert aws[0].cis_control != azure[0].cis_control or azure[0].cis_control is None


def test_mapping_is_versioned():
    """The version is written onto the scan so a report can say which benchmark
    revision produced its control numbers."""
    version = mapping.mapping_version()
    assert version
    assert version[0].isdigit()
