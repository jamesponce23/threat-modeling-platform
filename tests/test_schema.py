"""The canonical resource shape — the contract every connector and the IaC
parser must satisfy, and every rule reads."""

from __future__ import annotations

import pytest

from app.normalize import schema
from app.normalize.schema import Resource, open_rule_severity


def _bucket(**kw) -> Resource:
    base = dict(provider="aws", account="000000000000",
                resource_type=schema.STORAGE_BUCKET,
                resource_id="arn:aws:s3:::example", name="example")
    base.update(kw)
    return Resource(**base)


def test_project_tag_prefers_lowercase_project():
    assert _bucket(tags={"project": "Payments"}).project_tag() == "Payments"


def test_project_tag_accepts_the_documented_aliases():
    for key in schema.PROJECT_TAG_KEYS:
        assert _bucket(tags={key: "Payments"}).project_tag() == "Payments"


def test_project_tag_is_stripped():
    """The correlation join is an exact string match against `project.name`,
    so stray whitespace from a console-entered tag would silently break it."""
    assert _bucket(tags={"project": "  Payments  "}).project_tag() == "Payments"


def test_untagged_resource_has_no_project():
    assert _bucket().project_tag() is None
    assert _bucket(tags={"project": ""}).project_tag() is None


def test_validate_rejects_an_unknown_resource_type():
    """A connector emitting a type no rule handles would otherwise produce a
    scan that reports nothing and looks clean."""
    with pytest.raises(Exception):
        schema.validate(_bucket(resource_type="storage.not_a_real_type"))


def test_validate_accepts_every_canonical_type():
    for canonical in schema.CANONICAL_TYPES:
        schema.validate(_bucket(resource_type=canonical))


def test_as_dict_round_trips_the_fields_the_report_reads():
    resource = _bucket(region="us-east-1", tags={"project": "P"},
                       properties={"public_access": True})
    payload = resource.as_dict()
    assert payload["resource_id"] == "arn:aws:s3:::example"
    assert payload["properties"]["public_access"] is True
    assert payload["tags"]["project"] == "P"
    assert payload["origin"] == "live"


# --- open-ingress severity --------------------------------------------------

@pytest.mark.parametrize("rule", [
    {"protocol": "tcp", "port": 22},
    {"protocol": "tcp", "port": 3389},
    {"protocol": "-1", "port": None},
    {"protocol": "tcp", "port": "0-65535"},
])
def test_admin_ports_and_all_ports_are_critical(rule):
    assert open_rule_severity([rule]) == "critical"


@pytest.mark.parametrize("rule", [
    {"protocol": "tcp", "port": 443},
    {"protocol": "tcp", "port": 8080},
])
def test_other_open_ports_are_medium(rule):
    """A public web listener is worth looking at, not an incident by itself."""
    assert open_rule_severity([rule]) == "medium"


def test_a_range_that_contains_an_admin_port_is_critical():
    assert open_rule_severity([{"protocol": "tcp", "port": 20, "to_port": 25}]) == "critical"


def test_azure_string_port_ranges_are_understood():
    """Azure NSG rules arrive as strings, not integers."""
    assert open_rule_severity([{"protocol": "Tcp", "port": "3389"}]) == "critical"
    assert open_rule_severity([{"protocol": "Tcp", "port": "1000-2000"}]) == "medium"
