"""The misconfiguration rules — Track A's stage 4.

Every rule takes one Resource and returns a Finding or None, so each can be
exercised without a cloud account, a database, or a scanner subprocess.
"""

from __future__ import annotations

import pytest

from app.analysis import rules
from app.normalize import schema
from app.normalize.schema import Resource


def _resource(resource_type: str, **kw) -> Resource:
    base = dict(provider="aws", account="000000000000",
                resource_type=resource_type,
                resource_id=f"arn:aws:test:::{resource_type}", name="thing")
    base.update(kw)
    return Resource(**base)


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --- storage ----------------------------------------------------------------

def test_public_bucket_is_critical():
    finding = rules.storage_public(
        _resource(schema.STORAGE_BUCKET, properties={"public_access": True}))
    assert finding is not None
    assert finding.rule_id == "estate.storage.public_access"
    assert finding.severity == "critical"


def test_private_bucket_produces_nothing():
    assert rules.storage_public(
        _resource(schema.STORAGE_BUCKET, properties={"public_access": False})) is None


def test_unreadable_bucket_is_reported_not_assumed_public():
    """`None` means the scanning identity was denied, not that the bucket is
    public. Treating unknown as public produced false criticals against a real
    account; treating it as private hides a genuinely exposed bucket."""
    unknown = _resource(schema.STORAGE_BUCKET, properties={"public_access": None})
    assert rules.storage_public(unknown) is None
    finding = rules.storage_access_unknown(unknown)
    assert finding is not None
    assert finding.rule_id == "estate.storage.access_unknown"
    assert finding.severity == "medium"


def test_access_unknown_stays_quiet_when_the_value_was_readable():
    for value in (True, False):
        resource = _resource(schema.STORAGE_BUCKET, properties={"public_access": value})
        assert rules.storage_access_unknown(resource) is None


def test_encryption_and_tls_default_to_compliant_when_absent():
    """A property the connector could not populate must not manufacture a
    finding — absence is not evidence of misconfiguration."""
    bare = _resource(schema.STORAGE_BUCKET, properties={})
    assert rules.storage_unencrypted(bare) is None
    assert rules.storage_tls_not_enforced(bare) is None


def test_explicit_false_does_produce_the_finding():
    resource = _resource(schema.STORAGE_BUCKET, properties={
        "encrypted_at_rest": False, "encryption_in_transit_required": False})
    assert rules.storage_unencrypted(resource).severity == "high"
    assert rules.storage_tls_not_enforced(resource).severity == "medium"


# --- network ----------------------------------------------------------------

def test_open_ssh_is_critical_and_names_the_port():
    finding = rules.network_open_to_internet(_resource(
        schema.NETWORK_SECURITY_GROUP,
        properties={"open_ingress_rules": [{"protocol": "tcp", "port": 22}]}))
    assert finding.severity == "critical"
    assert "22" in finding.title


def test_closed_security_group_produces_nothing():
    assert rules.network_open_to_internet(_resource(
        schema.NETWORK_SECURITY_GROUP, properties={"open_ingress_rules": []})) is None


# --- identity ---------------------------------------------------------------

def test_wildcard_policy_is_high_and_elevation():
    finding = rules.identity_wildcard_permissions(_resource(
        schema.IDENTITY_POLICY, properties={"wildcard_permissions": ["s3:*"]}))
    assert finding.severity == "high"
    assert finding.stride == "E"


def test_role_trusting_any_principal_is_critical():
    finding = rules.identity_role_trusts_everyone(_resource(
        schema.IDENTITY_ROLE, properties={"public_access": True}))
    assert finding.rule_id == "estate.identity.role_trusts_any_principal"
    assert finding.severity == "critical"


# --- audit ------------------------------------------------------------------

def test_a_trail_that_is_switched_off_outranks_one_that_is_single_region():
    """A disabled trail looks like coverage and is not, so it is the more
    serious of the two."""
    off = rules.audit_trail_not_logging(_resource(
        schema.AUDIT_TRAIL, properties={"logging_enabled": False}))
    partial = rules.audit_trail_not_multi_region(_resource(
        schema.AUDIT_TRAIL, properties={"multi_region": False}))
    assert off.severity == "high"
    assert partial.severity == "medium"
    assert off.stride == partial.stride == "R"


# --- wiring -----------------------------------------------------------------

def test_rules_only_fire_on_their_own_resource_type():
    """Every rule must type-check first, or a bucket property name colliding
    with a database one would cross-fire."""
    bucket = _resource(schema.STORAGE_BUCKET, properties={"public_access": True})
    assert rules.database_public(bucket) is None
    assert rules.identity_role_trusts_everyone(bucket) is None
    assert rules.network_open_to_internet(bucket) is None


def test_analyze_runs_every_rule_and_reports_no_errors_on_clean_input():
    findings, errors = rules.analyze([
        _resource(schema.STORAGE_BUCKET, properties={"public_access": True}),
        _resource(schema.IDENTITY_POLICY, properties={"wildcard_permissions": ["*"]}),
    ])
    assert errors == []
    assert "estate.storage.public_access" in _ids(findings)
    assert "estate.identity.wildcard_permissions" in _ids(findings)


def test_one_broken_rule_does_not_end_the_scan():
    """`analyze` collects rule exceptions rather than propagating them — a
    single malformed resource must not cost the whole estate."""
    findings, errors = rules.analyze([
        _resource(schema.NETWORK_SECURITY_GROUP,
                  properties={"open_ingress_rules": [{"protocol": None, "port": object()}]}),
        _resource(schema.STORAGE_BUCKET, properties={"public_access": True}),
    ])
    assert "estate.storage.public_access" in _ids(findings)


def test_evidence_is_stable_and_identifies_the_resource():
    """`evidence_for` is the dedup key in the store and the join key in
    correlate(), so its shape is load-bearing."""
    resource = _resource(schema.STORAGE_BUCKET, properties={"public_access": True})
    findings, _ = rules.analyze([resource])
    assert all(f.evidence == rules.evidence_for(resource) for f in findings)
    assert resource.resource_id in rules.evidence_for(resource)
