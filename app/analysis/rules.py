"""Stage 4: turn canonical resources into findings.

Each rule is a small function over one Resource. They are deliberately
independent - a rule that raises is reported and skipped, never allowed to
abandon the scan, because one bad rule silently zeroing a whole account's
findings is the failure mode this project exists to prevent.

Severity and STRIDE vocabulary come from app/scanners/base.py so Track A and
Track B findings are directly comparable in the shared store.

Three-valued properties: a boolean property may be None, meaning the
connector could not read it. Rules test `is False` / `is True`, never
truthiness, so "unknown" is neither reported as a misconfiguration nor
counted as clean. The one exception is `storage_access_unknown`, which exists
precisely to make "could not check" visible in the report.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from app.normalize import schema
from app.normalize.schema import Resource
from app.scanners.base import (
    STRIDE_ELEVATION,
    STRIDE_INFO_DISCLOSURE,
    STRIDE_REPUDIATION,
    Finding,
)

SCANNER_NAME = "estate"


def _finding(resource: Resource, rule_id: str, severity: str, title: str, stride: str) -> Finding:
    return Finding(
        scanner=SCANNER_NAME,
        rule_id=rule_id,
        severity=severity,
        title=title,
        file_path=resource.origin[len("iac:"):] if resource.origin.startswith("iac:") else None,
        evidence=evidence_for(resource),
        stride=stride,
    )


def evidence_for(resource: Resource) -> str:
    """The string that identifies a resource in `finding.evidence`.

    Used as the dedup key in app/findings/store.py and the join key in
    correlate(), so it is defined once, here.
    """
    return f"{resource.provider}:{resource.resource_type} {resource.resource_id}"


# --- rules ------------------------------------------------------------------


def storage_public(resource: Resource) -> Finding | None:
    if resource.resource_type != schema.STORAGE_BUCKET:
        return None
    if resource.properties.get("public_access") is not True:
        return None
    return _finding(
        resource, "estate.storage.public_access", "critical",
        f"Storage '{resource.name}' allows public access", STRIDE_INFO_DISCLOSURE,
    )


def storage_access_unknown(resource: Resource) -> Finding | None:
    """The scanning identity could not read the bucket's access settings.

    Reported on purpose: a bucket nobody can inspect is not a clean bucket.
    Fix the scanner's permissions (SecurityAudit / Reader) and rescan.
    """
    if resource.resource_type != schema.STORAGE_BUCKET:
        return None
    if "public_access" not in resource.properties or resource.properties["public_access"] is not None:
        return None
    return _finding(
        resource, "estate.storage.access_unknown", "medium",
        f"Storage '{resource.name}': public-access settings could not be read (permission denied)",
        STRIDE_INFO_DISCLOSURE,
    )


def storage_unencrypted(resource: Resource) -> Finding | None:
    if resource.resource_type != schema.STORAGE_BUCKET:
        return None
    if resource.properties.get("encrypted_at_rest", True) is not False:
        return None
    return _finding(
        resource, "estate.storage.unencrypted", "high",
        f"Storage '{resource.name}' has no encryption at rest configured", STRIDE_INFO_DISCLOSURE,
    )


def storage_tls_not_enforced(resource: Resource) -> Finding | None:
    if resource.resource_type != schema.STORAGE_BUCKET:
        return None
    if resource.properties.get("encryption_in_transit_required", True) is not False:
        return None
    return _finding(
        resource, "estate.storage.tls_not_enforced", "medium",
        f"Storage '{resource.name}' does not require encrypted transport", STRIDE_INFO_DISCLOSURE,
    )


def network_open_to_internet(resource: Resource) -> Finding | None:
    """Critical when an admin port (22/3389) or every port is open to the
    world - that is what CIS AWS 5.2/5.3 and CIS Azure 6.1/6.2 name. Other
    ports open to 0.0.0.0/0 (a web listener on 443, say) are medium: worth a
    look, not an incident on their own."""
    if resource.resource_type != schema.NETWORK_SECURITY_GROUP:
        return None
    open_rules = resource.properties.get("open_ingress_rules") or []
    if not open_rules:
        return None
    ports = ", ".join(_port_label(r) for r in open_rules[:5])
    return _finding(
        resource, "estate.network.open_ingress", schema.open_rule_severity(open_rules),
        f"Security group '{resource.name}' allows inbound from the internet (ports: {ports})",
        STRIDE_INFO_DISCLOSURE,
    )


def _port_label(rule: dict) -> str:
    port, to_port = rule.get("port"), rule.get("to_port")
    if port is None or str(rule.get("protocol", "")).lower() in ("-1", "*", "all"):
        return "all"
    if to_port not in (None, port):
        return f"{port}-{to_port}"
    return str(port)


def identity_wildcard_permissions(resource: Resource) -> Finding | None:
    if resource.resource_type not in (schema.IDENTITY_POLICY, schema.IDENTITY_ASSIGNMENT):
        return None
    wildcards = resource.properties.get("wildcard_permissions") or []
    if not wildcards:
        return None
    return _finding(
        resource, "estate.identity.wildcard_permissions", "high",
        f"'{resource.name}' grants unrestricted permissions ({', '.join(wildcards[:3])})",
        STRIDE_ELEVATION,
    )


def identity_role_trusts_everyone(resource: Resource) -> Finding | None:
    if resource.resource_type != schema.IDENTITY_ROLE:
        return None
    if resource.properties.get("public_access") is not True:
        return None
    return _finding(
        resource, "estate.identity.role_trusts_any_principal", "critical",
        f"Role '{resource.name}' can be assumed by any principal", STRIDE_ELEVATION,
    )


def database_public(resource: Resource) -> Finding | None:
    if resource.resource_type != schema.DATABASE_INSTANCE:
        return None
    if resource.properties.get("public_access") is not True:
        return None
    return _finding(
        resource, "estate.database.public_access", "critical",
        f"Database '{resource.name}' is reachable from the public internet", STRIDE_INFO_DISCLOSURE,
    )


def database_unencrypted(resource: Resource) -> Finding | None:
    if resource.resource_type != schema.DATABASE_INSTANCE:
        return None
    if resource.properties.get("encrypted_at_rest", True) is not False:
        return None
    return _finding(
        resource, "estate.database.unencrypted", "high",
        f"Database '{resource.name}' has unencrypted storage", STRIDE_INFO_DISCLOSURE,
    )


def audit_trail_not_multi_region(resource: Resource) -> Finding | None:
    if resource.resource_type != schema.AUDIT_TRAIL:
        return None
    if resource.properties.get("multi_region") is not False:
        return None
    return _finding(
        resource, "estate.audit.trail_not_multi_region", "medium",
        f"Audit trail '{resource.name}' does not cover all regions", STRIDE_REPUDIATION,
    )


def audit_trail_not_logging(resource: Resource) -> Finding | None:
    """A trail that exists but is switched off looks like coverage and is not."""
    if resource.resource_type != schema.AUDIT_TRAIL:
        return None
    if resource.properties.get("logging_enabled", True) is not False:
        return None
    return _finding(
        resource, "estate.audit.trail_not_logging", "high",
        f"Audit trail '{resource.name}' exists but is not logging", STRIDE_REPUDIATION,
    )


RULES: tuple[Callable[[Resource], Finding | None], ...] = (
    storage_public,
    storage_access_unknown,
    storage_unencrypted,
    storage_tls_not_enforced,
    network_open_to_internet,
    identity_wildcard_permissions,
    identity_role_trusts_everyone,
    database_public,
    database_unencrypted,
    audit_trail_not_multi_region,
    audit_trail_not_logging,
)


def analyze(resources: Iterable[Resource]) -> tuple[list[Finding], list[str]]:
    """Run every rule over every resource. Returns (findings, rule_errors)."""
    findings: list[Finding] = []
    errors: list[str] = []

    for resource in resources:
        for rule in RULES:
            try:
                finding = rule(resource)
            except Exception as exc:  # noqa: BLE001 - one bad rule must not end the scan
                errors.append(f"{rule.__name__} on {resource.resource_id}: {exc}")
                continue
            if finding is not None:
                findings.append(finding)

    return findings, errors


def missing_audit_trail(resources: Iterable[Resource], account: str) -> Finding | None:
    """An account with no trail at all produces no per-resource finding.

    Absence is the finding here: rules that iterate resources can only report
    on things that exist, so 'there is no CloudTrail' (or, on Azure, 'no
    diagnostic setting exports the Activity Log') has to be checked separately
    or it is never reported. Both connectors emit `audit.trail` resources, so
    this is a fair question to ask of either cloud.
    """
    if any(r.resource_type == schema.AUDIT_TRAIL for r in resources):
        return None
    return Finding(
        scanner=SCANNER_NAME,
        rule_id="estate.audit.no_trail",
        severity="high",
        title=f"Account {account} has no audit trail configured",
        evidence=f"account:{account}",
        stride=STRIDE_REPUDIATION,
    )
