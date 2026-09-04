"""The canonical resource shape. Both connectors and the IaC parser emit this.

The point of normalising is that a misconfiguration rule should be written
once. "Storage that the internet can read" is the same finding whether it is
an S3 bucket or an Azure storage account, so both become `storage.bucket` with
a `public_access` property, and one rule catches both.

Provider-specific detail is not thrown away - it stays in `properties` under
its original key - but the keys a rule is allowed to depend on are the ones
listed in CANONICAL_PROPERTIES below. A rule reading anything else is a rule
that only works on one cloud, which is the thing this schema exists to stop.

Three-valued properties. A boolean canonical property may be True, False or
None. None means "could not be determined" - typically a permission the
scanning identity lacks - and it is NOT the same as False. A connector that
cannot read a bucket's public-access block must say so, not guess; a rule that
treats None as "safe" would turn every missing permission into a clean report.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Canonical resource types. Deliberately coarse: the analysis engine cares
# about what a thing does, not what a vendor calls it.
STORAGE_BUCKET = "storage.bucket"
NETWORK_SECURITY_GROUP = "network.security_group"
IDENTITY_ROLE = "identity.role"
IDENTITY_POLICY = "identity.policy"
IDENTITY_ASSIGNMENT = "identity.assignment"
DATABASE_INSTANCE = "database.instance"
COMPUTE_INSTANCE = "compute.instance"
AUDIT_TRAIL = "audit.trail"

CANONICAL_TYPES = (
    STORAGE_BUCKET,
    NETWORK_SECURITY_GROUP,
    IDENTITY_ROLE,
    IDENTITY_POLICY,
    IDENTITY_ASSIGNMENT,
    DATABASE_INSTANCE,
    COMPUTE_INSTANCE,
    AUDIT_TRAIL,
)

# Property keys a cross-cloud rule may rely on. Anything else belongs in
# `properties` but must not be the basis of a shared rule.
CANONICAL_PROPERTIES = (
    "public_access",        # bool | None - reachable by anonymous internet callers
    "encrypted_at_rest",    # bool | None
    "encryption_in_transit_required",  # bool | None
    "open_ingress_rules",   # list[dict] - {port, to_port, protocol, source}
    "wildcard_permissions", # list[str]  - actions granted as "*"
    "privileged_scope",     # str | None - e.g. "subscription", "account"
    "multi_region",         # bool
    "logging_enabled",      # bool | None
)

# The tag key used to attribute a live resource back to a Track B project.
PROJECT_TAG_KEYS = ("project", "Project", "PROJECT", "app", "Application")

# Ports whose exposure to the internet CIS calls out by name (AWS 5.2/5.3,
# Azure 6.1/6.2): remote administration. Everything else open to the world is
# still a finding, just not a critical one on its own.
ADMIN_PORTS = frozenset({22, 3389})


@dataclass
class Resource:
    """One normalised cloud resource, live or declared."""

    provider: str            # "aws" | "azure"
    account: str             # AWS account id / Azure subscription id
    resource_type: str       # one of CANONICAL_TYPES
    resource_id: str         # ARN or Azure resource id - globally unique
    name: str
    region: str | None = None
    properties: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)
    # "live" for a connector, or "iac:<path>" for the parser - so a finding
    # can say whether it describes something running or something declared.
    origin: str = "live"

    def project_tag(self) -> str | None:
        """The Track B project this resource claims to belong to, if tagged."""
        for key in PROJECT_TAG_KEYS:
            value = self.tags.get(key)
            if value:
                return str(value).strip()
        return None

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "account": self.account,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "name": self.name,
            "region": self.region,
            "properties": self.properties,
            "tags": self.tags,
            "origin": self.origin,
        }


def validate(resource: Resource) -> Resource:
    """Fail loudly on a resource type no rule knows how to handle.

    A connector emitting an unrecognised type would otherwise produce a
    resource that every rule silently skips - a scan that reports nothing and
    looks clean.
    """
    if resource.resource_type not in CANONICAL_TYPES:
        raise ValueError(
            f"{resource.resource_id}: {resource.resource_type!r} is not a canonical type. "
            f"Add it to CANONICAL_TYPES and write a rule for it, or map it to an existing one."
        )
    return resource


# --- shared helpers ---------------------------------------------------------
#
# Both the live AWS connector and the Terraform parser have to read IAM policy
# documents. One implementation, so "what counts as a wildcard grant" is
# decided in exactly one place.


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def wildcard_actions(document: dict) -> list[str]:
    """Actions an IAM policy document grants without restriction.

    A statement counts if it is an Allow with `Action: "*"`, or an Allow whose
    action is a service-wide wildcard (`s3:*`) on `Resource: "*"`. That is the
    CIS AWS 1.16 definition, and it deliberately does not flag the very common
    "specific actions on Resource *" shape - that is over-broad, but it is not
    full administrative privilege.
    """
    wildcards: set[str] = set()
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in _as_list(statement.get("Action"))]
        resources = [str(r) for r in _as_list(statement.get("Resource"))]
        for action in actions:
            if action == "*" or (action.endswith(":*") and "*" in resources):
                wildcards.add(action)
    return sorted(wildcards)


def open_rule_severity(open_rules: list[dict]) -> str:
    """Critical if an open rule reaches an admin port or every port; else medium."""
    for rule in open_rules:
        protocol = str(rule.get("protocol", "")).lower()
        port, to_port = rule.get("port"), rule.get("to_port", rule.get("port"))
        if protocol in ("-1", "*", "all") or port in (None, "*", "0-65535"):
            return "critical"
        try:
            low, high = int(port), int(to_port if to_port is not None else port)
        except (TypeError, ValueError):
            # Azure port ranges arrive as strings like "22" or "3389" or "1000-2000".
            text = str(port)
            if "-" in text:
                try:
                    low, high = (int(p) for p in text.split("-", 1))
                except ValueError:
                    continue
            else:
                continue
        if any(low <= admin <= high for admin in ADMIN_PORTS):
            return "critical"
    return "medium"
