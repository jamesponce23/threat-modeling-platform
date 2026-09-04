"""Stage 2: parse Terraform into canonical Resources.

Uses python-hcl2 for a real parse rather than regex. The scoping engine in
app/scoping/project_model.py is deliberately regex-shaped because it reads
unknown languages and must fail towards "found nothing"; this module reads one
known language and must be exact, because a rule engine acts on what it says.

Two things about Terraform that a naive parser gets wrong:

* Modern AWS provider code splits a bucket across several resources -
  `aws_s3_bucket` says almost nothing on its own; public access lives in
  `aws_s3_bucket_public_access_block` / `aws_s3_bucket_acl`, encryption in
  `aws_s3_bucket_server_side_encryption_configuration`. Security group rules
  are usually `aws_security_group_rule` or `aws_vpc_security_group_ingress_rule`
  blocks, not inline `ingress {}`. The same is true of
  `azurerm_network_security_rule`. These *companion* resources are collected
  across the whole tree and merged onto the resource they configure.
* python-hcl2 changed its output shape at v8: keys and string values arrive
  wrapped in literal double quotes (`'"aws_s3_bucket"'`) and blocks carry
  `__is_block__` markers. `_clean()` normalises both the old and new shapes
  before anything else looks at the document.

Unsupported providers and resource types are skipped rather than guessed at -
a resource this does not understand produces no finding, and that gap is
reported by the caller rather than hidden.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import hcl2

from app.normalize import schema
from app.normalize.schema import Resource

# Terraform resource type -> canonical type. Only what a rule can act on.
TERRAFORM_TYPE_MAP = {
    "aws_s3_bucket": schema.STORAGE_BUCKET,
    "aws_security_group": schema.NETWORK_SECURITY_GROUP,
    "aws_iam_policy": schema.IDENTITY_POLICY,
    "aws_iam_role": schema.IDENTITY_ROLE,
    "aws_db_instance": schema.DATABASE_INSTANCE,
    "aws_instance": schema.COMPUTE_INSTANCE,
    "aws_cloudtrail": schema.AUDIT_TRAIL,
    "azurerm_storage_account": schema.STORAGE_BUCKET,
    "azurerm_network_security_group": schema.NETWORK_SECURITY_GROUP,
    "azurerm_role_assignment": schema.IDENTITY_ASSIGNMENT,
    "azurerm_mssql_server": schema.DATABASE_INSTANCE,
    "azurerm_sql_server": schema.DATABASE_INSTANCE,
    "azurerm_linux_virtual_machine": schema.COMPUTE_INSTANCE,
    "azurerm_windows_virtual_machine": schema.COMPUTE_INSTANCE,
}

# Resources that configure another resource rather than being one. Keyed by
# the attribute that names their target.
COMPANION_TYPES = {
    "aws_s3_bucket_public_access_block": "bucket",
    "aws_s3_bucket_acl": "bucket",
    "aws_s3_bucket_server_side_encryption_configuration": "bucket",
    "aws_s3_bucket_policy": "bucket",
    "aws_security_group_rule": "security_group_id",
    "aws_vpc_security_group_ingress_rule": "security_group_id",
    "azurerm_network_security_rule": "network_security_group_name",
}

PROVIDER_BY_PREFIX = {"aws_": "aws", "azurerm_": "azure"}

META_KEYS = {"__is_block__", "__start_line__", "__end_line__"}

# `${aws_s3_bucket.logs.id}` / `aws_s3_bucket.logs.bucket` -> ("aws_s3_bucket", "logs")
REFERENCE = re.compile(r"\$?\{?\s*(aws_[a-z0-9_]+|azurerm_[a-z0-9_]+)\.([A-Za-z0-9_-]+)")


class IacParseError(RuntimeError):
    """A .tf file could not be parsed. Never silently skipped."""


# --- python-hcl2 shape normalisation ----------------------------------------


def _unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def _clean(value):
    """Strip hcl2 v8 quoting and block markers, recursively. Idempotent on v4-7 output."""
    if isinstance(value, dict):
        return {_unquote(str(k)): _clean(v) for k, v in value.items() if k not in META_KEYS}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, str):
        text = _unquote(value)
        if text.lower() in ("true", "false"):
            return text.lower() == "true"
        return text
    return value


def _first(value):
    """Older hcl2 wraps scalars in single-item lists."""
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def _blocks(body: dict, name: str) -> list[dict]:
    declared = body.get(name, [])
    declared = declared if isinstance(declared, list) else [declared]
    return [d for d in declared if isinstance(d, dict)]


# --- parsing ----------------------------------------------------------------


def _load(path: Path) -> dict:
    try:
        with path.open() as handle:
            return _clean(hcl2.load(handle))
    except Exception as exc:  # noqa: BLE001
        raise IacParseError(f"{path}: {type(exc).__name__}: {exc}") from exc


def _iter_resources(document: dict):
    """Yield (tf_type, tf_name, body) for every resource block in a document."""
    for block in document.get("resource", []):
        if not isinstance(block, dict):
            continue
        for tf_type, bodies in block.items():
            if not isinstance(bodies, dict):
                continue
            for tf_name, body in bodies.items():
                yield tf_type, tf_name, body if isinstance(body, dict) else {}


def parse_file(path: Path, account: str = "iac") -> list[Resource]:
    """Parse one .tf file on its own. Companion resources in *other* files are
    not seen - use parse_tree for a real module."""
    resources, companions = _parse(path, account)
    _apply_companions(resources, companions)
    return [schema.validate(r) for r in resources]


def parse_tree(root: Path, account: str = "iac") -> tuple[list[Resource], list[str]]:
    """Parse every .tf under `root`. Returns (resources, parse_errors)."""
    resources: list[Resource] = []
    companions: list[tuple[str, str, dict]] = []
    errors: list[str] = []
    for path in sorted(root.rglob("*.tf")):
        if any(part in {".terraform", ".git"} for part in path.parts):
            continue
        try:
            found, extra = _parse(path, account)
        except IacParseError as exc:
            errors.append(str(exc))
            continue
        resources.extend(found)
        companions.extend(extra)
    _apply_companions(resources, companions)
    return [schema.validate(r) for r in resources], errors


def _parse(path: Path, account: str) -> tuple[list[Resource], list[tuple[str, str, dict]]]:
    document = _load(path)
    resources: list[Resource] = []
    companions: list[tuple[str, str, dict]] = []

    for tf_type, tf_name, body in _iter_resources(document):
        if tf_type in COMPANION_TYPES:
            companions.append((tf_type, tf_name, body))
            continue
        canonical = TERRAFORM_TYPE_MAP.get(tf_type)
        if canonical is None:
            continue
        provider = next(
            (p for prefix, p in PROVIDER_BY_PREFIX.items() if tf_type.startswith(prefix)), "aws"
        )
        resources.append(
            Resource(
                provider=provider,
                account=account,
                resource_type=canonical,
                resource_id=f"{tf_type}.{tf_name}",
                name=tf_name,
                properties=_properties(tf_type, body),
                tags=_tags(body),
                origin=f"iac:{path}",
            )
        )
    return resources, companions


# --- properties --------------------------------------------------------------


def _properties(tf_type: str, body: dict) -> dict:
    """Map declared attributes onto canonical property keys."""
    properties: dict = {}

    if tf_type == "aws_s3_bucket":
        # `acl` inline is the pre-v4 provider shape; still honoured if present.
        properties["public_access"] = _first(body.get("acl")) in ("public-read", "public-read-write")
        # SSE-S3 has been the default on every bucket since January 2023, so a
        # declaration that says nothing about encryption is still encrypted.
        properties["encrypted_at_rest"] = True

    elif tf_type == "azurerm_storage_account":
        allow_public = _first(
            body.get("allow_nested_items_to_be_public", body.get("allow_blob_public_access", True))
        )
        properties["public_access"] = allow_public is not False
        properties["encryption_in_transit_required"] = (
            _first(body.get("https_traffic_only_enabled", body.get("enable_https_traffic_only", True))) is not False
        )
        properties["encrypted_at_rest"] = True

    elif tf_type in ("aws_security_group", "azurerm_network_security_group"):
        properties["open_ingress_rules"] = _open_rules(tf_type, body)

    elif tf_type == "aws_iam_policy":
        wildcards = _policy_wildcards(body.get("policy"))
        properties["wildcard_permissions"] = wildcards
        properties["privileged_scope"] = "account" if wildcards else None

    elif tf_type == "aws_db_instance":
        properties["public_access"] = _first(body.get("publicly_accessible", False)) is True
        properties["encrypted_at_rest"] = _first(body.get("storage_encrypted", False)) is True

    elif tf_type in ("azurerm_mssql_server", "azurerm_sql_server"):
        properties["public_access"] = _first(body.get("public_network_access_enabled", True)) is not False
        properties["encrypted_at_rest"] = True

    elif tf_type == "aws_cloudtrail":
        properties["multi_region"] = _first(body.get("is_multi_region_trail", False)) is True
        properties["logging_enabled"] = _first(body.get("enable_logging", True)) is not False

    elif tf_type == "azurerm_role_assignment":
        role = str(_first(body.get("role_definition_name", "")))
        scope = str(_first(body.get("scope", "")))
        at_subscription = bool(re.fullmatch(r"\$?\{?/?subscriptions/[^/]+/?\}?", scope)) or scope.endswith("subscription.id}") or "data.azurerm_subscription" in scope
        properties["role_name"] = role
        properties["privileged_scope"] = "subscription" if at_subscription else None
        properties["wildcard_permissions"] = [role] if role in {"Owner", "Contributor", "User Access Administrator"} and at_subscription else []

    return properties


def _policy_wildcards(policy) -> list[str]:
    """`policy = jsonencode({...})` arrives as an expression string; a
    heredoc JSON policy arrives as JSON. Parse what can be parsed, and fall
    back to matching the wildcard-action shape textually."""
    policy = _first(policy)
    if isinstance(policy, dict):
        return schema.wildcard_actions(policy)
    text = str(policy or "")
    try:
        return schema.wildcard_actions(json.loads(text))
    except (ValueError, TypeError):
        pass
    if re.search(r'"?Action"?\s*[=:]\s*\[?\s*"\*"', text):
        return ["*"]
    return []


def _open_rules(tf_type: str, body: dict) -> list[dict]:
    rules = []
    if tf_type == "aws_security_group":
        for rule in _blocks(body, "ingress"):
            rules.extend(_aws_rule(rule.get("cidr_blocks"), rule.get("ipv6_cidr_blocks"),
                                   rule.get("from_port"), rule.get("to_port"), rule.get("protocol")))
    else:
        for rule in _blocks(body, "security_rule"):
            rules.extend(_azure_rule(rule))
    return rules


def _aws_rule(cidr_blocks, ipv6_blocks, from_port, to_port, protocol) -> list[dict]:
    sources = [str(b) for b in (cidr_blocks or [])] + [str(b) for b in (ipv6_blocks or [])]
    return [
        {"port": _first(from_port), "to_port": _first(to_port), "protocol": _first(protocol), "source": source}
        for source in sources
        if source in ("0.0.0.0/0", "::/0")
    ]


def _azure_rule(rule: dict) -> list[dict]:
    if str(_first(rule.get("direction", "Inbound"))) != "Inbound" or str(_first(rule.get("access", "Allow"))) != "Allow":
        return []
    prefixes = [str(_first(rule.get("source_address_prefix", "")))] + [str(p) for p in (rule.get("source_address_prefixes") or [])]
    if not any(p in ("*", "Internet", "0.0.0.0/0", "::/0") for p in prefixes):
        return []
    ports = [str(p) for p in (rule.get("destination_port_ranges") or [])]
    if rule.get("destination_port_range") is not None:
        ports.append(str(_first(rule.get("destination_port_range"))))
    return [
        {"port": port, "protocol": _first(rule.get("protocol")), "source": ",".join(p for p in prefixes if p)}
        for port in (ports or ["*"])
    ]


# --- companions --------------------------------------------------------------


def _target(tf_type: str, body: dict) -> str | None:
    """Resolve a companion's target to a `tf_type.tf_name` resource id."""
    value = str(_first(body.get(COMPANION_TYPES[tf_type], "")) or "")
    match = REFERENCE.search(value)
    if match:
        return f"{match.group(1)}.{match.group(2)}"
    return None


def _apply_companions(resources: list[Resource], companions: list[tuple[str, str, dict]]) -> None:
    by_id = {r.resource_id: r for r in resources}
    for tf_type, _tf_name, body in companions:
        target = _target(tf_type, body)
        resource = by_id.get(target) if target else None
        if resource is None:
            # Azure NSG rules reference the group by *name*, not by address.
            if tf_type == "azurerm_network_security_rule":
                wanted = str(_first(body.get("network_security_group_name", "")))
                resource = next(
                    (r for r in resources if r.resource_type == schema.NETWORK_SECURITY_GROUP
                     and r.provider == "azure" and (r.name == wanted or r.resource_id == _target(tf_type, body))),
                    None,
                )
            if resource is None:
                continue
        props = resource.properties

        if tf_type == "aws_s3_bucket_public_access_block":
            blocked = all(
                _first(body.get(k, False)) is True
                for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
            )
            if blocked:
                props["public_access"] = False
            props["public_access_block"] = blocked

        elif tf_type == "aws_s3_bucket_acl":
            if _first(body.get("acl")) in ("public-read", "public-read-write") and props.get("public_access_block") is not True:
                props["public_access"] = True

        elif tf_type == "aws_s3_bucket_server_side_encryption_configuration":
            props["encrypted_at_rest"] = True

        elif tf_type == "aws_s3_bucket_policy":
            text = str(_first(body.get("policy", "")))
            props["encryption_in_transit_required"] = "aws:SecureTransport" in text
            if '"Principal": "*"' in text.replace(" ", "").replace('"Principal":"*"', '"Principal": "*"') and props.get("public_access_block") is not True:
                props["public_access"] = True

        elif tf_type == "aws_security_group_rule":
            if str(_first(body.get("type", "ingress"))) == "ingress":
                props.setdefault("open_ingress_rules", []).extend(
                    _aws_rule(body.get("cidr_blocks"), body.get("ipv6_cidr_blocks"),
                              body.get("from_port"), body.get("to_port"), body.get("protocol"))
                )

        elif tf_type == "aws_vpc_security_group_ingress_rule":
            cidr4, cidr6 = _first(body.get("cidr_ipv4")), _first(body.get("cidr_ipv6"))
            props.setdefault("open_ingress_rules", []).extend(
                _aws_rule([cidr4] if cidr4 else None, [cidr6] if cidr6 else None,
                          body.get("from_port"), body.get("to_port"), body.get("ip_protocol"))
            )

        elif tf_type == "azurerm_network_security_rule":
            props.setdefault("open_ingress_rules", []).extend(_azure_rule(body))


def _tags(body: dict) -> dict:
    tags = _first(body.get("tags", {}))
    return {str(k): str(v) for k, v in tags.items()} if isinstance(tags, dict) else {}
