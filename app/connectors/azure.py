"""Azure connector. Read-only: list/get only, via DefaultAzureCredential.

DefaultAzureCredential takes the first credential that is configured: the
AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_CERTIFICATE_PATH environment
variables (a service principal authenticating by certificate), then a managed
identity when deployed inside Azure, then the `az login` session. None of those
paths holds a client secret -- a certificate is proof-of-possession and is never
transmitted. That is the same posture as the platform's own infrastructure.

Two things are read straight from the ARM REST API with the same token rather
than through an SDK package: the subscription list and the subscription's
diagnostic settings. The management SDKs are split and renamed between major
versions often enough that `from azure.mgmt.resource import SubscriptionClient`
stopped working in v26, and azure-mgmt-monitor v7 dropped diagnostic settings
entirely. Two GETs against a stable API version do not have that problem.
"""

from __future__ import annotations

import httpx
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient

from app.connectors.base import ConnectorError, safe_collect
from app.normalize import schema
from app.normalize.schema import Resource

ARM = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"

# Roles that grant broad control. Owner and Contributor at subscription scope
# are the two that turn one compromised principal into a whole-subscription
# incident, so only subscription-scope assignments of these are flagged.
PRIVILEGED_ROLE_NAMES = {"Owner", "Contributor", "User Access Administrator"}

INTERNET_PREFIXES = ("*", "0.0.0.0/0", "Internet", "::/0", "0.0.0.0")


def _text(value) -> str | None:
    """SDK enums stringify as their value; None stays None. Keeps properties JSON-safe."""
    if value is None:
        return None
    return str(getattr(value, "value", value))


class AzureConnector:
    provider = "azure"

    def __init__(self, subscription_id: str | None = None):
        self.credential = DefaultAzureCredential()
        self.errors: list[str] = []
        self.subscription_id = subscription_id or self._default_subscription()

    # --- plain ARM GET, for the two things the SDKs keep moving -------------

    def _arm_get(self, path: str, api_version: str) -> dict:
        token = self.credential.get_token(ARM_SCOPE).token
        response = httpx.get(
            f"{ARM}{path}",
            params={"api-version": api_version},
            headers={"Authorization": f"Bearer {token}"},
            timeout=60,
        )
        response.raise_for_status()
        return response.json()

    def _default_subscription(self) -> str:
        try:
            for subscription in self._arm_get("/subscriptions", "2022-12-01").get("value", []):
                if subscription.get("state") == "Enabled":
                    return subscription["subscriptionId"]
            raise ConnectorError("no enabled Azure subscription found")
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"could not resolve Azure subscription: {exc}") from exc

    def account_identifier(self) -> str:
        return self.subscription_id

    def collect(self) -> list[Resource]:
        resources: list[Resource] = []
        for label, fn in (
            ("storage", self._collect_storage),
            ("network", self._collect_nsgs),
            ("sql", self._collect_sql),
            ("rbac", self._collect_role_assignments),
            ("activity-log", self._collect_activity_log_settings),
        ):
            items, error = safe_collect(label, fn)
            resources.extend(items)
            if error:
                self.errors.append(error)
        return [schema.validate(r) for r in resources]

    def _collect_storage(self) -> list[Resource]:
        client = StorageManagementClient(self.credential, self.subscription_id)
        resources = []
        for account in client.storage_accounts.list():
            resources.append(
                Resource(
                    provider="azure",
                    account=self.subscription_id,
                    resource_type=schema.STORAGE_BUCKET,
                    resource_id=account.id,
                    name=account.name,
                    region=account.location,
                    properties={
                        # allow_blob_public_access defaults to True on older
                        # accounts and None means "not set", which behaves as
                        # allowed - so only an explicit False is safe.
                        "public_access": account.allow_blob_public_access is not False,
                        "encrypted_at_rest": bool(account.encryption),
                        "encryption_in_transit_required": bool(account.enable_https_traffic_only),
                        "minimum_tls_version": _text(getattr(account, "minimum_tls_version", None)),
                        "public_network_access": _text(getattr(account, "public_network_access", None)),
                    },
                    tags=dict(account.tags or {}),
                )
            )
        return resources

    def _collect_nsgs(self) -> list[Resource]:
        client = NetworkManagementClient(self.credential, self.subscription_id)
        resources = []
        for nsg in client.network_security_groups.list_all():
            open_rules = []
            for rule in nsg.security_rules or []:
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                prefixes = list(rule.source_address_prefixes or [])
                if rule.source_address_prefix:
                    prefixes.append(rule.source_address_prefix)
                if any(p in INTERNET_PREFIXES for p in prefixes):
                    ports = list(rule.destination_port_ranges or [])
                    if rule.destination_port_range:
                        ports.append(rule.destination_port_range)
                    for port in ports or ["*"]:
                        open_rules.append(
                            {
                                "port": port,
                                "protocol": rule.protocol,
                                "source": ",".join(prefixes),
                            }
                        )
            resources.append(
                Resource(
                    provider="azure",
                    account=self.subscription_id,
                    resource_type=schema.NETWORK_SECURITY_GROUP,
                    resource_id=nsg.id,
                    name=nsg.name,
                    region=nsg.location,
                    properties={"open_ingress_rules": open_rules},
                    tags=dict(nsg.tags or {}),
                )
            )
        return resources

    def _collect_sql(self) -> list[Resource]:
        client = SqlManagementClient(self.credential, self.subscription_id)
        resources = []
        for server in client.servers.list():
            resources.append(
                Resource(
                    provider="azure",
                    account=self.subscription_id,
                    resource_type=schema.DATABASE_INSTANCE,
                    resource_id=server.id,
                    name=server.name,
                    region=server.location,
                    properties={
                        "public_access": server.public_network_access == "Enabled",
                        "encrypted_at_rest": True,  # TDE is on by default and cannot be disabled
                        "minimum_tls_version": _text(getattr(server, "minimal_tls_version", None)),
                    },
                    tags=dict(server.tags or {}),
                )
            )
        return resources

    def _collect_role_assignments(self) -> list[Resource]:
        client = AuthorizationManagementClient(self.credential, self.subscription_id)
        scope = f"/subscriptions/{self.subscription_id}"

        definitions = {}
        for definition in client.role_definitions.list(scope):
            definitions[definition.id.lower()] = definition.role_name

        resources = []
        for assignment in client.role_assignments.list_for_subscription():
            role_name = definitions.get((assignment.role_definition_id or "").lower(), "unknown")
            at_subscription_scope = (assignment.scope or "").rstrip("/").lower() == scope.lower()
            privileged = role_name in PRIVILEGED_ROLE_NAMES and at_subscription_scope
            resources.append(
                Resource(
                    provider="azure",
                    account=self.subscription_id,
                    resource_type=schema.IDENTITY_ASSIGNMENT,
                    resource_id=assignment.id,
                    name=f"{role_name} -> {assignment.principal_id}",
                    properties={
                        "role_name": role_name,
                        "principal_type": getattr(assignment, "principal_type", None),
                        "scope": assignment.scope,
                        "privileged_scope": "subscription" if at_subscription_scope else None,
                        "wildcard_permissions": [role_name] if privileged else [],
                    },
                )
            )
        return resources

    def _collect_activity_log_settings(self) -> list[Resource]:
        """The subscription Activity Log export - Azure's answer to CloudTrail.

        CIS Azure 5.1.1: a diagnostic setting must exist that ships the
        Activity Log somewhere durable. Without this collector the AWS-shaped
        "no audit trail" rule would fire on every Azure subscription, because
        nothing would ever emit an `audit.trail` resource for it.
        """
        data = self._arm_get(
            f"/subscriptions/{self.subscription_id}/providers/Microsoft.Insights/diagnosticSettings",
            "2021-05-01-preview",
        )
        resources = []
        for setting in data.get("value", []):
            props = setting.get("properties", {})
            logs = props.get("logs", [])
            enabled = any(log.get("enabled") for log in logs)
            destination = bool(
                props.get("workspaceId") or props.get("storageAccountId") or props.get("eventHubAuthorizationRuleId")
            )
            resources.append(
                Resource(
                    provider="azure",
                    account=self.subscription_id,
                    resource_type=schema.AUDIT_TRAIL,
                    resource_id=setting.get("id") or f"/subscriptions/{self.subscription_id}/diagnosticSettings/{setting.get('name')}",
                    name=setting.get("name", "unknown"),
                    properties={
                        "multi_region": True,  # the Activity Log is subscription-wide
                        "logging_enabled": enabled and destination,
                        "encrypted_at_rest": True,  # Log Analytics / Storage encrypt at rest by default
                        "categories": [log.get("category") or log.get("categoryGroup") for log in logs if log.get("enabled")],
                    },
                )
            )
        return resources
