"""AWS connector. Read-only: list_*, describe_*, get_* only, enforced by hook.

Credentials come from boto3's default chain (env vars, then ~/.aws/credentials,
then instance/role metadata) - the same chain the aws CLI uses, so whatever
`aws sts get-caller-identity` prints is what gets scanned. There is
deliberately no credential handling code here: a scanner that accepts a secret
as a parameter is a scanner that ends up with a secret in a config file.

Unknown is not safe. When a per-bucket read is denied, the property is set to
None and the denial is recorded in `self.errors`. It is never guessed in
either direction: guessing "private" hides a real exposure, guessing "public"
turns every missing permission into a critical finding.
"""

from __future__ import annotations

import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from app.connectors.base import ConnectorError, install_boto3_guard, safe_collect
from app.normalize import schema
from app.normalize.schema import Resource

# Retries handle throttling on large accounts; the timeouts stop a hung
# endpoint from holding the whole scan open indefinitely.
BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=15,
    read_timeout=60,
)

PUBLIC_ACL_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


class AwsConnector:
    provider = "aws"

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.session = boto3.session.Session()
        # Every API call this session makes is checked against the read-only
        # verb list before a request is built. See app/connectors/base.py.
        install_boto3_guard(self.session)
        self.errors: list[str] = []

    def _client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region or self.region, config=BOTO_CONFIG)

    def _record(self, label: str, exc: Exception) -> None:
        self.errors.append(f"{label}: {type(exc).__name__}: {exc}")

    def account_identifier(self) -> str:
        try:
            return self._client("sts").get_caller_identity()["Account"]
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"could not resolve AWS account: {exc}") from exc

    def regions(self) -> list[str]:
        """Regions actually enabled for this account, not the full static list."""
        try:
            data = self._client("ec2").describe_regions(AllRegions=False)
            return [r["RegionName"] for r in data.get("Regions", [])]
        except Exception as exc:  # noqa: BLE001
            self._record("describe_regions (falling back to the default region only)", exc)
            return [self.region]

    def collect(self) -> list[Resource]:
        account = self.account_identifier()
        resources: list[Resource] = []

        for label, fn in (
            ("s3", self._collect_s3),
            ("iam", self._collect_iam),
        ):
            items, error = safe_collect(label, fn, account)
            resources.extend(items)
            if error:
                self.errors.append(error)

        # Regional services. CloudTrail is regional too: a trail's home region
        # is wherever it was created, and describe_trails from one region does
        # not list single-region trails that live elsewhere.
        trails_seen: set[str] = set()
        for region in self.regions():
            for label, fn in (
                (f"ec2/{region}", self._collect_security_groups),
                (f"rds/{region}", self._collect_rds),
            ):
                items, error = safe_collect(label, fn, account, region)
                resources.extend(items)
                if error:
                    self.errors.append(error)

            items, error = safe_collect(f"cloudtrail/{region}", self._collect_cloudtrail, account, region)
            if error:
                self.errors.append(error)
            for trail in items:
                if trail.resource_id not in trails_seen:
                    trails_seen.add(trail.resource_id)
                    resources.append(trail)

        return [schema.validate(r) for r in resources]

    # --- S3 -----------------------------------------------------------------

    def _collect_s3(self, account: str) -> list[Resource]:
        client = self._client("s3")
        buckets = client.list_buckets().get("Buckets", [])

        # If the account-level block is fully on, no bucket in the account can
        # be public whatever its own settings say.
        account_blocked = self._account_public_access_blocked(account)

        resources = []
        for bucket in buckets:
            name = bucket["Name"]
            public = False if account_blocked else self._bucket_is_public(client, name)
            resources.append(
                Resource(
                    provider="aws",
                    account=account,
                    resource_type=schema.STORAGE_BUCKET,
                    resource_id=f"arn:aws:s3:::{name}",
                    name=name,
                    region=self._bucket_region(client, name),
                    properties={
                        "public_access": public,
                        "encrypted_at_rest": self._bucket_is_encrypted(client, name),
                        "encryption_in_transit_required": self._bucket_tls_enforced(client, name),
                    },
                    tags=self._bucket_tags(client, name),
                )
            )
        return resources

    def _account_public_access_blocked(self, account: str) -> bool:
        try:
            config = self._client("s3control").get_public_access_block(AccountId=account)[
                "PublicAccessBlockConfiguration"
            ]
            return all(config.get(k, False) for k in PAB_KEYS)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NoSuchPublicAccessBlockConfiguration":
                self._record("s3control get_public_access_block (account level)", exc)
            return False
        except Exception as exc:  # noqa: BLE001
            self._record("s3control get_public_access_block (account level)", exc)
            return False

    def _bucket_is_public(self, client, name: str) -> bool | None:
        """AWS's own definition: a public policy or a public ACL, unless the
        bucket's public access block stops it. None if that cannot be read."""
        try:
            config = client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if all(config.get(k, False) for k in PAB_KEYS):
                return False
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NoSuchPublicAccessBlockConfiguration":
                self._record(f"s3 get_public_access_block {name}", exc)
                return None
        except Exception as exc:  # noqa: BLE001
            self._record(f"s3 get_public_access_block {name}", exc)
            return None

        # No (complete) block. Public if the policy or the ACL says so.
        try:
            status = client.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
            if status.get("IsPublic"):
                return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NoSuchBucketPolicy":
                self._record(f"s3 get_bucket_policy_status {name}", exc)
                return None
        except Exception as exc:  # noqa: BLE001
            self._record(f"s3 get_bucket_policy_status {name}", exc)
            return None

        try:
            grants = client.get_bucket_acl(Bucket=name).get("Grants", [])
            return any(g.get("Grantee", {}).get("URI") in PUBLIC_ACL_GRANTEES for g in grants)
        except Exception as exc:  # noqa: BLE001
            self._record(f"s3 get_bucket_acl {name}", exc)
            return None

    def _bucket_is_encrypted(self, client, name: str) -> bool | None:
        try:
            rules = client.get_bucket_encryption(Bucket=name)
            return bool(rules.get("ServerSideEncryptionConfiguration", {}).get("Rules"))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                return False
            self._record(f"s3 get_bucket_encryption {name}", exc)
            return None
        except Exception as exc:  # noqa: BLE001
            self._record(f"s3 get_bucket_encryption {name}", exc)
            return None

    def _bucket_tls_enforced(self, client, name: str) -> bool | None:
        """True only if the bucket policy denies non-TLS requests."""
        try:
            policy = json.loads(client.get_bucket_policy(Bucket=name)["Policy"])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchBucketPolicy":
                return False  # no policy at all, so nothing denies plain HTTP
            self._record(f"s3 get_bucket_policy {name}", exc)
            return None
        except Exception as exc:  # noqa: BLE001
            self._record(f"s3 get_bucket_policy {name}", exc)
            return None
        for statement in schema._as_list(policy.get("Statement")):
            secure = statement.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
            if statement.get("Effect") == "Deny" and str(secure).lower() == "false":
                return True
        return False

    def _bucket_region(self, client, name: str) -> str | None:
        try:
            return client.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except Exception as exc:  # noqa: BLE001
            self._record(f"s3 get_bucket_location {name}", exc)
            return None

    def _bucket_tags(self, client, name: str) -> dict:
        try:
            tags = client.get_bucket_tagging(Bucket=name).get("TagSet", [])
            return {t["Key"]: t["Value"] for t in tags}
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") != "NoSuchTagSet":
                self._record(f"s3 get_bucket_tagging {name}", exc)
            return {}
        except Exception as exc:  # noqa: BLE001
            self._record(f"s3 get_bucket_tagging {name}", exc)
            return {}

    # --- EC2 security groups ------------------------------------------------

    def _collect_security_groups(self, account: str, region: str) -> list[Resource]:
        client = self._client("ec2", region)
        paginator = client.get_paginator("describe_security_groups")

        resources = []
        for page in paginator.paginate():
            for group in page.get("SecurityGroups", []):
                open_rules = []
                for rule in group.get("IpPermissions", []):
                    sources = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                    sources += [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]
                    for cidr in sources:
                        if cidr in ("0.0.0.0/0", "::/0"):
                            open_rules.append(
                                {
                                    "port": rule.get("FromPort"),
                                    "to_port": rule.get("ToPort"),
                                    "protocol": rule.get("IpProtocol"),
                                    "source": cidr,
                                }
                            )
                resources.append(
                    Resource(
                        provider="aws",
                        account=account,
                        resource_type=schema.NETWORK_SECURITY_GROUP,
                        resource_id=f"arn:aws:ec2:{region}:{account}:security-group/{group['GroupId']}",
                        name=group.get("GroupName") or group["GroupId"],
                        region=region,
                        properties={"open_ingress_rules": open_rules},
                        tags={t["Key"]: t["Value"] for t in group.get("Tags", [])},
                    )
                )
        return resources

    # --- IAM ----------------------------------------------------------------

    def _collect_iam(self, account: str) -> list[Resource]:
        client = self._client("iam")
        resources = []

        paginator = client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for policy in page.get("Policies", []):
                wildcards = self._policy_wildcards(client, policy)
                resources.append(
                    Resource(
                        provider="aws",
                        account=account,
                        resource_type=schema.IDENTITY_POLICY,
                        resource_id=policy["Arn"],
                        name=policy["PolicyName"],
                        properties={
                            "wildcard_permissions": wildcards,
                            "privileged_scope": "account" if wildcards else None,
                        },
                        tags=self._policy_tags(client, policy["Arn"]),
                    )
                )

        role_paginator = client.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page.get("Roles", []):
                trust = role.get("AssumeRolePolicyDocument") or {}
                resources.append(
                    Resource(
                        provider="aws",
                        account=account,
                        resource_type=schema.IDENTITY_ROLE,
                        resource_id=role["Arn"],
                        name=role["RoleName"],
                        properties={
                            "public_access": _role_trusts_everyone(trust),
                            "privileged_scope": "account",
                        },
                        # ListRoles does not return tags - IAM's list
                        # operations return a subset of each object's
                        # attributes, and `role.get("Tags")` here is always
                        # absent. Read them per role instead. See
                        # _role_tags for why that is worth the extra calls.
                        tags=self._role_tags(client, role["RoleName"]),
                    )
                )
        return resources

    def _role_tags(self, client, role_name: str) -> dict:
        """Tags on one IAM role, paginated.

        One extra API call per role. That is the price of attributing a role
        to a project at all: a role that trusts any principal is one of the
        four exposure rules the correlation loop acts on, so a role that
        cannot carry a project tag is an exposure that can never raise a
        divergence - and nothing anywhere would say so.
        """
        tags: dict = {}
        marker = None
        try:
            while True:
                kwargs = {"RoleName": role_name}
                if marker:
                    kwargs["Marker"] = marker
                page = client.list_role_tags(**kwargs)
                tags.update({t["Key"]: t["Value"] for t in page.get("Tags", [])})
                if not page.get("IsTruncated"):
                    break
                marker = page.get("Marker")
        except Exception as exc:  # noqa: BLE001
            self._record(f"iam list_role_tags {role_name}", exc)
        return tags

    def _policy_tags(self, client, policy_arn: str) -> dict:
        """Tags on one customer-managed policy. ListPolicies omits them too."""
        tags: dict = {}
        marker = None
        try:
            while True:
                kwargs = {"PolicyArn": policy_arn}
                if marker:
                    kwargs["Marker"] = marker
                page = client.list_policy_tags(**kwargs)
                tags.update({t["Key"]: t["Value"] for t in page.get("Tags", [])})
                if not page.get("IsTruncated"):
                    break
                marker = page.get("Marker")
        except Exception as exc:  # noqa: BLE001
            self._record(f"iam list_policy_tags {policy_arn}", exc)
        return tags

    def _policy_wildcards(self, client, policy: dict) -> list[str]:
        try:
            version = client.get_policy_version(
                PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
            )
            document = version["PolicyVersion"]["Document"]
        except Exception as exc:  # noqa: BLE001
            self._record(f"iam get_policy_version {policy.get('PolicyName')}", exc)
            return []
        return schema.wildcard_actions(document)

    # --- RDS ----------------------------------------------------------------

    def _collect_rds(self, account: str, region: str) -> list[Resource]:
        client = self._client("rds", region)
        paginator = client.get_paginator("describe_db_instances")

        resources = []
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                resources.append(
                    Resource(
                        provider="aws",
                        account=account,
                        resource_type=schema.DATABASE_INSTANCE,
                        resource_id=db["DBInstanceArn"],
                        name=db["DBInstanceIdentifier"],
                        region=region,
                        properties={
                            "public_access": bool(db.get("PubliclyAccessible")),
                            "encrypted_at_rest": bool(db.get("StorageEncrypted")),
                            "engine": db.get("Engine"),
                        },
                        tags={t["Key"]: t["Value"] for t in db.get("TagList", [])},
                    )
                )
        return resources

    # --- CloudTrail ---------------------------------------------------------

    def _collect_cloudtrail(self, account: str, region: str) -> list[Resource]:
        """Trails homed in `region`. Called per region; the caller dedups by ARN."""
        client = self._client("cloudtrail", region)
        trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])

        resources = []
        for trail in trails:
            arn = trail.get("TrailARN") or trail.get("Name", "unknown")
            # A trail can exist and be switched off. describe_trails does not
            # say; get_trail_status does, and "exists but not logging" is the
            # finding that matters.
            try:
                logging_enabled = bool(client.get_trail_status(Name=arn).get("IsLogging"))
            except Exception as exc:  # noqa: BLE001
                self._record(f"cloudtrail get_trail_status {arn}", exc)
                logging_enabled = None
            resources.append(
                Resource(
                    provider="aws",
                    account=account,
                    resource_type=schema.AUDIT_TRAIL,
                    resource_id=arn,
                    name=trail.get("Name", "unknown"),
                    region=trail.get("HomeRegion") or region,
                    properties={
                        "multi_region": bool(trail.get("IsMultiRegionTrail")),
                        "logging_enabled": logging_enabled,
                        "encrypted_at_rest": bool(trail.get("KmsKeyId")),
                    },
                    tags=self._trail_tags(client, arn),
                )
            )
        return resources


    def _trail_tags(self, client, arn: str) -> dict:
        """Tags on one trail. describe_trails does not carry them either."""
        try:
            entries = client.list_tags(ResourceIdList=[arn]).get("ResourceTagList", [])
        except Exception as exc:  # noqa: BLE001
            self._record(f"cloudtrail list_tags {arn}", exc)
            return {}
        for entry in entries:
            if entry.get("ResourceId") == arn:
                return {t["Key"]: t.get("Value", "") for t in entry.get("TagsList", [])}
        return {}


def _role_trusts_everyone(trust_policy: dict) -> bool:
    """True if the role can be assumed by any AWS principal with no condition.

    `Principal: "*"` behind a Condition (an OIDC audience, a source ARN) is the
    normal shape for federated trust and is not "everyone".
    """
    for statement in schema._as_list(trust_policy.get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict) and "*" in schema._as_list(principal.get("AWS")):
            return True
    return False
