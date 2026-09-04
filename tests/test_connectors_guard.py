"""The read-only guarantee, tested as a unit.

Regression cover for a defect that made the least-privilege role unusable:
botocore issues `sts:AssumeRole` through the same event system the guard is
registered on, so a guard that refuses every non-read verb also refuses the
credential handshake the read-only profile depends on.
"""

from __future__ import annotations

import pytest

from app.connectors.base import ConnectorError, assert_read_only


@pytest.mark.parametrize("operation", [
    "ListBuckets", "DescribeInstances", "GetBucketPolicy", "HeadObject",
    "list_buckets", "describe_instances", "get_caller_identity",
])
def test_reads_are_allowed(operation):
    assert_read_only(operation)


@pytest.mark.parametrize("operation", [
    "AssumeRole", "assume_role",
    "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML",
])
def test_credential_issuance_is_allowed(operation):
    """Not a read, but it mutates nothing and the role profile requires it."""
    assert_read_only(operation)


@pytest.mark.parametrize("operation", [
    "DeleteBucket", "PutBucketPolicy", "CreateRole", "UpdateStack",
    "TerminateInstances", "delete_bucket", "put_bucket_tagging",
])
def test_writes_are_refused(operation):
    with pytest.raises(ConnectorError):
        assert_read_only(operation)


def test_auth_allowlist_is_exact_not_a_prefix():
    """`assume*` as a prefix rule would admit anything starting with it.

    The allowlist names three operations; a fourth that merely begins the same
    way must still be refused.
    """
    with pytest.raises(ConnectorError):
        assert_read_only("AssumeRoleAndDeleteEverything")


def test_refusal_names_the_operation():
    """The message has to say what was blocked, or the failure is unreadable
    when it surfaces from inside botocore's credential resolution."""
    with pytest.raises(ConnectorError, match="DeleteBucket"):
        assert_read_only("DeleteBucket")
