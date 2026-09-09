"""Tags the AWS list operations do not return.

IAM's list operations return a subset of each object's attributes: neither
`ListRoles` nor `ListPolicies` includes tags, and `DescribeTrails` does not
either. The first draft of the connector read `role["Tags"]` straight off the
list response, so every role, policy and trail arrived untagged no matter what
was on it in the account — and an untagged resource is one the correlation
loop cannot see. These tests pin the per-object reads that replaced it.

Stub clients, not live calls: the point is the shape of the response handling
(pagination, the batched CloudTrail form, a denied call), which a live account
with nothing tagged cannot demonstrate.
"""

from __future__ import annotations

import pytest

from app.connectors.aws import AwsConnector


class _StubIam:
    def __init__(self, pages: list[dict]):
        self.pages = pages
        self.calls: list[dict] = []

    def list_role_tags(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages[len(self.calls) - 1]

    list_policy_tags = list_role_tags


def test_role_tags_are_read_per_role_and_paginated():
    client = _StubIam([
        {"Tags": [{"Key": "project", "Value": "Payments"}], "IsTruncated": True, "Marker": "m1"},
        {"Tags": [{"Key": "owner", "Value": "team-a"}], "IsTruncated": False},
    ])
    tags = AwsConnector._role_tags(AwsConnector.__new__(AwsConnector), client, "billing-role")
    assert tags == {"project": "Payments", "owner": "team-a"}
    assert client.calls[0] == {"RoleName": "billing-role"}
    assert client.calls[1] == {"RoleName": "billing-role", "Marker": "m1"}


def test_policy_tags_are_read_per_policy():
    client = _StubIam([{"Tags": [{"Key": "project", "Value": "Search"}], "IsTruncated": False}])
    connector = AwsConnector.__new__(AwsConnector)
    tags = AwsConnector._policy_tags(connector, client, "arn:aws:iam::1:policy/p")
    assert tags == {"project": "Search"}
    assert client.calls[0] == {"PolicyArn": "arn:aws:iam::1:policy/p"}


def test_trail_tags_pick_the_matching_arn_out_of_the_batch():
    """CloudTrail's ListTags takes a list of ARNs and answers for all of them."""
    arn = "arn:aws:cloudtrail:us-east-1:1:trail/t"

    class _StubCt:
        def list_tags(self, ResourceIdList):
            return {"ResourceTagList": [
                {"ResourceId": "arn:aws:cloudtrail:us-east-1:1:trail/other",
                 "TagsList": [{"Key": "project", "Value": "Wrong"}]},
                {"ResourceId": arn, "TagsList": [{"Key": "project", "Value": "Right"}]},
            ]}

    connector = AwsConnector.__new__(AwsConnector)
    assert AwsConnector._trail_tags(connector, _StubCt(), arn) == {"project": "Right"}


def test_a_denied_tag_read_is_recorded_not_raised():
    """A scanning identity without iam:ListRoleTags must degrade to 'this role
    has no tags I can see', recorded as a scan warning — not abort the scan."""
    class _Denied:
        def list_role_tags(self, **_kwargs):
            raise RuntimeError("AccessDenied")

    connector = AwsConnector.__new__(AwsConnector)
    connector.errors = []
    assert AwsConnector._role_tags(connector, _Denied(), "r") == {}
    assert len(connector.errors) == 1
    assert "list_role_tags" in connector.errors[0]


@pytest.mark.parametrize("operation", ["list_role_tags", "list_policy_tags", "list_tags"])
def test_the_new_calls_pass_the_read_only_guard(operation):
    from app.connectors.base import assert_read_only

    assert_read_only(operation)
