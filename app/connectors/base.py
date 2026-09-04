"""Connector interface, plus the read-only guarantee.

A scanner holding credentials to a production cloud account is a liability if
it can write. Rather than trusting that nobody adds a mutating call later,
`assert_read_only` checks the verb of an API operation name, and the AWS
connector registers it as a boto3 `before-call` hook - so it runs on EVERY
boto3 call the connector makes, not only the ones somebody remembered to wrap.
A `delete_bucket` slipped into a connector fails before the request is built.

The one exception is credential issuance: `AssumeRole` is not a read, but it
writes nothing and botocore calls it internally whenever the active profile
assumes a role. See AUTH_OPERATIONS below.

The Azure SDK has no equivalent hook. Its connector only ever calls `list`
and `get` methods, and that is enforced by review rather than at runtime.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.normalize.schema import Resource

# Every AWS/Azure call this platform is allowed to make starts with one of
# these. Anything else is a write, and a write is a bug.
READ_ONLY_PREFIXES = (
    "list", "describe", "get", "head", "check", "lookup", "batch_get", "query", "select",
)

# Credential-issuing STS operations. These are not reads, but they mutate
# nothing in the account - they exchange one identity for a scoped, temporary
# one, bounded by the role's trust policy and its attached permissions.
# botocore calls AssumeRole internally, through this same event system,
# whenever the active profile has a `role_arn` - which is exactly what the
# read-only `estate-readonly` profile has. Blocking it makes the least-
# privilege role impossible to use, so the guard would force the connector
# to run under broader credentials. Allowing it is the safer choice.
AUTH_OPERATIONS = frozenset({
    "assumerole",
    "assumerolewithwebidentity",
    "assumerolewithsaml",
})


class ConnectorError(RuntimeError):
    """The cloud API could not be read. Distinct from 'the account is empty'."""


def assert_read_only(operation: str) -> None:
    """Raise unless `operation` is a read.

    Accepts either boto3's snake_case method names (`get_bucket_policy`) or
    the PascalCase operation names the before-call hook sees (`GetBucketPolicy`).
    """
    verb = operation.lower().lstrip("_")
    if verb.replace("_", "") in AUTH_OPERATIONS:
        return
    if not verb.startswith(READ_ONLY_PREFIXES):
        raise ConnectorError(
            f"refusing to call {operation!r}: Track A connectors are read-only. "
            f"If this is genuinely a read, add its prefix to READ_ONLY_PREFIXES."
        )


def install_boto3_guard(session) -> None:
    """Make every call on `session` pass through assert_read_only."""

    def _guard(model, **_kwargs):
        assert_read_only(model.name)

    session.events.register("before-call.*.*", _guard, unique_id="track-a-read-only")


@runtime_checkable
class Connector(Protocol):
    provider: str
    errors: list[str]

    def account_identifier(self) -> str: ...

    def collect(self) -> list[Resource]: ...


def safe_collect(label: str, fn, *args, **kwargs):
    """Run one collection step. A permission error on one service must not
    abandon the whole scan - a Reader role missing SQL access should still
    yield storage and network results, with the gap recorded.

    Returns (items, error). Never raises.
    """
    try:
        return fn(*args, **kwargs), None
    except Exception as exc:  # noqa: BLE001 - deliberately broad, always recorded
        return [], f"{label}: {type(exc).__name__}: {exc}"
