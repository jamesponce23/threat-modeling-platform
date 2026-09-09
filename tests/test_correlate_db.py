"""The half of the correlation loop that needs the project registry.

`attribute()` can be tested with no database; deciding whether a tag names a
real project, and whether that project's Track B rating contradicts what is
deployed, cannot. These run against the local dev Postgres and skip when it is
not up, so `python3 -m pytest` still passes on a machine with no containers.

Nothing is committed: every row is inserted, flushed so the queries can see
it, and rolled back at the end of the test.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import OperationalError

from app.analysis.rules import evidence_for
from app.findings import store
from app.models import Project, RiskAssessment, Submission
from app.normalize import schema
from app.normalize.schema import Resource
from app.scanners.base import Finding


@pytest.fixture()
def db():
    from app.db import SessionLocal

    session = SessionLocal()
    try:
        session.execute(__import__("sqlalchemy").text("select 1"))
    except OperationalError:
        session.close()
        pytest.skip("dev Postgres is not running (docker compose up -d)")
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _register(db, name: str, tier: str = "MEDIUM") -> Project:
    """A project with one completed submission and one rating."""
    project = Project(name=name, owner_email="test@example.invalid")
    db.add(project)
    db.flush()
    submission = Submission(project_id=project.id, status="complete", source_type="git")
    db.add(submission)
    db.flush()
    db.add(RiskAssessment(
        submission_id=submission.id, tier=tier,
        inherent_score=20, technical_score=27, total_score=47,
        model_version="1.0.0", drivers=[], overrides_fired=[],
    ))
    db.flush()
    return project


def _sg(tag_value: str) -> Resource:
    return Resource(
        provider="aws", account="000000000000",
        resource_type=schema.NETWORK_SECURITY_GROUP,
        resource_id=f"arn:aws:ec2:us-east-2:000000000000:security-group/{_unique('sg')}",
        name="launch-wizard-2", tags={"project": tag_value},
    )


def _exposure(resource: Resource) -> Finding:
    return Finding(
        scanner="estate", rule_id="estate.network.open_ingress", severity="critical",
        title="open to the internet", evidence=evidence_for(resource), stride="S",
    )


def test_a_slug_tag_matches_a_display_named_project(db):
    """The regression this whole change exists for: a resource tagged
    `project=payments-api` against a project registered as "Payments API".
    Before normalisation this produced no attribution, no divergence, and no
    message saying anything had failed to match."""
    name = _unique("Payments API").replace("-", " ", 0)
    project = _register(db, name)
    slug = name.lower().replace(" ", "-")

    resource = _sg(slug)
    summary = store.attribution_summary(db, [resource])
    assert summary["attributed"] == {slug: 1}
    assert summary["unknown_project_tags"] == {}

    divergences = store.correlate(db, [resource], [_exposure(resource)])
    assert len(divergences) == 1
    assert divergences[0]["project"] == project.name      # the registry spelling
    assert divergences[0]["project_tag"] == slug          # what is on the resource
    assert divergences[0]["rated_tier"] == "MEDIUM"
    assert divergences[0]["exposed_count"] == 1


def test_a_tag_naming_no_project_is_reported_as_unknown(db):
    resource = _sg(_unique("ghost"))
    summary = store.attribution_summary(db, [resource])
    assert summary["attributed"] == {}
    assert list(summary["unknown_project_tags"]) == [resource.tags["project"]]
    assert store.correlate(db, [resource], [_exposure(resource)]) == []


def test_two_projects_that_a_tag_cannot_tell_apart_match_neither(db):
    """Two registry names that normalise the same are indistinguishable to a
    tag. Attributing to whichever row was created first would hang one team's
    exposure on another team's rating, so neither is matched and the report
    names the tag as contested."""
    base = _unique("Contested")
    _register(db, base)
    _register(db, base.replace("-", " "))

    resource = _sg(base)
    summary = store.attribution_summary(db, [resource])
    assert summary["attributed"] == {}
    assert list(summary["ambiguous_project_tags"]) == [base]
    assert store.correlate(db, [resource], [_exposure(resource)]) == []


def test_a_high_rated_project_is_not_a_divergence(db):
    """The finding is a reassuring rating contradicted by deployment. A HIGH
    rating already said the project was risky."""
    name = _unique("Loud")
    _register(db, name, tier="HIGH")
    resource = _sg(name)
    assert store.correlate(db, [resource], [_exposure(resource)]) == []


def test_a_non_exposure_finding_does_not_diverge(db):
    """An unencrypted bucket is a real finding, but it is not the internet
    being able to reach the resource."""
    name = _unique("Quiet")
    _register(db, name)
    resource = _sg(name)
    not_exposure = Finding(
        scanner="estate", rule_id="estate.storage.unencrypted", severity="high",
        title="unencrypted", evidence=evidence_for(resource), stride="I",
    )
    assert store.correlate(db, [resource], [not_exposure]) == []
