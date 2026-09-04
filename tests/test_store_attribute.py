"""Attribution — the half of the correlation loop that needs no database.

`attribute()` decides which live resources can be tied back to a Track B
project. Everything the correlation report says about coverage rests on it.
"""

from __future__ import annotations

from app.findings import store
from app.normalize import schema
from app.normalize.schema import Resource


def _bucket(name: str, tags: dict | None = None) -> Resource:
    return Resource(provider="aws", account="000000000000",
                    resource_type=schema.STORAGE_BUCKET,
                    resource_id=f"arn:aws:s3:::{name}", name=name,
                    tags=tags or {})


def test_tagged_resources_group_under_their_project():
    by_project, untagged = store.attribute([
        _bucket("a", {"project": "Payments"}),
        _bucket("b", {"project": "Payments"}),
        _bucket("c", {"project": "Search"}),
    ])
    assert {k: len(v) for k, v in by_project.items()} == {"Payments": 2, "Search": 1}
    assert untagged == []


def test_untagged_resources_are_returned_separately_not_discarded():
    """An untagged estate is the normal starting state. The report has to be
    able to say how much of the estate the loop cannot see."""
    by_project, untagged = store.attribute([_bucket("a"), _bucket("b")])
    assert by_project == {}
    assert len(untagged) == 2


def test_tag_whitespace_does_not_split_a_project():
    """The join is an exact match on `project.name`, so a console-entered tag
    with stray spaces would otherwise create a phantom second project."""
    by_project, _ = store.attribute([
        _bucket("a", {"project": "Payments"}),
        _bucket("b", {"project": " Payments "}),
    ])
    assert list(by_project) == ["Payments"]
    assert len(by_project["Payments"]) == 2


def test_a_tag_naming_no_known_project_still_groups():
    """attribute() does not consult the database — deciding whether a tag names
    a real project is attribution_summary's job. This keeps the split pure."""
    by_project, untagged = store.attribute([_bucket("a", {"project": "Ghost"})])
    assert list(by_project) == ["Ghost"]
    assert untagged == []


def test_exposure_rules_are_a_deliberate_subset():
    """Only rules that mean 'the internet can reach this' trigger a divergence.
    An unencrypted or non-TLS bucket is a real finding but not an exposure, and
    must not raise a divergence against a LOW-rated project."""
    assert "estate.storage.public_access" in store.EXPOSURE_RULES
    assert "estate.network.open_ingress" in store.EXPOSURE_RULES
    assert "estate.storage.tls_not_enforced" not in store.EXPOSURE_RULES
    assert "estate.storage.unencrypted" not in store.EXPOSURE_RULES


def test_only_reassuring_tiers_can_diverge():
    """A HIGH-rated project with an exposed resource is not a divergence — the
    rating already said so. The finding is a LOW/MEDIUM rating contradicted by
    what is actually deployed."""
    assert set(store.LOW_RISK_TIERS) == {"LOW", "MEDIUM"}
    assert "HIGH" not in store.LOW_RISK_TIERS
