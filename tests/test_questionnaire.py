"""The six scoping questions — Track B's inherent-risk input.

Every weight the classifier applies comes from here, so an answer the
questionnaire accepts but cannot score would silently under-rate a project.
"""

from __future__ import annotations

import pytest

from app.scoping import questionnaire

COMPLETE = {
    "data_classification": "public",
    "internet_exposure": "internal_only",
    "authentication": "sso_mfa",
    "blast_radius": "single_service",
    "compliance_scope": "none",
    "third_party": "none",
}


def test_a_complete_answer_set_validates():
    assert questionnaire.validate_answers(dict(COMPLETE)) == COMPLETE


def test_a_missing_answer_is_rejected():
    """A partial questionnaire must not produce a score — a missing high-risk
    answer would read as a low-risk one."""
    partial = dict(COMPLETE)
    partial.pop("blast_radius")
    with pytest.raises(Exception):
        questionnaire.validate_answers(partial)


def test_an_unknown_option_is_rejected():
    bad = dict(COMPLETE, data_classification="top_secret_probably")
    with pytest.raises(Exception):
        questionnaire.validate_answers(bad)


def test_an_unknown_question_key_is_rejected():
    with pytest.raises(Exception):
        questionnaire.validate_answers(dict(COMPLETE, invented_question="yes"))


def test_every_declared_option_is_scoreable():
    """The guard against the quiet failure: an option offered by the form that
    the scorer does not recognise."""
    for question in questionnaire.QUESTIONS:
        for option in question.options:
            assert isinstance(questionnaire.score_for(question.key, option.value), int)


def test_there_are_six_questions_with_unique_keys():
    keys = [q.key for q in questionnaire.QUESTIONS]
    assert len(keys) == 6
    assert len(set(keys)) == 6


def test_riskier_answers_never_score_lower():
    """Options are declared worst-to-best or best-to-worst per question; what
    must hold is that the spread is real — a question where every option scores
    the same contributes nothing and is a bug."""
    for question in questionnaire.QUESTIONS:
        scores = {questionnaire.score_for(question.key, o.value) for o in question.options}
        assert len(scores) > 1, f"{question.key} cannot discriminate"
