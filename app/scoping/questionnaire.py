"""The six scoping questions, defined as data.

B1 renders the form from this module and B5 scores from it, so the option
values here are the contract between the two. Changing a `value` string is a
breaking change: it invalidates stored `questionnaire_response` rows and any
weight keyed on it in `policy/risk/risk-model.yaml`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Option:
    value: str
    label: str
    score: int


@dataclass(frozen=True)
class Question:
    key: str
    text: str
    options: tuple[Option, ...]


QUESTIONS: tuple[Question, ...] = (
    Question(
        key="data_classification",
        text="What is the most sensitive data this project handles?",
        options=(
            Option("public", "Public", 0),
            Option("internal", "Internal", 2),
            Option("confidential", "Confidential", 4),
            Option("regulated", "Regulated (PII / PCI / PHI)", 5),
        ),
    ),
    Question(
        key="internet_exposure",
        text="How is it reachable?",
        options=(
            Option("internal_only", "Internal only", 0),
            Option("partner_vpn", "Partner / VPN", 2),
            Option("authenticated_public", "Authenticated public", 3),
            Option("public_unauthenticated", "Public, unauthenticated", 5),
        ),
    ),
    Question(
        key="authentication",
        text="How do users and services authenticate?",
        options=(
            Option("sso_mfa", "SSO + MFA", 0),
            Option("sso_only", "SSO only", 2),
            Option("app_managed_creds", "Application-managed credentials", 3),
            Option("none_or_shared", "None / shared secret", 5),
        ),
    ),
    Question(
        key="blast_radius",
        text="What can it affect if compromised?",
        options=(
            Option("single_service", "A single service", 1),
            Option("shared_platform", "A shared platform", 3),
            Option("prod_control_plane", "Production cloud control plane / can create IAM", 5),
        ),
    ),
    Question(
        key="compliance_scope",
        text="Which regimes apply?",
        options=(
            Option("none", "None", 0),
            Option("internal_policy", "Internal policy only", 1),
            Option("soc2", "SOC 2", 2),
            Option("regulated", "PCI / HIPAA / GDPR", 5),
        ),
    ),
    Question(
        key="third_party",
        text="Third-party components with data access?",
        options=(
            Option("none", "None", 0),
            Option("vendor_no_data", "Vendor SaaS, no data access", 2),
            Option("vendor_with_data", "Vendor with data access", 4),
            Option("vendor_prod_access", "Vendor with production access", 5),
        ),
    ),
)

QUESTION_KEYS: tuple[str, ...] = tuple(q.key for q in QUESTIONS)
_BY_KEY = {q.key: q for q in QUESTIONS}


def get_question(key: str) -> Question:
    return _BY_KEY[key]


def score_for(key: str, value: str) -> int:
    """Score one answer. Raises KeyError/ValueError on anything unrecognised."""
    question = _BY_KEY[key]
    for option in question.options:
        if option.value == value:
            return option.score
    raise ValueError(f"{value!r} is not a valid answer to {key!r}")


def validate_answers(answers: dict[str, str]) -> dict[str, str]:
    """Return the six answers, or raise ValueError naming what is wrong.

    Every question is required. A partially answered questionnaire must not be
    storable, because B5 would silently score the missing ones as zero.
    """
    missing = [k for k in QUESTION_KEYS if not answers.get(k)]
    if missing:
        raise ValueError("Unanswered question(s): " + ", ".join(missing))

    unknown = [k for k in answers if k not in _BY_KEY]
    if unknown:
        raise ValueError("Unknown question key(s): " + ", ".join(unknown))

    for key in QUESTION_KEYS:
        score_for(key, answers[key])  # raises if the option value is not valid

    return {k: answers[k] for k in QUESTION_KEYS}
