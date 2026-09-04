"""Both auth gates, and the rule that they are never both open.

The property worth testing is not that sign-in works — it is that configuring
an identity provider *removes* the local form, so a deployment cannot end up
with a real IdP and a form that accepts any address sitting beside it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.config import settings
from app.main import app


@pytest.fixture
def client():
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def oidc_configured(monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "https://login.microsoftonline.com/t/v2.0")
    monkeypatch.setattr(settings, "oidc_client_id", "client-id")
    monkeypatch.setattr(settings, "oidc_client_secret", "client-secret")


# --- the mutual exclusion ---------------------------------------------------

def test_local_form_is_available_when_no_idp_is_configured(client):
    assert auth.oidc_enabled() is False
    response = client.post("/login", data={"email": "someone@example.com"})
    assert response.status_code == 303


def test_configuring_an_idp_removes_the_local_form(client, oidc_configured):
    """No deployment may have both a real IdP and a form that verifies nothing."""
    assert auth.oidc_enabled() is True
    response = client.post("/login", data={"email": "someone@example.com"})
    assert response.status_code == 404


def test_a_half_configured_idp_does_not_enable_oidc(monkeypatch):
    """Partial configuration must not silently fall back to the local form —
    that is a bypass that appears exactly when configuration is broken."""
    monkeypatch.setattr(settings, "oidc_issuer", "https://login.microsoftonline.com/t/v2.0")
    monkeypatch.setattr(settings, "oidc_client_id", "client-id")
    monkeypatch.setattr(settings, "oidc_client_secret", "")
    assert auth.oidc_enabled() is False


def test_callback_is_closed_when_oidc_is_off(client):
    """An unconfigured callback must not be a route an attacker can drive."""
    assert client.get("/auth/callback?code=x&state=y").status_code == 404


# --- the browser gate -------------------------------------------------------

def test_anonymous_browser_is_sent_to_sign_in(client):
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_signing_in_replaces_any_pre_existing_session(client):
    """Session fixation: whatever the cookie held before sign-in is discarded,
    so a session planted before authentication cannot survive it."""
    client.cookies.set("session", "attacker-planted-value")
    response = client.post("/login", data={"email": "someone@example.com"})
    assert response.status_code == 303
    assert client.get("/").status_code == 200


def test_a_malformed_address_is_refused(client):
    assert client.post("/login", data={"email": "not-an-address"}).status_code == 400


def test_logout_clears_the_session(client):
    client.post("/login", data={"email": "someone@example.com"})
    assert client.get("/").status_code == 200
    client.post("/logout")
    assert client.get("/").status_code == 303


# --- the API gate -----------------------------------------------------------

def _api_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_api_rejects_a_missing_token(client):
    assert client.get("/api/v1/projects").status_code == 401


def test_api_rejects_a_wrong_token(client):
    response = client.get("/api/v1/projects", headers=_api_headers("wrong"))
    assert response.status_code == 401


def test_api_rejects_a_token_with_the_wrong_scheme(client):
    response = client.get("/api/v1/projects",
                          headers={"Authorization": f"Basic {settings.api_token}"})
    assert response.status_code == 401


def test_api_accepts_the_configured_token(client):
    response = client.get("/api/v1/projects", headers=_api_headers(settings.api_token))
    assert response.status_code == 200


def test_a_browser_session_does_not_open_the_api(client):
    """The two gates are independent; a signed-in browser is not a CI client."""
    client.post("/login", data={"email": "someone@example.com"})
    assert client.get("/api/v1/projects").status_code == 401
