"""Access control.

Two gates, for two kinds of caller:

* **Browser routes** are gated on a signed session cookie. When an OIDC issuer
  is configured the cookie is only ever established by a completed
  authorisation-code flow against that issuer; the local sign-in form is
  switched off entirely, so there is no second way in.
* **The JSON API** is gated on a bearer token, because CI has no browser and no
  session.

The local form exists only for a machine with no IdP configured. It verifies
nothing — it accepts any address — so it is a development convenience and says
so on the page. Configuring `OIDC_ISSUER`, `OIDC_CLIENT_ID` and
`OIDC_CLIENT_SECRET` disables it in the same act as enabling real sign-in,
which is deliberate: there is no state in which both are available.

The cookie is signed by Starlette's SessionMiddleware using SESSION_SECRET -
see app/main.py. Without that middleware installed, request.session does not
exist and neither gate can work.
"""

from __future__ import annotations

import hmac
import logging

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import settings
from app.templating import templates

log = logging.getLogger(__name__)
router = APIRouter()


def oidc_enabled() -> bool:
    """All three settings, or none. A half-configured IdP must not silently
    fall back to the local form — that would be a bypass that appears only
    when configuration is broken."""
    return bool(settings.oidc_issuer and settings.oidc_client_id and settings.oidc_client_secret)


oauth = OAuth()
if oidc_enabled():
    oauth.register(
        name="idp",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        # Authlib fetches the issuer's own metadata, so endpoint URLs, signing
        # keys and supported algorithms are never hardcoded here and rotate
        # with the provider.
        server_metadata_url=f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration",
        client_kwargs={"scope": settings.oidc_scopes},
    )
else:
    log.warning(
        "OIDC is not configured - the local sign-in form is active and verifies "
        "nothing. Set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET before "
        "exposing this service to anything but localhost."
    )


# --- gates ------------------------------------------------------------------

def require_user(request: Request) -> str:
    """Browser gate. Sends anonymous callers to the sign-in page."""
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="sign-in required",
            headers={"Location": "/login"},
        )
    return user


def require_api_client(request: Request) -> str:
    """JSON API gate, for CI. Expects `Authorization: Bearer <API_TOKEN>`."""
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, settings.api_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "ci"


# --- sign-in ----------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """With an IdP configured this is a redirect, not a page."""
    if oidc_enabled():
        return await oauth.idp.authorize_redirect(
            request, str(request.url_for("auth_callback"))
        )
    return templates.TemplateResponse(
        request, "login.html", {"error": None, "oidc": False}
    )


@router.get("/auth/callback", name="auth_callback")
async def auth_callback(request: Request):
    """The IdP's redirect back. Authlib validates the state parameter, the id
    token's signature, issuer, audience and nonce before this returns."""
    if not oidc_enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC is not configured")
    try:
        token = await oauth.idp.authorize_access_token(request)
    except OAuthError as exc:
        log.warning("OIDC callback rejected: %s", exc.error)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Sign-in failed or was cancelled. Please try again.", "oidc": True},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    claims = token.get("userinfo") or {}
    # Entra ID puts the address in `preferred_username`; `email` is only present
    # when the account has a verified one. Falling back to `sub` guarantees a
    # stable identifier rather than an empty session.
    user = claims.get("email") or claims.get("preferred_username") or claims.get("sub")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no identity in token")

    # Drop any pre-login session state before adopting the new identity, so a
    # session fixed by an attacker before sign-in cannot survive it.
    request.session.clear()
    request.session["user"] = user
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/login")
def local_login(request: Request, email: str = Form(...)):
    """Development sign-in. Refuses to exist once an IdP is configured."""
    if oidc_enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="use the identity provider")
    email = email.strip()
    if "@" not in email:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Enter an email address.", "oidc": False},
            status_code=400,
        )
    request.session.clear()
    request.session["user"] = email
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
