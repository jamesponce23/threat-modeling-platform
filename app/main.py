"""FastAPI application: mounts middleware, static files and the B1 routers."""

from __future__ import annotations

from fastapi.exception_handlers import http_exception_handler
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.routes import estate, projects, reports, webhooks
from app.templating import templates
from app import auth

app = FastAPI(title="Threat Model & Project Risk Platform")

# Signs the session cookie both auth gates read. Without this, request.session
# does not exist. `same_site="lax"` lets the cookie survive the IdP's redirect
# back to /auth/callback while still refusing it on cross-site POSTs; "strict"
# would drop the session mid sign-in. Set SESSION_HTTPS_ONLY=true behind TLS.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    max_age=settings.session_max_age,
    same_site="lax",
    https_only=settings.session_https_only,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(webhooks.router)
app.include_router(reports.router)
app.include_router(estate.router)

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

ERROR_HEADINGS = {
    401: "Not authorised",
    403: "Forbidden",
    404: "No such page",
    405: "Method not allowed",
    409: "Conflict",
}


@app.exception_handler(StarletteHTTPException)
async def friendly_http_exception(request: Request, exc: StarletteHTTPException) -> Response:
    """Send browsers somewhere useful; leave the JSON API answering in JSON.

    Two problems this solves. A redirect raised as an HTTPException would
    otherwise be delivered as a JSON error body that happens to carry a
    Location header, which is not what a redirect is. And a browser hitting an
    unknown URL would get a bare `{"detail":"Not Found"}` with no way back —
    easy to misread as the whole application being broken.
    """
    location = (exc.headers or {}).get("Location")
    if location and exc.status_code in REDIRECT_STATUSES:
        return RedirectResponse(location, status_code=exc.status_code)

    wants_html = "text/html" in request.headers.get("accept", "")
    if wants_html and not request.url.path.startswith(("/api/", "/webhooks/")):
        return templates.TemplateResponse(
            request,
            "error.html",
            {
                "status": exc.status_code,
                "heading": ERROR_HEADINGS.get(exc.status_code, "Something went wrong"),
                "detail": exc.detail,
                "user": request.session.get("user") if "session" in request.scope else None,
            },
            status_code=exc.status_code,
        )

    return await http_exception_handler(request, exc)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}
