"""Settings, read once from environment/.env and shared by everything else."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    redis_url: str
    workspace_root: str = "/var/tmp/tmp-workspaces"
    artifact_root: str = "/var/tmp/tmp-artifacts"
    max_repo_mb: int = 500
    clone_timeout_sec: int = 300
    scan_timeout_sec: int = 1800
    risk_model_path: str = "policy/risk/risk-model.yaml"

    # Entra ID issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    # All three must be set for OIDC to activate; see app/auth.py.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid email profile"

    # Session cookie lifetime, seconds. Eight hours - a working day, after
    # which sign-in is required again.
    session_max_age: int = 28800
    # Set true once this runs behind TLS, so the cookie is never sent in clear.
    session_https_only: bool = False

    session_secret: str
    webhook_secret: str
    api_token: str
    git_token: str = ""


settings = Settings()
