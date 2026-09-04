"""One canonical spelling for a repository URL.

The same repository arrives in several forms: pasted from a browser address bar
(`https://github.com/you/repo`), from a Git remote (`.../repo.git`), from a
GitHub push payload's `clone_url` (also `.git`), or as SSH
(`git@github.com:you/repo.git`). Matching those as raw strings means a webhook
silently reports "not a registered project" for a repo that plainly is one —
and silently is the dangerous part: nothing errors, scans just never happen.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

SSH_PREFIXES = ("git@", "ssh://git@")


def normalize_repo_url(url: str | None) -> str | None:
    """Reduce a repository URL to the form stored in `project.repo_url`."""
    if not url:
        return None

    raw = url.strip()
    if not raw:
        return None

    # git@host:owner/repo -> https://host/owner/repo
    if raw.startswith("git@") and ":" in raw:
        host, _, path = raw[len("git@") :].partition(":")
        raw = f"https://{host}/{path}"
    elif raw.startswith("ssh://git@"):
        raw = "https://" + raw[len("ssh://git@") :]

    parts = urlsplit(raw if "://" in raw else f"https://{raw}")
    path = parts.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]

    # Host is case-insensitive; the path is not, so it is left alone.
    return urlunsplit((parts.scheme.lower() or "https", parts.netloc.lower(), path, "", ""))
