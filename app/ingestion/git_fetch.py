"""Clone a submitted repository into its sandbox.

This is the first point where the platform handles code it does not control,
so the clone is deliberately hostile-input-shaped: shallow, single branch, no
submodules, no hooks, no credential prompts, on a timeout, with a size cap.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from app.config import settings
from app.ingestion import workspace


class CloneError(RuntimeError):
    """Raised when a repository cannot be fetched safely. Caller marks failed."""


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            # Never block waiting for a username/password on a private or
            # mistyped URL — fail instead of hanging until the timeout.
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
            # Ignore /etc/gitconfig and ~/.gitconfig so a setting on this
            # machine cannot change how untrusted repositories are fetched.
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
    )
    if settings.git_token:
        env["GIT_TOKEN"] = settings.git_token
    return env


def _git_hardening_flags() -> list[str]:
    return [
        # A repository can ship hooks. Cloning must never execute them.
        "-c", "core.hooksPath=/dev/null",
        # No credential helper: nothing on this machine gets consulted, and no
        # local credential can be leaked to a URL someone else supplied.
        "-c", "credential.helper=",
        # git:// and ext:: can run arbitrary commands. Allow only http(s).
        "-c", "protocol.ext.allow=never",
        "-c", "protocol.git.allow=never",
    ]


def clone(repo_url: str, ref: str | None, submission_id: int) -> str:
    """Shallow-clone `repo_url` at `ref`. Returns the resolved commit SHA.

    The SHA matters: a rating describes one state of a repository, and `main`
    means something different tomorrow. Pinning it is what makes the result
    reproducible and auditable.
    """
    destination = workspace.source_path(submission_id)

    command = ["git", *_git_hardening_flags(), "clone",
               "--depth", "1",
               "--single-branch",
               "--no-tags",
               # Submodules are separate repositories under someone else's
               # control. They are never fetched.
               "--recurse-submodules=no"]
    if ref:
        command += ["--branch", ref]
    command += ["--", repo_url, str(destination)]

    try:
        result = subprocess.run(
            command,
            env=_git_env(),
            capture_output=True,
            text=True,
            timeout=settings.clone_timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run kills the child on timeout, so nothing is left running.
        raise CloneError(
            f"clone exceeded CLONE_TIMEOUT_SEC ({settings.clone_timeout_sec}s)"
        ) from exc

    if result.returncode != 0:
        # git writes diagnostics to stderr; the last line is the useful one.
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise CloneError(detail[-1] if detail else f"git clone exited {result.returncode}")

    # Size is checked after the fact: a shallow clone gives no reliable
    # advance figure, and --filter is not supported by every host.
    size_mb = workspace.directory_size_mb(destination)
    if size_mb > settings.max_repo_mb:
        raise CloneError(
            f"repository is {size_mb:.0f} MB, over MAX_REPO_MB ({settings.max_repo_mb})"
        )

    return resolve_head(destination)


def resolve_head(source: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        env=_git_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise CloneError("could not resolve HEAD after clone")
    return result.stdout.strip()
