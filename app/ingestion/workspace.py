"""Per-submission sandbox directories under WORKSPACE_ROOT.

The workspace has to outlive the clone: B2 fetches the code, B3 reads it, B4
scans it. So the lifetime is owned here, by a context manager the whole
pipeline wraps, rather than by a `finally` inside the clone — a clone that
deletes its own output leaves the scanners nothing to scan.

Layout:

    WORKSPACE_ROOT/<submission_id>/          0700, owned by this process
    WORKSPACE_ROOT/<submission_id>/src/      the code under review
    WORKSPACE_ROOT/<submission_id>/<upload>  the archive, if one was uploaded
"""

from __future__ import annotations

import shutil
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.config import settings

SRC_DIRNAME = "src"


def workspace_path(submission_id: int) -> Path:
    return Path(settings.workspace_root) / str(submission_id)


def source_path(submission_id: int) -> Path:
    return workspace_path(submission_id) / SRC_DIRNAME


def create(submission_id: int) -> Path:
    """Create the workspace 0700. Existing contents are cleared first."""
    path = workspace_path(submission_id)
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(stat.S_IRWXU)  # 0700 — not group- or world-readable
    return path


def destroy(submission_id: int) -> None:
    """Remove the workspace. Never raises: cleanup must not mask a real error."""
    shutil.rmtree(workspace_path(submission_id), ignore_errors=True)


def directory_size_mb(path: Path) -> float:
    total = 0
    for entry in path.rglob("*"):
        # lstat, not stat: a symlink pointing outside the sandbox must be
        # measured as a link, not followed and counted as its target.
        if entry.is_symlink():
            continue
        try:
            total += entry.lstat().st_size
        except OSError:
            continue
    return total / (1024 * 1024)


@contextmanager
def sandbox(submission_id: int, *, keep: bool = False) -> Iterator[Path]:
    """Own a workspace for the duration of one scan job.

    `keep=True` leaves it on disk for debugging a failed run. Everything
    downstream of the clone runs inside this block.
    """
    path = create(submission_id)
    try:
        yield path
    finally:
        if not keep:
            destroy(submission_id)
