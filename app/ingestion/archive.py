"""Unpack an uploaded zip/tar into the sandbox.

Archives are the other untrusted input. Two classic attacks apply and both are
checked before a single byte is written:

* **Zip-slip** — a member named `../../etc/cron.d/x` or `/etc/passwd` escapes
  the extraction directory. Python's `extractall` historically did this
  happily. Member names are validated here rather than trusted.
* **Zip bomb** — a few KB that expand to gigabytes. The declared uncompressed
  size is summed first, and the running total is checked again while writing,
  because the declared size is attacker-controlled too.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from app.config import settings
from app.ingestion import workspace


class ArchiveError(RuntimeError):
    """Raised when an archive is malformed or hostile. Caller marks failed."""


def _reject_unsafe_name(name: str) -> None:
    path = Path(name)
    if path.is_absolute() or name.startswith("/") or name.startswith("\\"):
        raise ArchiveError(f"archive member has an absolute path: {name!r}")
    if ".." in path.parts:
        raise ArchiveError(f"archive member escapes the sandbox: {name!r}")
    if ":" in name.split("/")[0] and len(name.split("/")[0]) == 2:
        raise ArchiveError(f"archive member has a drive letter: {name!r}")


def _check_total(total_bytes: int) -> None:
    cap = settings.max_repo_mb * 1024 * 1024
    if total_bytes > cap:
        raise ArchiveError(
            f"archive expands to more than MAX_REPO_MB ({settings.max_repo_mb} MB)"
        )


def unpack(archive_path: Path, submission_id: int) -> Path:
    """Extract `archive_path` into the submission's `src/`. Returns that path."""
    destination = workspace.source_path(submission_id)
    destination.mkdir(parents=True, exist_ok=True)

    name = archive_path.name.lower()
    if name.endswith(".zip"):
        _unpack_zip(archive_path, destination)
    elif name.endswith((".tar", ".tar.gz", ".tgz")):
        _unpack_tar(archive_path, destination)
    else:
        raise ArchiveError(f"unsupported archive type: {archive_path.name}")

    return destination


def _unpack_zip(archive_path: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            declared = 0
            for member in members:
                _reject_unsafe_name(member.filename)
                declared += member.file_size
            _check_total(declared)

            written = 0
            for member in members:
                if member.is_dir():
                    continue
                target = destination / member.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                # Stream and re-check: file_size above is a claim made by the
                # archive, not a measurement of what it actually contains.
                with archive.open(member) as src, open(target, "wb") as out:
                    while chunk := src.read(64 * 1024):
                        written += len(chunk)
                        _check_total(written)
                        out.write(chunk)
    except zipfile.BadZipFile as exc:
        raise ArchiveError("not a valid zip file") from exc


def _unpack_tar(archive_path: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive_path) as archive:
            members = archive.getmembers()
            declared = 0
            for member in members:
                _reject_unsafe_name(member.name)
                # Links can point anywhere, including outside the sandbox.
                if member.issym() or member.islnk():
                    raise ArchiveError(f"archive contains a link member: {member.name!r}")
                if not (member.isfile() or member.isdir()):
                    raise ArchiveError(f"archive contains a special file: {member.name!r}")
                declared += member.size
            _check_total(declared)

            # data_filter (Python 3.12+) re-checks paths on extraction; on
            # older interpreters the validation above is what protects us.
            extract_kwargs = {}
            if hasattr(tarfile, "data_filter"):
                extract_kwargs["filter"] = "data"
            archive.extractall(destination, **extract_kwargs)
    except tarfile.TarError as exc:
        raise ArchiveError("not a valid tar file") from exc
