"""Walk the fetched source once and record what is in it.

One pass, because the tree can be large and every extra walk is another full
stat of every file. The result is the *observed* half of the project model;
B3 merges it with the *declared* half from the questionnaire, and a mismatch
between the two is the highest-value signal the platform produces.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ProjectModel

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".terraform"}

LANGUAGE_BY_SUFFIX = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".jsx": "JavaScript", ".go": "Go", ".java": "Java", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++", ".rs": "Rust", ".sh": "Shell",
    ".ps1": "PowerShell", ".sql": "SQL", ".kt": "Kotlin", ".swift": "Swift",
}

MANIFEST_NAMES = {
    "requirements.txt", "pyproject.toml", "package.json", "go.mod",
    "pom.xml", "Gemfile", "build.gradle", "Cargo.toml",
}

CI_PATHS = (".github/workflows", ".gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile")

MAX_YAML_SNIFF_BYTES = 4096


def _is_iac(path: Path, root: Path) -> str | None:
    """Classify a file as infrastructure-as-code, or return None."""
    name = path.name
    suffix = path.suffix.lower()
    relative = path.relative_to(root).as_posix()

    if suffix in {".tf", ".tfvars"}:
        return "terraform"
    if suffix == ".bicep":
        return "bicep"
    if name == "template.json":
        return "arm"
    if name.startswith("Dockerfile"):
        return "docker"
    if name.startswith("docker-compose") and suffix in {".yml", ".yaml"}:
        return "docker-compose"
    if suffix in {".yml", ".yaml"}:
        if relative.startswith("k8s/") or "/k8s/" in relative:
            return "kubernetes"
        # A Kubernetes manifest anywhere in the tree is still a Kubernetes
        # manifest; the reliable marker is the apiVersion key near the top.
        try:
            head = path.read_text(errors="ignore")[:MAX_YAML_SNIFF_BYTES]
        except OSError:
            return None
        if any(line.startswith("apiVersion:") for line in head.splitlines()):
            return "kubernetes"
    return None


def detect(source: Path) -> dict:
    """Single walk of the source tree. Returns the observed project model."""
    languages: Counter[str] = Counter()
    manifests: list[str] = []
    iac_files: list[dict[str, str]] = []
    ci_files: list[str] = []
    file_count = 0

    for path in source.rglob("*"):
        # Never follow a symlink out of the sandbox.
        if path.is_symlink() or not path.is_file():
            continue
        if SKIP_DIRS.intersection(path.relative_to(source).parts):
            continue

        file_count += 1
        relative = path.relative_to(source).as_posix()

        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if language:
            languages[language] += 1

        if path.name in MANIFEST_NAMES or path.suffix.lower() == ".csproj":
            manifests.append(relative)

        kind = _is_iac(path, source)
        if kind:
            iac_files.append({"path": relative, "kind": kind})

        if any(relative.startswith(c) or relative == c for c in CI_PATHS):
            ci_files.append(relative)

    return {
        "file_count": file_count,
        "languages": dict(languages.most_common()),
        "manifests": sorted(manifests),
        "iac_files": iac_files,
        "ci_files": sorted(ci_files),
    }


def store(db: Session, submission_id: int, detection: dict) -> ProjectModel:
    """Upsert the observed half of the project model.

    Upsert, not insert: `project_model.submission_id` is unique, and B3 writes
    entry points and trust boundaries into the same row afterwards.
    """
    row = db.scalar(select(ProjectModel).where(ProjectModel.submission_id == submission_id))
    if row is None:
        row = ProjectModel(submission_id=submission_id)
        db.add(row)

    row.languages = detection["languages"]
    row.iac_files = detection["iac_files"]
    # entry_points, data_stores and trust_boundaries are B3's to fill.
    db.commit()
    db.refresh(row)
    return row
