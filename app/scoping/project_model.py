"""Build the canonical project model: declared scope merged with observed scope.

Without this step you are rating a questionnaire. With it you are rating a
system — and, more usefully, rating the gap between the two.

Detection here is deliberately regex-shaped rather than AST-shaped. It reads
files it does not trust, in languages it may not know, and it has to fail
towards "found nothing" rather than towards a crash. Over-matching is a bug;
missing a framework is a known limitation with a list of patterns to extend.
"""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingestion.detect import SKIP_DIRS
from app.models import ProjectModel, QuestionnaireResponse
from app.scoping import boundaries

# Only text worth reading, and only so much of it.
READABLE_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php", ".cs",
    ".tf", ".tfvars", ".bicep", ".yml", ".yaml", ".json", ".toml", ".ini",
    ".env", ".cfg", ".conf", ".sh", ".sql", ".md",
}
READABLE_NAMES = {"Dockerfile", "Procfile", "Makefile"}
MAX_FILE_BYTES = 512 * 1024

HTTP_ROUTE_PATTERNS = (
    # Flask / FastAPI / Starlette decorators
    re.compile(r"@\w+\.(?:route|get|post|put|patch|delete)\(\s*[\"']([^\"']+)"),
    # Express / Koa
    re.compile(r"\b(?:app|router)\.(?:get|post|put|patch|delete|all)\(\s*[\"']([^\"']+)"),
    # Django urls
    re.compile(r"\bpath\(\s*[\"']([^\"']*)[\"']\s*,"),
    # Spring
    re.compile(r"@(?:Get|Post|Put|Delete|Request)Mapping\(\s*[\"']([^\"']+)"),
)

PUBLIC_IAC_PATTERNS = (
    (re.compile(r"0\.0\.0\.0/0"), "open CIDR 0.0.0.0/0"),
    (re.compile(r"::/0"), "open IPv6 CIDR ::/0"),
    (re.compile(r"type:\s*LoadBalancer"), "Kubernetes Service type LoadBalancer"),
    (re.compile(r"type:\s*NodePort"), "Kubernetes Service type NodePort"),
    (re.compile(r"\baws_lb\b|\baws_alb\b|\baws_elb\b"), "AWS load balancer"),
    (re.compile(r"\bazurerm_public_ip\b"), "Azure public IP"),
    (re.compile(r"\bgoogle_compute_global_address\b"), "GCP global address"),
    (re.compile(r"publicNetworkAccess\s*=\s*[\"']?Enabled"), "public network access enabled"),
)

PRIVILEGED_IAC_PATTERNS = (
    (re.compile(r"\baws_iam_(?:role|policy|user|group|role_policy\w*)\b"), "AWS IAM resource"),
    (re.compile(r"\bazurerm_role_assignment\b|\bazurerm_role_definition\b"), "Azure role assignment"),
    (re.compile(r"\bgoogle_project_iam_\w+\b"), "GCP IAM binding"),
    (re.compile(r"\"Action\"\s*:\s*\"\*\"|\bAction\s*=\s*\[?\s*\"\*\""), "wildcard IAM action"),
    (re.compile(r"\bkind:\s*ClusterRoleBinding\b"), "Kubernetes ClusterRoleBinding"),
)

DATA_STORE_PATTERNS = (
    (re.compile(r"\b(postgres(?:ql)?|mysql|mariadb|mongodb|redis|amqp|mssql)://"), "connection URI"),
    (re.compile(r"\bDeclarativeBase\b|\b__tablename__\b"), "ORM model"),
    (re.compile(r"boto3\.(?:client|resource)\(\s*[\"'](s3|dynamodb|rds)[\"']"), "AWS data SDK"),
    (re.compile(r"\bBlobServiceClient\b|\bCosmosClient\b|\bTableServiceClient\b"), "Azure data SDK"),
    (re.compile(r"\bcreate_engine\(|\bpsycopg\b|\bpymongo\b"), "database driver"),
)

EXTERNAL_HOST = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[/:]|\b)")

# Hosts that are documentation, schemas or package registries, not runtime
# dependencies. Counting these would make the third-party check meaningless.
IGNORED_HOSTS = {
    "localhost", "example.com", "www.example.com", "schema.org", "www.w3.org",
    "json-schema.org", "github.com", "www.github.com", "raw.githubusercontent.com",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "npmjs.com",
    "docs.python.org", "opensource.org", "www.apache.org", "creativecommons.org",
    "spdx.org", "azure.microsoft.com", "learn.microsoft.com", "docs.aws.amazon.com",
    "registry.terraform.io", "hub.docker.com", "127.0.0.1", "0.0.0.0",
}


def _readable_files(source: Path):
    for path in source.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        if SKIP_DIRS.intersection(path.relative_to(source).parts):
            continue
        if path.suffix.lower() not in READABLE_SUFFIXES and path.name not in READABLE_NAMES:
            if not path.name.startswith("Dockerfile"):
                continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            yield path, path.read_text(errors="ignore")
        except OSError:
            continue


def scan(source: Path) -> dict:
    """One content pass. Returns entry points, data stores, deps, privileges."""
    entry_points: list[dict] = []
    data_stores: list[dict] = []
    external: dict[str, str] = {}
    privileged: list[dict] = []

    for path, text in _readable_files(source):
        relative = path.relative_to(source).as_posix()

        for pattern in HTTP_ROUTE_PATTERNS:
            for route in set(pattern.findall(text)):
                entry_points.append(
                    {"kind": "http_route", "value": route, "public": False,
                     "evidence": f"{relative}: {route}"}
                )

        if path.name.startswith("Dockerfile"):
            for port in set(re.findall(r"^\s*EXPOSE\s+(\d+)", text, re.M)):
                entry_points.append(
                    {"kind": "container_port", "value": port, "public": False,
                     "evidence": f"{relative}: EXPOSE {port}"}
                )

        for pattern, label in PUBLIC_IAC_PATTERNS:
            if pattern.search(text):
                entry_points.append(
                    {"kind": "public_exposure", "value": label, "public": True,
                     "evidence": f"{relative}: {label}"}
                )

        for pattern, label in PRIVILEGED_IAC_PATTERNS:
            if pattern.search(text):
                privileged.append({"kind": label, "evidence": f"{relative}: {label}"})

        for pattern, label in DATA_STORE_PATTERNS:
            if pattern.search(text):
                data_stores.append({"kind": label, "evidence": f"{relative}: {label}"})

        for host in EXTERNAL_HOST.findall(text):
            host = host.lower().rstrip(".")
            if host not in IGNORED_HOSTS and host not in external:
                external[host] = f"{relative}: {host}"

    return {
        "entry_points": _dedupe(entry_points, ("kind", "value")),
        "data_stores": _dedupe(data_stores, ("kind",)),
        "external_dependencies": [{"host": h, "evidence": e} for h, e in sorted(external.items())],
        "privileged_resources": _dedupe(privileged, ("kind",)),
    }


def _dedupe(items: list[dict], keys: tuple[str, ...]) -> list[dict]:
    seen: set[tuple] = set()
    result = []
    for item in items:
        signature = tuple(item.get(k) for k in keys)
        if signature not in seen:
            seen.add(signature)
            result.append(item)
    return result


def declared_scope(db: Session, submission_id: int) -> dict[str, str]:
    """The questionnaire answers, as {question_key: answer_value}."""
    rows = db.scalars(
        select(QuestionnaireResponse).where(QuestionnaireResponse.submission_id == submission_id)
    ).all()
    return {r.question_key: r.answer_value for r in rows if r.answer_value}


def build(db: Session, submission_id: int, source: Path) -> ProjectModel:
    """Merge declared and observed scope, then persist onto the B2 row."""
    observed = scan(source)
    declared = declared_scope(db, submission_id)

    trust_boundaries = boundaries.derive(
        entry_points=observed["entry_points"],
        data_stores=observed["data_stores"],
        external_dependencies=observed["external_dependencies"],
        privileged_resources=observed["privileged_resources"],
    )
    mismatches = boundaries.detect_scope_mismatches(declared, observed)

    # Upsert: B2 created this row with languages and iac_files.
    row = db.scalar(select(ProjectModel).where(ProjectModel.submission_id == submission_id))
    if row is None:
        row = ProjectModel(submission_id=submission_id)
        db.add(row)

    row.entry_points = observed["entry_points"]
    row.data_stores = observed["data_stores"]
    row.trust_boundaries = trust_boundaries
    row.external_dependencies = observed["external_dependencies"]
    row.scope_mismatches = mismatches
    db.commit()
    db.refresh(row)
    return row
