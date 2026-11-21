"""Scan detail, findings, comparison, report downloads and SBOM retrieval."""
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, not_, or_, select

from . import service
from .auth import Principal, get_db, get_principal, load_project
from .db import Finding, Project, ProjectException, Scan, utcnow
from .service import CATEGORIES, SEVERITIES, ApiError

router = APIRouter()
REPORT_FORMATS = ("json", "sarif", "markdown", "html", "csv", "docx", "codequality", "vex")
DOWNLOADS = {
    "json": ("application/json", "report.json"),
    "sarif": ("application/sarif+json", "report.sarif"),
    "markdown": ("text/markdown; charset=utf-8", "report.md"),
    "html": ("text/html; charset=utf-8", "report.html"),
    "csv": ("text/csv; charset=utf-8", "report.csv"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "report.docx"),
    "codequality": ("application/json", "gl-code-quality-report.json"),
    "vex": ("application/vnd.cyclonedx+json", "report.vex.json"),
}
# Downloaded HTML reports never run script on the API origin.
HTML_POLICY = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"


def load_scan(db, principal, scan_id):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ApiError(404, "scan not found")
    project = db.get(Project, scan.project_id)
    try:
        load_project(db, principal, project.key)
    except ApiError as exc:
        raise ApiError(404, "scan not found") if exc.status == 404 else exc
    return scan, project


def choices(value, allowed, name):
    if value is None:
        return None
    values = [part.strip() for part in value.split(",") if part.strip()]
    if not values or any(part not in allowed for part in values):
        raise ApiError(422, f"{name} must be one or more of: " + ", ".join(allowed))
    return values


def like(text):
    escaped = text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def finding_rows(scan, stmt_filter=()):
    stmt = service._exception_join(select(Finding.data, ProjectException).select_from(Finding)).where(
        Finding.scan_id == scan.id, *stmt_filter).order_by(Finding.position)
    return stmt


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    scan, project = load_scan(db, principal, scan_id)
    return service.scan_detail(db, scan, project.key)


@router.get("/scans/{scan_id}/findings")
def list_findings(scan_id: int, severity: str | None = Query(None, max_length=200),
                  category: str | None = Query(None, max_length=200), status: str | None = Query(None),
                  producer: str | None = Query(None, max_length=500), kind: str | None = Query(None),
                  new: bool | None = Query(None), q: str | None = Query(None, max_length=200),
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500),
                  db=Depends(get_db), principal: Principal = Depends(get_principal)):
    scan, project = load_scan(db, principal, scan_id)
    day = service.today()
    filters = []
    if (levels := choices(severity, SEVERITIES, "severity")) is not None:
        filters.append(Finding.severity.in_(levels))
    if (groups := choices(category, CATEGORIES, "category")) is not None:
        filters.append(Finding.category.in_(groups))
    if producer is not None:
        names = [part.strip() for part in producer.split(",") if part.strip()]
        filters.append(Finding.producer.in_(names))
    if kind is not None:
        if kind not in ("vulnerability", "review"):
            raise ApiError(422, "kind must be vulnerability or review")
        filters.append(Finding.kind == kind)
    if status is not None:
        if status not in ("open", "suppressed"):
            raise ApiError(422, "status must be open or suppressed")
        clause = service.suppressed_clause(day)
        filters.append(clause if status == "suppressed" else not_(clause))
    if new is not None:
        filters.append(Finding.is_new.is_(True) if new else Finding.is_new.is_(False))
    if q:
        pattern = like(q)
        filters.append(or_(*(func.lower(column).like(pattern, escape="\\") for column in (
            Finding.rule, Finding.path, Finding.package_name, Finding.package_purl))))
    stmt = finding_rows(scan, filters)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))
    rows = db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [service.finding_item(json.loads(data), row, day) for data, row in rows], "total": total}


@router.get("/scans/{scan_id}/compare")
def compare(scan_id: int, base: int = Query(...), db=Depends(get_db), principal: Principal = Depends(get_principal)):
    head_scan, project = load_scan(db, principal, scan_id)
    base_scan, base_project = load_scan(db, principal, base)
    if base_project.id != project.id:
        raise ApiError(422, "both scans must belong to the same project")
    day = service.today()
    head_rows = db.execute(finding_rows(head_scan)).all()
    base_rows = db.execute(finding_rows(base_scan)).all()
    head = [(json.loads(data), row) for data, row in head_rows]
    previous = [(json.loads(data), row) for data, row in base_rows]
    head_prints = {finding["fingerprint"] for finding, _ in head}
    base_prints = {finding["fingerprint"] for finding, _ in previous}
    keys = {project.id: project.key}
    base_summary, head_summary = service.summaries(db, [base_scan, head_scan], keys)
    return {
        "base": base_summary, "head": head_summary,
        "new": [service.finding_item(finding, row, day) for finding, row in head
                if finding["fingerprint"] not in base_prints],
        "fixed": [service.finding_item(finding, row, day) for finding, row in previous
                  if finding["fingerprint"] not in head_prints],
        "unchanged": sum(1 for finding, _ in head if finding["fingerprint"] in base_prints),
    }


@router.get("/scans/{scan_id}/report")
def download_report(scan_id: int, format: str = Query("json"), template: str | None = Query(None),
                    db=Depends(get_db), principal: Principal = Depends(get_principal)):
    from ..reports import render
    if format not in REPORT_FORMATS:
        raise ApiError(422, "format must be one of: " + ", ".join(REPORT_FORMATS))
    if template not in (None, "technical", "executive"):
        raise ApiError(422, "template must be technical or executive")
    scan, project = load_scan(db, principal, scan_id)
    report = service.apply_exceptions(service.unpack(scan.report_gz), service.project_exceptions(db, project.id))
    db.commit()
    options = {"generated_at": service.iso(utcnow())}
    if template is not None:
        options["template"] = template
    try:
        data = render(report, format, **options)
    except ImportError:
        raise ApiError(501, f"the {format} renderer needs an optional dependency that is not installed") from None
    except ValueError as exc:
        raise ApiError(422, f"cannot render {format}: {exc}") from None
    media_type, name = DOWNLOADS[format]
    headers = {"Content-Disposition": f'attachment; filename="{project.key}-{scan.id}-{name}"'}
    if format == "html":
        headers["Content-Security-Policy"] = HTML_POLICY
    return Response(content=data, media_type=media_type, headers=headers)


@router.get("/scans/{scan_id}/sbom")
def download_sbom(scan_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    scan, project = load_scan(db, principal, scan_id)
    sbom = service.unpack(scan.sbom_gz)
    if sbom is None:
        raise ApiError(404, "this scan has no SBOM")
    suffix = "spdx.json" if "spdxVersion" in sbom else "cdx.json"
    data = (json.dumps(sbom, indent=2) + "\n").encode("utf-8")
    return Response(content=data, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="{project.key}-{scan.id}-sbom.{suffix}"'})
