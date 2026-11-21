"""Projects, members, scan uploads, exceptions, project jobs and schedules."""
import json
import re

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select

from . import service
from .auth import (Paging, Principal, get_db, get_principal, load_project, project_role, require_admin,
                   require_session, visible_projects)
from .db import Job, Membership, Project, ProjectException, Scan, Schedule, User, utcnow
from .service import ApiError, iso

router = APIRouter()
PROJECT_KEY = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
MIB = 1024 * 1024


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectCreate(Body):
    key: str
    name: str = Field(min_length=1, max_length=200)
    repository_url: str | None = None
    default_branch: str | None = Field(None, max_length=256)
    scan_path: str | None = Field(None, max_length=4096)


class ProjectPatch(Body):
    name: str | None = Field(None, min_length=1, max_length=200)
    repository_url: str | None = None
    default_branch: str | None = Field(None, max_length=256)
    scan_path: str | None = Field(None, max_length=4096)


class MemberBody(Body):
    role: str


class ExceptionBody(Body):
    status: str
    reason: str
    justification: str | None = None
    expires: str | None = None
    ticket: str | None = None


class JobBody(Body):
    source: dict
    options: dict = Field(default_factory=dict)


class ScheduleCreate(Body):
    cron: str
    source: dict
    options: dict = Field(default_factory=dict)
    enabled: bool = True


class SchedulePatch(Body):
    cron: str | None = None
    source: dict | None = None
    options: dict | None = None
    enabled: bool | None = None


def project_item(db, principal, project, latest=None):
    return {"id": project.id, "key": project.key, "name": project.name, "repository_url": project.repository_url,
            "default_branch": project.default_branch, "scan_path": project.scan_path,
            "created_at": iso(project.created_at), "role": project_role(db, principal, project),
            "latest_scan": latest}


def check_repository(url):
    if url is not None and not service.http_url(url):
        raise ApiError(422, "repository_url must be an http or https URL")
    return url


def reject_constant(name):
    raise ValueError(f"{name} is not valid JSON")


def parse_json(body):
    """Strict JSON object parsing: NaN, Infinity and -Infinity are rejected."""
    try:
        data = json.loads(body, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise ApiError(400, "request body must be JSON") from None
    if not isinstance(data, dict):
        raise ApiError(422, "request body must be a JSON object")
    return data


async def read_json(request, limit):
    """Read a JSON object body, answering 413 as soon as it exceeds `limit` bytes. Callers authorize
    first. A small pool of slots bounds how many large bodies are buffered and parsed at once, and
    parsing runs in the threadpool so it never blocks the event loop."""
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > limit:
        raise ApiError(413, "request body too large")
    async with request.app.state.body_slots:
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > limit:
                raise ApiError(413, "request body too large")
        return await run_in_threadpool(parse_json, body)


def body_limit(settings):
    return 2 * settings.upload_limit + MIB


# Projects -------------------------------------------------------------------------------------

@router.get("/projects")
def list_projects(paging: Paging = Depends(), db=Depends(get_db), principal: Principal = Depends(get_principal)):
    projects, total = paging.apply(db, visible_projects(principal).order_by(Project.key))
    keys = {project.id: project.key for project in projects}
    latest = service.latest_scans(db, list(keys))
    scans = list(latest.values())
    by_project = {scan.project_id: item for scan, item in zip(scans, service.summaries(db, scans, keys))}
    return {"items": [project_item(db, principal, project, by_project.get(project.id)) for project in projects],
            "total": total}


@router.post("/projects", status_code=201)
def create_project(body: ProjectCreate, request: Request, db=Depends(get_db),
                   principal: Principal = Depends(get_principal)):
    require_admin(principal)
    if not PROJECT_KEY.fullmatch(body.key):
        raise ApiError(422, "key must be 1-64 lowercase letters, digits, '.', '_' or '-'")
    if db.scalar(select(Project).where(Project.key == body.key)):
        raise ApiError(409, "project key already exists")
    project = Project(key=body.key, name=body.name.strip(), repository_url=check_repository(body.repository_url),
                      default_branch=body.default_branch or None,
                      scan_path=service.validate_scan_path(body.scan_path, request.app.state.settings.scan_roots))
    db.add(project)
    db.commit()
    return project_item(db, principal, project)


def latest_summary(db, project):
    scan = service.latest_scans(db, [project.id]).get(project.id)
    return service.scan_summary(db, scan, project.key) if scan else None


@router.get("/projects/{key}")
def get_project(key: str, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    project = load_project(db, principal, key)
    return project_item(db, principal, project, latest_summary(db, project))


@router.patch("/projects/{key}")
def update_project(key: str, body: ProjectPatch, request: Request, db=Depends(get_db),
                   principal: Principal = Depends(get_principal)):
    require_session(principal)
    project = load_project(db, principal, key, "maintainer")
    fields = body.model_fields_set
    if "name" in fields:
        if body.name is None:
            raise ApiError(422, "name cannot be empty")
        project.name = body.name.strip()
    if "repository_url" in fields:
        project.repository_url = check_repository(body.repository_url or None)
    if "default_branch" in fields:
        project.default_branch = body.default_branch or None
    if "scan_path" in fields:
        if not principal.is_admin:
            raise ApiError(403, "only admins can change the scan path")
        project.scan_path = service.validate_scan_path(body.scan_path, request.app.state.settings.scan_roots)
    project.updated_at = utcnow()
    db.commit()
    return project_item(db, principal, project, latest_summary(db, project))


@router.delete("/projects/{key}", status_code=204)
def delete_project(key: str, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_admin(principal)
    project = load_project(db, principal, key)
    db.execute(delete(Project).where(Project.id == project.id))
    db.commit()
    return Response(status_code=204)


# Members --------------------------------------------------------------------------------------

def member_item(user, role):
    return {"user_id": user.id, "username": user.username, "role": role}


@router.get("/projects/{key}/members")
def list_members(key: str, paging: Paging = Depends(), db=Depends(get_db),
                 principal: Principal = Depends(get_principal)):
    require_session(principal)
    project = load_project(db, principal, key, "maintainer")
    rows, total = paging.apply(db, select(User, Membership.role).join(Membership, Membership.user_id == User.id)
                               .where(Membership.project_id == project.id).order_by(User.username), scalars=False)
    return {"items": [member_item(user, role) for user, role in rows], "total": total}


@router.get("/projects/{key}/candidates")
def member_candidates(key: str, q: str = Query("", max_length=64), db=Depends(get_db),
                      principal: Principal = Depends(get_principal)):
    """Active users whose name starts with `q`, so maintainers can add members without /users."""
    require_session(principal)
    load_project(db, principal, key, "maintainer")
    prefix = q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    users = db.execute(select(User.id, User.username).where(User.active.is_(True),
                                                            User.username.like(prefix + "%", escape="\\"))
                       .order_by(User.username).limit(20)).all()
    return {"items": [{"id": user_id, "username": username} for user_id, username in users]}


@router.put("/projects/{key}/members/{user_id}")
def put_member(key: str, user_id: int, body: MemberBody, db=Depends(get_db),
               principal: Principal = Depends(get_principal)):
    require_session(principal)
    project = load_project(db, principal, key, "maintainer")
    if body.role not in ("maintainer", "viewer"):
        raise ApiError(422, "role must be maintainer or viewer")
    user = db.get(User, user_id)
    if user is None:
        raise ApiError(404, "user not found")
    membership = db.scalar(select(Membership).where(Membership.project_id == project.id,
                                                    Membership.user_id == user.id))
    if membership is None:
        db.add(Membership(project_id=project.id, user_id=user.id, role=body.role))
    else:
        membership.role = body.role
    db.commit()
    return member_item(user, body.role)


@router.delete("/projects/{key}/members/{user_id}", status_code=204)
def delete_member(key: str, user_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_session(principal)
    project = load_project(db, principal, key, "maintainer")
    removed = db.execute(delete(Membership).where(Membership.project_id == project.id,
                                                  Membership.user_id == user_id)).rowcount
    if not removed:
        raise ApiError(404, "membership not found")
    db.commit()
    return Response(status_code=204)


# Scans ----------------------------------------------------------------------------------------

def authorize_upload(db, principal, key):
    """Authorize before the body is read; the transaction ends so no lock is held while it streams."""
    project = load_project(db, principal, key, "maintainer", upload=True)
    db.commit()
    return project


def store_upload(db, project, body, settings, base_url):
    unknown = set(body) - {"report", "sbom", "source", "ci"}
    if unknown:
        raise ApiError(422, "unknown upload fields: " + ", ".join(sorted(unknown)))
    if "report" not in body:
        raise ApiError(422, "report is required")
    service.check_document_size("report", body["report"], settings.upload_limit)
    if body.get("sbom") is not None:
        service.check_document_size("sbom", body["sbom"], settings.upload_limit)
    report = service.validate_report(body["report"])
    sbom = service.validate_sbom(body.get("sbom"))
    source = body.get("source") or "upload"
    if source not in ("runner", "upload"):
        raise ApiError(422, "source must be runner or upload")
    ci = service.validate_ci(body.get("ci"))
    scan = service.store_scan(db, project, report, sbom=sbom, source=source, ci=ci)
    db.commit()
    item = service.scan_summary(db, scan, project.key)
    item["url"] = f"{base_url}scans/{scan.id}"
    return item


@router.post("/projects/{key}/scans", status_code=201)
async def upload_scan(key: str, request: Request, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    settings = request.app.state.settings
    project = await run_in_threadpool(authorize_upload, db, principal, key)
    body = await read_json(request, body_limit(settings))
    return await run_in_threadpool(store_upload, db, project, body, settings, str(request.base_url))


@router.get("/projects/{key}/scans")
def list_scans(key: str, branch: str | None = Query(None, max_length=256), paging: Paging = Depends(),
               db=Depends(get_db), principal: Principal = Depends(get_principal)):
    project = load_project(db, principal, key)
    stmt = select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc(), Scan.id.desc())
    if branch is not None:
        stmt = stmt.where(Scan.branch == branch)
    scans, total = paging.apply(db, stmt)
    return {"items": service.summaries(db, scans, {project.id: project.key}), "total": total}


# Exceptions -----------------------------------------------------------------------------------

@router.get("/projects/{key}/exceptions")
def list_exceptions(key: str, paging: Paging = Depends(), db=Depends(get_db),
                    principal: Principal = Depends(get_principal)):
    project = load_project(db, principal, key)
    rows, total = paging.apply(db, select(ProjectException).where(ProjectException.project_id == project.id)
                               .order_by(ProjectException.fingerprint))
    return {"items": [service.exception_item(row) for row in rows], "total": total}


@router.get("/projects/{key}/exceptions/export")
def export_exceptions(key: str, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    project = load_project(db, principal, key)
    document = service.export_exceptions(service.project_exceptions(db, project.id).values())
    return JSONResponse(document, headers={
        "Content-Disposition": f'attachment; filename="crab-exceptions-{project.key}.json"'})


@router.put("/projects/{key}/exceptions/{fingerprint}")
def put_exception(key: str, fingerprint: str, body: ExceptionBody, db=Depends(get_db),
                  principal: Principal = Depends(get_principal)):
    user = require_session(principal)
    project = load_project(db, principal, key, "maintainer")
    values = service.validate_exception(fingerprint, body.model_dump())
    row = db.scalar(select(ProjectException).where(ProjectException.project_id == project.id,
                                                   ProjectException.fingerprint == fingerprint))
    now = utcnow()
    if row is None:
        row = ProjectException(project_id=project.id, fingerprint=fingerprint, created_at=now)
        db.add(row)
    for name, value in values.items():
        setattr(row, name, value)
    row.reviewer = user.username
    row.updated_at = now
    db.commit()
    return service.exception_item(row)


@router.delete("/projects/{key}/exceptions/{fingerprint}", status_code=204)
def delete_exception(key: str, fingerprint: str, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_session(principal)
    project = load_project(db, principal, key, "maintainer")
    removed = db.execute(delete(ProjectException).where(ProjectException.project_id == project.id,
                                                        ProjectException.fingerprint == fingerprint)).rowcount
    if not removed:
        raise ApiError(404, "exception not found")
    db.commit()
    return Response(status_code=204)


# Project jobs ---------------------------------------------------------------------------------

@router.post("/projects/{key}/jobs", status_code=201)
def create_job(key: str, body: JobBody, request: Request, db=Depends(get_db),
               principal: Principal = Depends(get_principal)):
    require_session(principal)
    settings = request.app.state.settings
    project = load_project(db, principal, key, "maintainer")
    source = service.validate_source(body.source, settings, scan_path=project.scan_path,
                                     confined=not principal.is_admin)
    options = service.validate_options(body.options)
    service.check_queue_capacity(db, project.id)
    job = service.new_job(project.id, source, options, settings)
    db.add(job)
    db.commit()
    return service.job_item(job, project.key)


@router.get("/projects/{key}/jobs")
def list_project_jobs(key: str, status: str | None = Query(None), paging: Paging = Depends(), db=Depends(get_db),
                      principal: Principal = Depends(get_principal)):
    project = load_project(db, principal, key, "maintainer")
    stmt = select(Job).where(Job.project_id == project.id).order_by(Job.created_at.desc(), Job.id.desc())
    if status is not None:
        stmt = stmt.where(Job.status == status)
    jobs, total = paging.apply(db, stmt)
    return {"items": [service.job_item(job, project.key) for job in jobs], "total": total}


# Schedules ------------------------------------------------------------------------------------

@router.get("/projects/{key}/schedules")
def list_schedules(key: str, paging: Paging = Depends(), db=Depends(get_db),
                   principal: Principal = Depends(get_principal)):
    project = load_project(db, principal, key, "maintainer")
    rows, total = paging.apply(db, select(Schedule).where(Schedule.project_id == project.id).order_by(Schedule.id))
    return {"items": [service.schedule_item(row, project.key) for row in rows], "total": total}


@router.post("/projects/{key}/schedules", status_code=201)
def create_schedule(key: str, body: ScheduleCreate, request: Request, db=Depends(get_db),
                    principal: Principal = Depends(get_principal)):
    require_session(principal)
    settings = request.app.state.settings
    project = load_project(db, principal, key, "maintainer")
    cron = service.parse_cron(body.cron)
    source = service.validate_source(body.source, settings, scan_path=project.scan_path,
                                     confined=not principal.is_admin)
    service.check_schedule_capacity(db, project.id)
    schedule = Schedule(project_id=project.id, cron=cron.text, source=source, admin_source=principal.is_admin,
                        options=service.validate_options(body.options), enabled=body.enabled,
                        next_run_at=cron.next_after(utcnow()) if body.enabled else None)
    db.add(schedule)
    db.commit()
    return service.schedule_item(schedule, project.key)


def load_schedule(db, principal, schedule_id):
    schedule = db.get(Schedule, schedule_id)
    if schedule is None:
        raise ApiError(404, "schedule not found")
    project = db.get(Project, schedule.project_id)
    try:
        load_project(db, principal, project.key, "maintainer")
    except ApiError as exc:
        raise ApiError(404, "schedule not found") if exc.status == 404 else exc
    return schedule, project


@router.patch("/schedules/{schedule_id}")
def update_schedule(schedule_id: int, body: SchedulePatch, request: Request, db=Depends(get_db),
                    principal: Principal = Depends(get_principal)):
    require_session(principal)
    settings = request.app.state.settings
    schedule, project = load_schedule(db, principal, schedule_id)
    fields = body.model_fields_set
    reschedule = False
    if "cron" in fields and body.cron is not None:
        schedule.cron = service.parse_cron(body.cron).text
        reschedule = True
    if "source" in fields and body.source is not None:
        schedule.source = service.validate_source(body.source, settings, scan_path=project.scan_path,
                                                  confined=not principal.is_admin)
        schedule.admin_source = principal.is_admin
    if "options" in fields:
        schedule.options = service.validate_options(body.options)
    if "enabled" in fields and body.enabled is not None:
        reschedule = reschedule or body.enabled != schedule.enabled
        schedule.enabled = body.enabled
    if reschedule:
        schedule.next_run_at = service.parse_cron(schedule.cron).next_after(utcnow()) if schedule.enabled else None
    schedule.updated_at = utcnow()
    db.commit()
    return service.schedule_item(schedule, project.key)


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_session(principal)
    schedule, _ = load_schedule(db, principal, schedule_id)
    db.execute(delete(Schedule).where(Schedule.id == schedule.id))
    db.commit()
    return Response(status_code=204)
