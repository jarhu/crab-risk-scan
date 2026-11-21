"""Job queue, worker protocol and dashboards."""
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from . import service
from .api_projects import body_limit, read_json
from .auth import Paging, Principal, get_db, get_principal, load_project, require_admin, require_worker, visible_projects
from .db import Job, Project, Scan, Worker, utcnow
from .service import ApiError, iso

router = APIRouter()
JOB_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClaimBody(Body):
    worker: str = Field(min_length=1, max_length=64)
    capabilities: dict = Field(default_factory=dict)


class HeartbeatBody(Body):
    worker: str | None = Field(None, max_length=64)


class FailBody(Body):
    error: str = Field(min_length=1, max_length=service.ERROR_LIMIT)
    log: str | None = Field(None, max_length=4 * service.LOG_LIMIT)
    worker: str | None = Field(None, max_length=64)


def job_project(db, job):
    return db.get(Project, job.project_id)


def load_job(db, principal, job_id, need="viewer"):
    job = db.get(Job, job_id)
    if job is None:
        raise ApiError(404, "job not found")
    project = job_project(db, job)
    try:
        load_project(db, principal, project.key, need)
    except ApiError as exc:
        raise ApiError(404, "job not found") if exc.status == 404 else exc
    return job, project


def status_filter(status):
    if status is not None and status not in JOB_STATUSES:
        raise ApiError(422, "status must be one of: " + ", ".join(JOB_STATUSES))
    return status


@router.get("/jobs")
def list_jobs(status: str | None = Query(None), project: str | None = Query(None, max_length=64),
              paging: Paging = Depends(), db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_admin(principal)
    stmt = select(Job, Project.key).join(Project, Project.id == Job.project_id) \
        .order_by(Job.created_at.desc(), Job.id.desc())
    if status_filter(status) is not None:
        stmt = stmt.where(Job.status == status)
    if project is not None:
        stmt = stmt.where(Project.key == project)
    rows, total = paging.apply(db, stmt, scalars=False)
    return {"items": [service.job_item(job, key) for job, key in rows], "total": total}


@router.get("/jobs/{job_id}")
def get_job(job_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    job, project = load_job(db, principal, job_id)
    return service.job_item(job, project.key, log=True)


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    job, project = load_job(db, principal, job_id, "maintainer")
    service.cancel_job(db, job)
    db.commit()
    return service.job_item(job, project.key)


# Worker protocol ------------------------------------------------------------------------------

@router.post("/workers/claim")
def claim(body: ClaimBody, request: Request, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    token = require_worker(principal)
    if not service.WORKER_NAME.fullmatch(body.worker):
        raise ApiError(422, "worker must be 1-64 letters, digits, '.', '_' or '-'")
    settings = request.app.state.settings
    job = service.claim_job(db, settings, body.worker, bool(body.capabilities.get("git")), token.id)
    if job is None:
        return Response(status_code=204)
    project = job_project(db, job)
    item = service.job_item(job, project.key)
    item["repository_url"] = project.repository_url
    return {"job": item, "lease_seconds": settings.lease_seconds}


@router.post("/jobs/{job_id}/heartbeat")
def heartbeat(job_id: int, request: Request, body: HeartbeatBody | None = None, db=Depends(get_db),
              principal: Principal = Depends(get_principal)):
    token = require_worker(principal)
    return service.heartbeat(db, request.app.state.settings, job_id, token.id, body.worker if body else None)


def complete_job(db, token, job_id, body, settings):
    unknown = set(body) - {"report", "sbom", "log", "worker"}
    if unknown:
        raise ApiError(422, "unknown fields: " + ", ".join(sorted(unknown)))
    worker = body.get("worker")
    if worker is not None and not isinstance(worker, str):
        raise ApiError(422, "worker must be a string")
    job = service.held_job(db, job_id, token.id, worker)
    log = service.bounded_log(body.get("log"))
    try:
        if "report" not in body:
            raise ApiError(422, "report is required")
        service.check_document_size("report", body["report"], settings.upload_limit)
        if body.get("sbom") is not None:
            service.check_document_size("sbom", body["sbom"], settings.upload_limit)
        report = service.validate_report(body["report"])
        sbom = service.validate_sbom(body.get("sbom"))
    except ApiError as exc:
        service.finish_job(db, job, "failed", error=f"worker returned an unusable report: {exc.detail}", log=log)
        db.commit()
        raise
    scan = service.store_scan(db, job_project(db, job), report, sbom=sbom, source="job", job_id=job.id)
    service.finish_job(db, job, "succeeded", log=log, scan_id=scan.id)
    db.commit()
    return {"scan_id": scan.id}


@router.post("/jobs/{job_id}/complete")
async def complete(job_id: int, request: Request, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    token = require_worker(principal)
    settings = request.app.state.settings
    body = await read_json(request, body_limit(settings))
    return await run_in_threadpool(complete_job, db, token, job_id, body, settings)


@router.post("/jobs/{job_id}/fail")
def fail(job_id: int, body: FailBody, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    token = require_worker(principal)
    job = service.held_job(db, job_id, token.id, body.worker)
    service.finish_job(db, job, "failed", error=body.error, log=body.log)
    db.commit()
    return {"id": job.id, "status": job.status}


@router.get("/workers")
def list_workers(request: Request, paging: Paging = Depends(), db=Depends(get_db),
                 principal: Principal = Depends(get_principal)):
    require_admin(principal)
    horizon = utcnow() - timedelta(seconds=max(60, request.app.state.settings.lease_seconds))
    workers, total = paging.apply(db, select(Worker).order_by(Worker.name))
    return {"items": [{"name": worker.name, "last_seen_at": iso(worker.last_seen_at),
                       "current_job": worker.current_job_id, "active": worker.last_seen_at >= horizon,
                       "capabilities": worker.capabilities} for worker in workers], "total": total}


# Dashboards -----------------------------------------------------------------------------------

@router.get("/dashboard")
def dashboard(days: int = Query(30, ge=1, le=365), db=Depends(get_db), principal: Principal = Depends(get_principal)):
    projects = db.scalars(visible_projects(principal).order_by(Project.key)).all()
    data = service.breakdown(db, projects, days)
    latest = data.pop("latest")
    data["projects_summary"] = [{"key": project.key, "name": project.name, "latest_scan": latest.get(project.id)}
                                for project in projects]
    return data


@router.get("/projects/{key}/dashboard")
def project_dashboard(key: str, days: int = Query(30, ge=1, le=365), db=Depends(get_db),
                      principal: Principal = Depends(get_principal)):
    project = load_project(db, principal, key)
    data = service.breakdown(db, [project], days)
    latest = data.pop("latest")
    recent = db.scalars(select(Scan).where(Scan.project_id == project.id)
                        .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(10)).all()
    return {"project": project.key, "latest_scan": latest.get(project.id), "scans": data["scans"],
            "counts": data["counts"], "categories": data["categories"], "policy": data["policy"],
            "trend": data["trend"], "top_rules": data["top_rules"], "top_packages": data["top_packages"],
            "recent_scans": service.summaries(db, recent, {project.id: project.key})}
