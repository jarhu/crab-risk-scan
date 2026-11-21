"""Server domain logic: scan ingestion, triage overlay, jobs, schedules and dashboards.

Functions raise ApiError for client mistakes; the application maps it to `{"detail": ...}`.
"""
import copy
import ipaddress
import json
import os
import re
import zlib
from datetime import date, datetime, time, timedelta
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import and_, delete, func, not_, or_, select, update

from .cron import CronExpression
from .db import Finding, Job, LoginFailure, Project, ProjectException, Scan, Schedule, Worker, utcnow
from .safety import blocked_address, contained, host_allowed, unc_or_device

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = ("sast", "secrets", "iac", "sca", "container")
LEVELS = SEVERITIES + ("none",)
EXCEPTION_STATUSES = ("accepted", "false_positive", "not_affected")
JUSTIFICATIONS = ("code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
                  "requires_environment", "protected_by_compiler", "protected_at_runtime",
                  "protected_at_perimeter", "protected_by_mitigating_control")
FINGERPRINT = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
ENGINES = re.compile(r"auto|all|none|[a-z][a-z-]{0,31}(,[a-z][a-z-]{0,31}){0,15}")
GIT_REF = re.compile(r"[A-Za-z0-9._/][A-Za-z0-9._/-]{0,199}")
WORKER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
LOG_LIMIT = 64 * 1024
ERROR_LIMIT = 2000
CHUNK = 500
MAX_SCHEDULES = 50
MAX_QUEUED_JOBS = 100
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "report-v3.schema.json"


class ApiError(Exception):
    def __init__(self, status, detail, headers=None):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.headers = headers


def iso(moment):
    return None if moment is None else moment.isoformat(timespec="seconds") + "Z"


def today():
    return utcnow().date().isoformat()


def pack(document):
    return zlib.compress(json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8"), 6)


def unpack(blob):
    return None if blob is None else json.loads(zlib.decompress(blob))


def document_size(document):
    return len(json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def chunks(values):
    values = list(values)
    for start in range(0, len(values), CHUNK):
        yield values[start:start + CHUNK]


# Upload validation ----------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _validator():
    from jsonschema import Draft202012Validator
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def check_document_size(name, document, limit):
    if document_size(document) > limit:
        raise ApiError(413, f"{name} exceeds the {limit // (1024 * 1024)} MiB limit")


def validate_report(report):
    """Validate against report-v3.schema.json. Messages carry only the JSON path and the failing
    keyword, never instance values, because reports may contain sensitive data."""
    if not isinstance(report, dict):
        raise ApiError(422, "report must be a JSON object")
    errors = sorted(_validator().iter_errors(report), key=lambda error: (len(error.absolute_path),
                                                                          list(map(str, error.absolute_path))))
    if errors:
        error = errors[0]
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        raise ApiError(422, f"report does not match schema 3 at {location} ({error.validator})")
    return report


def validate_sbom(sbom):
    if sbom is None:
        return None
    if not isinstance(sbom, dict) or not (sbom.get("bomFormat") == "CycloneDX" or "spdxVersion" in sbom):
        raise ApiError(422, "sbom must be a CycloneDX or SPDX JSON object")
    return sbom


def validate_ci(ci):
    if ci is None:
        return None
    if not isinstance(ci, dict) or set(ci) - {"platform", "run_url"}:
        raise ApiError(422, "ci must be an object with platform and run_url")
    platform, run_url = ci.get("platform"), ci.get("run_url")
    if platform is not None and (not isinstance(platform, str) or len(platform) > 64):
        raise ApiError(422, "ci.platform must be a string of at most 64 characters")
    if run_url is not None and not http_url(run_url):
        raise ApiError(422, "ci.run_url must be an http or https URL")
    return {"platform": platform, "run_url": run_url}


def http_url(value, schemes=("http", "https")):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in schemes and bool(parts.hostname) and not any(ch.isspace() for ch in value)


# Scans ----------------------------------------------------------------------------------------

def scan_status(report):
    if report.get("errors"):
        return "incomplete"
    return "passed" if report["policy"]["passed"] else "failed"


def store_scan(db, project, report, *, sbom=None, source="upload", ci=None, job_id=None):
    comparison = report.get("comparison")
    scan = Scan(project_id=project.id, revision=report.get("revision"), branch=report.get("branch"),
                source=source, status=scan_status(report), created_at=utcnow(), target=report["target"],
                tool_version=report["tool"]["version"], policy_passed=bool(report["policy"]["passed"]),
                violations=report["policy"]["violations"], finding_total=len(report["findings"]),
                new_count=comparison["new"] if comparison else None, report_gz=pack(report),
                sbom_gz=pack(sbom) if sbom is not None else None, ci=ci, job_id=job_id)
    db.add(scan)
    db.flush()
    rows = []
    for position, finding in enumerate(report["findings"]):
        package = finding.get("package") or {}
        exception = finding.get("exception") or {}
        rows.append({
            "scan_id": scan.id, "project_id": project.id, "position": position,
            "fingerprint": finding["fingerprint"], "severity": finding["severity"],
            "category": finding["category"], "producer": finding["producer"], "kind": finding["kind"],
            "rule": finding["rule"], "path": finding.get("path"), "package_name": package.get("name"),
            "package_version": package.get("version"), "package_purl": package.get("purl"),
            "is_new": finding.get("new"), "embedded_suppressed": bool(finding.get("suppressed")),
            "embedded_expires": exception.get("expires"),
            "data": json.dumps(finding, separators=(",", ":"), ensure_ascii=False),
        })
    for batch in chunks(rows):
        db.execute(Finding.__table__.insert(), batch)
    return scan


def _exception_join(stmt):
    return stmt.outerjoin(ProjectException, and_(ProjectException.project_id == Finding.project_id,
                                                 ProjectException.fingerprint == Finding.fingerprint))


def suppressed_clause(day):
    """SQL truth value of "currently suppressed": a project exception wins over the report's own
    exception; expired exceptions (on or after `expires`) never suppress."""
    project_active = or_(ProjectException.expires.is_(None), ProjectException.expires > day)
    embedded_active = and_(Finding.embedded_suppressed.is_(True),
                           or_(Finding.embedded_expires.is_(None), Finding.embedded_expires > day))
    return or_(and_(ProjectException.status.is_not(None), project_active),
               and_(ProjectException.status.is_(None), embedded_active))


def active(expires, day):
    return expires is None or expires > day


def zero_counts():
    return {level: 0 for level in SEVERITIES}, {category: 0 for category in CATEGORIES}


def aggregate(db, scan_ids, day=None):
    """Current unsuppressed severity and category counts per scan, plus suppressed totals."""
    day = day or today()
    result = {}
    for scan_id in scan_ids:
        counts, categories = zero_counts()
        result[scan_id] = {"counts": counts, "categories": categories, "suppressed": 0}
    for batch in chunks(scan_ids):
        stmt = _exception_join(select(
            Finding.scan_id, Finding.severity, Finding.category, Finding.embedded_suppressed,
            Finding.embedded_expires, ProjectException.status, ProjectException.expires, func.count()
        ).select_from(Finding)).where(Finding.scan_id.in_(batch)).group_by(
            Finding.scan_id, Finding.severity, Finding.category, Finding.embedded_suppressed,
            Finding.embedded_expires, ProjectException.status, ProjectException.expires)
        for scan_id, severity, category, emb, emb_expires, exc_status, exc_expires, count in db.execute(stmt):
            entry = result[scan_id]
            suppressed = active(exc_expires, day) if exc_status is not None else (emb and active(emb_expires, day))
            if suppressed:
                entry["suppressed"] += count
            else:
                if severity in entry["counts"]:
                    entry["counts"][severity] += count
                if category in entry["categories"]:
                    entry["categories"][category] += count
    return result


def summaries(db, scans, keys, day=None):
    """ScanSummary objects for scans; keys maps project_id -> project key."""
    totals = aggregate(db, [scan.id for scan in scans], day)
    return [summary(scan, keys[scan.project_id], totals[scan.id]) for scan in scans]


def summary(scan, key, totals):
    return {"id": scan.id, "project": key, "revision": scan.revision, "branch": scan.branch,
            "source": scan.source, "status": scan.status, "created_at": iso(scan.created_at),
            "counts": totals["counts"], "categories": totals["categories"],
            "total": sum(totals["counts"].values()), "suppressed": totals["suppressed"],
            "new": scan.new_count, "policy": {"passed": scan.policy_passed, "violations": scan.violations}}


def scan_summary(db, scan, key):
    return summaries(db, [scan], {scan.project_id: key})[0]


def scan_detail(db, scan, key):
    report = unpack(scan.report_gz)
    detail = scan_summary(db, scan, key)
    detail["policy"] = report["policy"]
    producers = db.scalars(select(Finding.producer).where(Finding.scan_id == scan.id).distinct())
    detail.update({"imports": report["imports"], "errors": report["errors"],
                   "comparison": report.get("comparison"), "target": report["target"],
                   "repository": report.get("repository"), "tool": report["tool"], "ci": scan.ci,
                   "job_id": scan.job_id, "has_sbom": scan.sbom_gz is not None,
                   "producers": sorted(producers)})
    return detail


def latest_scans(db, project_ids):
    if not project_ids:
        return {}
    latest = {}
    for batch in chunks(project_ids):
        ids = select(func.max(Scan.id)).where(Scan.project_id.in_(batch)).group_by(Scan.project_id)
        for scan in db.scalars(select(Scan).where(Scan.id.in_(ids))):
            latest[scan.project_id] = scan
    return latest


# Exceptions -----------------------------------------------------------------------------------

def report_exception(row):
    """Exception object as embedded in schema-3 findings (optional keys omitted when empty)."""
    entry = {"status": row.status, "reason": row.reason, "reviewer": row.reviewer}
    for name in ("expires", "ticket", "justification"):
        if getattr(row, name):
            entry[name] = getattr(row, name)
    return entry


def exception_item(row):
    return {"fingerprint": row.fingerprint, "status": row.status, "justification": row.justification,
            "reason": row.reason, "reviewer": row.reviewer, "expires": row.expires, "ticket": row.ticket,
            "created_at": iso(row.created_at), "updated_at": iso(row.updated_at)}


def validate_exception(fingerprint, body):
    if not FINGERPRINT.fullmatch(fingerprint):
        raise ApiError(422, "fingerprint must be 64 lowercase hexadecimal characters")
    status = body.get("status")
    if status not in EXCEPTION_STATUSES:
        raise ApiError(422, "status must be accepted, false_positive or not_affected")
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
        raise ApiError(422, "reason must be 1 to 1000 characters")
    justification = body.get("justification") or None
    if status == "not_affected" and justification not in JUSTIFICATIONS:
        raise ApiError(422, "not_affected requires a CycloneDX VEX justification")
    if justification is not None and justification not in JUSTIFICATIONS:
        raise ApiError(422, "unknown justification")
    expires = body.get("expires") or None
    if expires is not None:
        if not isinstance(expires, str) or not DATE.fullmatch(expires):
            raise ApiError(422, "expires must be a YYYY-MM-DD date")
        try:
            date.fromisoformat(expires)
        except ValueError:
            raise ApiError(422, "expires must be a valid date") from None
    ticket = body.get("ticket") or None
    if ticket is not None and (not isinstance(ticket, str) or len(ticket) > 100):
        raise ApiError(422, "ticket must be at most 100 characters")
    return {"status": status, "reason": reason.strip(), "justification": justification,
            "expires": expires, "ticket": ticket}


def project_exceptions(db, project_id, fingerprints=None):
    stmt = select(ProjectException).where(ProjectException.project_id == project_id)
    if fingerprints is not None:
        found = {}
        for batch in chunks(set(fingerprints)):
            for row in db.scalars(stmt.where(ProjectException.fingerprint.in_(batch))):
                found[row.fingerprint] = row
        return found
    return {row.fingerprint: row for row in db.scalars(stmt)}


def overlay_finding(finding, row, day):
    """Apply the current project exception (row or None) to one report finding."""
    finding = dict(finding)
    if row is not None:
        finding["exception"] = report_exception(row)
        finding["suppressed"] = active(row.expires, day)
    elif finding.get("suppressed") and not active((finding.get("exception") or {}).get("expires"), day):
        finding["suppressed"] = False
    return finding


def finding_item(finding, row, day):
    item = overlay_finding(finding, row, day)
    item["status"] = "suppressed" if item["suppressed"] else "open"
    item["exception"] = item.get("exception")
    return item


def apply_exceptions(report, rows, day=None):
    """Report copy with current project exceptions applied to each finding."""
    day = day or today()
    report = copy.deepcopy(report)
    report["findings"] = [overlay_finding(finding, rows.get(finding["fingerprint"]), day)
                          for finding in report["findings"]]
    return report


def export_exceptions(rows):
    entries = []
    for row in sorted(rows, key=lambda item: item.fingerprint):
        entry = {"fingerprint": row.fingerprint}
        entry.update(report_exception(row))
        entries.append(entry)
    return {"version": 2, "exceptions": entries}


# Jobs -----------------------------------------------------------------------------------------

def checked_path(path, label):
    if not isinstance(path, str) or not path or len(path) > 4096 or "\x00" in path:
        raise ApiError(422, f"{label} must be a non-empty string")
    if unc_or_device(path):
        raise ApiError(422, f"{label} must not be a UNC or device path")
    if not os.path.isabs(path):
        raise ApiError(422, f"{label} must be absolute")
    return path


def inside(path, roots):
    """Containment in admin-configured roots, lexical before resolved (see safety.contained)."""
    return contained(path, roots)


def validate_scan_path(value, scan_roots):
    """Admin-set project scan path: absolute, inside the server scan roots. Empty clears it."""
    if value is None or value == "":
        return None
    path = checked_path(value, "scan_path")
    if not scan_roots:
        raise ApiError(422, "scan_path needs CRAB_SCAN_ROOTS on the server")
    if not inside(path, scan_roots):
        raise ApiError(422, "scan_path is outside the allowed scan roots")
    return os.path.normpath(path)


def check_git_host(parts, git_hosts):
    """Default-deny: the URL host must match a CRAB_GIT_HOSTS entry exactly. An entry without a
    port matches only the scheme's default port. Literal blocked addresses never pass."""
    if not git_hosts:
        raise ApiError(422, "git sources are disabled; list allowed hosts in CRAB_GIT_HOSTS on the server")
    host = parts.hostname.rstrip(".")
    try:
        port = parts.port
    except ValueError:
        raise ApiError(422, "source.url has an invalid port") from None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and blocked_address(address):
        raise ApiError(422, "source.url must not point to a loopback, link-local, multicast or reserved address")
    if not host_allowed(host, port, 443 if parts.scheme == "https" else 80, git_hosts):
        raise ApiError(422, "source.url host is not listed in CRAB_GIT_HOSTS")


def validate_source(source, settings, *, scan_path=None, confined=False):
    """Validate a job or schedule source. `confined` (non-admin) path sources must resolve inside
    the project's `scan_path`; without one they are rejected."""
    if not isinstance(source, dict):
        raise ApiError(422, "source must be an object")
    kind = source.get("type")
    if kind == "path":
        if set(source) - {"type", "path"}:
            raise ApiError(422, "path sources accept only type and path")
        path = checked_path(source.get("path"), "source.path")
        if not settings.scan_roots:
            raise ApiError(422, "path sources are disabled; set CRAB_SCAN_ROOTS on the server")
        if confined and not scan_path:
            raise ApiError(422, "path sources need a project scan_path set by an admin")
        if not inside(path, settings.scan_roots):
            raise ApiError(422, "source.path is outside the allowed scan roots")
        if confined and not inside(path, (scan_path,)):
            raise ApiError(422, "source.path is outside the project's scan_path")
        return {"type": "path", "path": path}
    if kind == "git":
        if set(source) - {"type", "url", "ref"}:
            raise ApiError(422, "git sources accept only type, url and ref")
        url = source.get("url")
        if not http_url(url):
            raise ApiError(422, "source.url must be an http or https URL")
        parts = urlsplit(url)
        if parts.username or parts.password:
            raise ApiError(422, "source.url must not contain credentials")
        check_git_host(parts, settings.git_hosts)
        ref = source.get("ref") or None
        if ref is not None and (not isinstance(ref, str) or not GIT_REF.fullmatch(ref) or ".." in ref):
            raise ApiError(422, "source.ref must be a branch, tag or commit name")
        result = {"type": "git", "url": url}
        if ref:
            result["ref"] = ref
        return result
    raise ApiError(422, "source.type must be path or git")


def check_queue_capacity(db, project_id):
    queued = db.scalar(select(func.count()).select_from(Job).where(Job.project_id == project_id,
                                                                   Job.status == "queued"))
    if queued >= MAX_QUEUED_JOBS:
        raise ApiError(422, f"the project already has {MAX_QUEUED_JOBS} queued jobs")


def check_schedule_capacity(db, project_id):
    count = db.scalar(select(func.count()).select_from(Schedule).where(Schedule.project_id == project_id))
    if count >= MAX_SCHEDULES:
        raise ApiError(422, f"the project already has {MAX_SCHEDULES} schedules")


def validate_options(options):
    options = options or {}
    if not isinstance(options, dict) or set(options) - {"engines", "sbom", "fail_on"}:
        raise ApiError(422, "options accept engines, sbom and fail_on")
    result = {}
    if options.get("engines") is not None:
        engines = options["engines"]
        if not isinstance(engines, str) or not ENGINES.fullmatch(engines):
            raise ApiError(422, "options.engines must be auto, all, none or a comma-separated engine list")
        result["engines"] = engines
    if options.get("sbom") is not None:
        if not isinstance(options["sbom"], bool):
            raise ApiError(422, "options.sbom must be a boolean")
        result["sbom"] = options["sbom"]
    if options.get("fail_on") is not None:
        if options["fail_on"] not in LEVELS:
            raise ApiError(422, "options.fail_on must be a severity level or none")
        result["fail_on"] = options["fail_on"]
    return result


def new_job(project_id, source, options, settings, schedule_id=None):
    return Job(project_id=project_id, status="queued", source=source, options=options,
               requires_git=source["type"] == "git", attempts=0, max_attempts=settings.max_attempts,
               created_at=utcnow(), schedule_id=schedule_id)


def job_item(job, key, *, log=False):
    item = {"id": job.id, "project": key, "status": job.status, "source": job.source, "options": job.options,
            "worker": job.worker, "attempts": job.attempts, "created_at": iso(job.created_at),
            "started_at": iso(job.started_at), "finished_at": iso(job.finished_at), "scan_id": job.scan_id,
            "error": job.error, "schedule_id": job.schedule_id}
    if log:
        item["log"] = job.log
    return item


def bounded_log(log):
    if log is None:
        return None
    if not isinstance(log, str):
        raise ApiError(422, "log must be a string")
    return log[-LOG_LIMIT:]


def requeue_expired(db, now=None):
    """Return jobs whose lease expired to the queue, or fail them once attempts are exhausted."""
    now = now or utcnow()
    expired = and_(Job.status == "running", Job.lease_expires_at < now)
    requeued = db.execute(update(Job).where(expired, Job.attempts < Job.max_attempts).values(
        status="queued", worker=None, token_id=None, lease_expires_at=None,
    ).execution_options(synchronize_session=False)).rowcount
    failed = db.execute(update(Job).where(expired, Job.attempts >= Job.max_attempts).values(
        status="failed", lease_expires_at=None, finished_at=now,
        error="worker lease expired on the final attempt",
    ).execution_options(synchronize_session=False)).rowcount
    return requeued, failed


def touch_worker(db, name, token_id, capabilities=None, job_id=...):
    worker = db.scalar(select(Worker).where(Worker.name == name))
    if worker is None:
        worker = Worker(name=name, capabilities=capabilities or {"git": False}, token_id=token_id)
        db.add(worker)
    worker.last_seen_at = utcnow()
    worker.token_id = token_id
    if capabilities is not None:
        worker.capabilities = capabilities
    if job_id is not ...:
        worker.current_job_id = job_id
    return worker


def claim_job(db, settings, worker_name, git, token_id):
    """Atomically lease the oldest eligible queued job. A conditional UPDATE on status acts as
    compare-and-set, so concurrent claims on any database hand each job to one worker."""
    now = utcnow()
    requeue_expired(db, now)
    worker = touch_worker(db, worker_name, token_id, {"git": bool(git)})
    candidates = select(Job.id).where(Job.status == "queued").order_by(Job.created_at, Job.id).limit(25)
    if not git:
        candidates = candidates.where(Job.requires_git.is_(False))
    for job_id in list(db.scalars(candidates)):
        claimed = db.execute(update(Job).where(Job.id == job_id, Job.status == "queued").values(
            status="running", worker=worker_name, token_id=token_id, attempts=Job.attempts + 1,
            lease_expires_at=now + timedelta(seconds=settings.lease_seconds), started_at=now, error=None,
        ).execution_options(synchronize_session=False)).rowcount
        if claimed == 1:
            worker.current_job_id = job_id
            db.commit()
            job = db.get(Job, job_id)
            db.refresh(job)
            return job
    worker.current_job_id = None
    db.commit()
    return None


def held_job(db, job_id, token_id, worker_name):
    job = db.get(Job, job_id)
    if job is None:
        raise ApiError(404, "job not found")
    if job.status == "cancelled":
        raise ApiError(409, "job was cancelled")
    if job.status != "running" or job.token_id != token_id or (worker_name and job.worker != worker_name):
        raise ApiError(409, "job lease is not held by this worker")
    return job


def heartbeat(db, settings, job_id, token_id, worker_name=None):
    job = db.get(Job, job_id)
    if job is not None and job.status == "cancelled":
        return {"lease_seconds": 0, "cancelled": True}
    job = held_job(db, job_id, token_id, worker_name)
    job.lease_expires_at = utcnow() + timedelta(seconds=settings.lease_seconds)
    touch_worker(db, job.worker, token_id, job_id=job.id)
    db.commit()
    return {"lease_seconds": settings.lease_seconds, "cancelled": False}


def finish_job(db, job, status, *, error=None, log=None, scan_id=None):
    job.status = status
    job.finished_at = utcnow()
    job.lease_expires_at = None
    job.error = error[:ERROR_LIMIT] if error else None
    job.log = bounded_log(log)
    job.scan_id = scan_id
    worker = db.scalar(select(Worker).where(Worker.name == job.worker)) if job.worker else None
    if worker is not None and worker.current_job_id == job.id:
        worker.current_job_id = None
        worker.last_seen_at = utcnow()


def cancel_job(db, job):
    if job.status not in ("queued", "running"):
        raise ApiError(409, f"job is already {job.status}")
    finish_job(db, job, "cancelled", log=job.log)


# Schedules ------------------------------------------------------------------------------------

def parse_cron(text):
    try:
        return CronExpression(text)
    except ValueError as exc:
        raise ApiError(422, str(exc)) from None


def schedule_item(schedule, key):
    return {"id": schedule.id, "project": key, "cron": schedule.cron, "source": schedule.source,
            "options": schedule.options, "enabled": schedule.enabled, "next_run_at": iso(schedule.next_run_at),
            "last_run_at": iso(schedule.last_run_at), "last_job_id": schedule.last_job_id,
            "created_at": iso(schedule.created_at)}


def enqueue_due(db, settings, now=None):
    """Enqueue one job per due schedule. The conditional UPDATE on next_run_at is a compare-and-set:
    when several API instances run this loop, exactly one wins each due slot."""
    now = now or utcnow()
    created = []
    due = db.execute(select(Schedule.id, Schedule.project_id, Schedule.cron, Schedule.next_run_at, Schedule.source,
                            Schedule.options, Schedule.admin_source)
                     .where(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None),
                            Schedule.next_run_at <= now).order_by(Schedule.next_run_at)).all()
    db.commit()
    for schedule_id, project_id, cron, previous, source, options, admin_source in due:
        try:
            following = CronExpression(cron).next_after(now)
        except ValueError:
            following = None
        won = db.execute(update(Schedule).where(Schedule.id == schedule_id, Schedule.next_run_at == previous)
                         .values(next_run_at=following, last_run_at=now)
                         .execution_options(synchronize_session=False)).rowcount
        if won != 1:
            db.rollback()
            continue
        job = new_job(project_id, source, options, settings, schedule_id=schedule_id)
        try:
            scan_path = db.scalar(select(Project.scan_path).where(Project.id == project_id))
            job.source = validate_source(source, settings, scan_path=scan_path, confined=not admin_source)
            job.options = validate_options(options)
        except ApiError as exc:
            job.status, job.finished_at, job.error = "failed", now, f"schedule source rejected: {exc.detail}"
        else:
            try:
                check_queue_capacity(db, project_id)
            except ApiError as exc:
                job.status, job.finished_at, job.error = "failed", now, f"schedule run skipped: {exc.detail}"
        db.add(job)
        db.flush()
        db.execute(update(Schedule).where(Schedule.id == schedule_id).values(last_job_id=job.id)
                   .execution_options(synchronize_session=False))
        db.commit()
        created.append(job.id)
    return created


def prune_login_failures(db, settings, now=None):
    """Delete sign-in failure rows whose window has passed and that hold no active lock."""
    now = now or utcnow()
    horizon = now - timedelta(seconds=settings.login_lockout_seconds)
    return db.execute(delete(LoginFailure).where(
        LoginFailure.first_failure_at < horizon,
        or_(LoginFailure.locked_until.is_(None), LoginFailure.locked_until <= now),
    ).execution_options(synchronize_session=False)).rowcount


# Dashboards -----------------------------------------------------------------------------------

def _top(db, scan_ids, columns, where, day, limit=10):
    if not scan_ids:
        return []
    totals = {}
    for batch in chunks(scan_ids):
        stmt = _exception_join(select(*columns, func.count()).select_from(Finding)).where(
            Finding.scan_id.in_(batch), not_(suppressed_clause(day)), *where).group_by(*columns)
        for row in db.execute(stmt):
            totals[tuple(row[:-1])] = totals.get(tuple(row[:-1]), 0) + row[-1]
    return sorted(totals.items(), key=lambda item: (-item[1], tuple("" if v is None else v for v in item[0])))[:limit]


def _sum(entries):
    counts, categories = zero_counts()
    for entry in entries:
        for level in SEVERITIES:
            counts[level] += entry["counts"][level]
        for category in CATEGORIES:
            categories[category] += entry["categories"][category]
    return counts, categories


def trend(db, project_ids, days, day=None):
    """Daily totals over the window: per day, the latest scan of each project up to that day."""
    end = utcnow().date()
    start = end - timedelta(days=days - 1)
    if not project_ids:
        return [{"date": (start + timedelta(days=i)).isoformat(), "counts": zero_counts()[0]} for i in range(days)]
    window_start = datetime.combine(start, time())
    history = {}
    for batch in chunks(project_ids):
        before = select(func.max(Scan.id)).where(Scan.project_id.in_(batch), Scan.created_at < window_start) \
            .group_by(Scan.project_id)
        rows = db.execute(select(Scan.id, Scan.project_id, Scan.created_at).where(
            Scan.project_id.in_(batch), or_(Scan.created_at >= window_start, Scan.id.in_(before)))
            .order_by(Scan.id)).all()
        for scan_id, project_id, created in rows:
            history.setdefault(project_id, []).append((scan_id, created.date()))
    chosen = {}
    needed = set()
    for project_id, scans in history.items():
        pointer, current = 0, None
        for offset in range(days):
            moment = start + timedelta(days=offset)
            while pointer < len(scans) and scans[pointer][1] <= moment:
                current = scans[pointer][0]
                pointer += 1
            if current is not None:
                chosen.setdefault(offset, []).append(current)
                needed.add(current)
    totals = aggregate(db, sorted(needed), day)
    return [{"date": (start + timedelta(days=offset)).isoformat(),
             "counts": _sum(totals[scan_id] for scan_id in chosen.get(offset, []))[0]} for offset in range(days)]


def breakdown(db, projects, days):
    """Counts, categories, policy states and top lists over each project's latest scan."""
    day = today()
    keys = {project.id: project.key for project in projects}
    latest = latest_scans(db, list(keys))
    scans = [latest[pid] for pid in keys if pid in latest]
    latest_summaries = {scan.project_id: item for scan, item in zip(scans, summaries(db, scans, keys, day))}
    counts, categories = _sum(latest_summaries.values())
    policy = {"passed": 0, "failed": 0, "incomplete": 0}
    for item in latest_summaries.values():
        policy[item["status"]] += 1
    scan_ids = [scan.id for scan in scans]
    rules = _top(db, scan_ids, (Finding.producer, Finding.rule), (), day)
    packages = _top(db, scan_ids, (Finding.package_name, Finding.package_version, Finding.package_purl),
                    (Finding.package_name.is_not(None),), day)
    total_scans = 0
    for batch in chunks(list(keys)):
        total_scans += db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id.in_(batch))) or 0
    return {
        "projects": len(projects), "scans": total_scans, "counts": counts, "categories": categories,
        "policy": policy, "latest": latest_summaries,
        "trend": trend(db, list(keys), days, day),
        "top_rules": [{"producer": producer, "rule": rule, "count": count} for (producer, rule), count in rules],
        "top_packages": [{"name": name, "version": version, "purl": purl, "count": count}
                         for (name, version, purl), count in packages],
    }
