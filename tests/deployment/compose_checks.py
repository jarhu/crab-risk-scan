"""Exercise the deployed HTTP API and its standard worker over Compose."""
import io
import json
import os
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]


class API:
    def __init__(self, address):
        self.base = "http://" + address + "/api/v1"
        self.session = None

    def request(self, path, body=None, *, token=None, raw=False):
        headers = {"Content-Type": "application/json"}
        if token or self.session:
            headers["Authorization"] = "Bearer " + (token or self.session)
        req = urllib.request.Request(self.base + path, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        with urllib.request.urlopen(req, timeout=45) as response:
            data = response.read()
        return data if raw else json.loads(data)


def parallel(count, operation):
    barrier = threading.Barrier(count, timeout=15)

    def start(index):
        barrier.wait()
        return operation(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(start, range(count)))


def verify_postgres(api, compose, worker, job_body, report):
    job = api.request("/projects/smoke/jobs", job_body)
    claim = api.request("/workers/claim", {"worker": "retry"}, token=worker)
    assert claim["lease_protocol"] == 2 and claim["job"]["id"] == job["id"], claim
    payload = {"worker": "retry", "attempt": claim["job"]["attempts"], "report": report}
    path = f"/jobs/{job['id']}/complete"
    results = parallel(2, lambda _: api.request(path, payload, token=worker)["scan_id"])
    assert results[0] == results[1] == api.request(f"/jobs/{job['id']}")["scan_id"], results
    count = compose("exec", "-T", "db", "psql", "-U", "crab", "-d", "crab", "-Atc",
                    f"SELECT count(*) FROM scans WHERE job_id = {int(job['id'])}", capture=True)
    assert count == "1", count

    # Different usernames share the two-attempt client budget over real concurrent HTTP connections.
    def login(index):
        try:
            api.request("/auth/login", {"username": f"unknown-{index}", "password": "fixture-failure"})
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                assert int(exc.headers["Retry-After"]) > 0
            return exc.code
        raise AssertionError("invalid login succeeded")

    statuses = sorted(parallel(4, login))
    assert statuses == [401, 401, 429, 429], statuses
    return {"completion_scan_ids": results, "rows_for_job": int(count), "login_statuses": statuses}


def verify_exports(api, job):
    scan = f"/scans/{job['scan_id']}"
    detail = api.request(scan)
    assert detail["job_id"] == job["id"] and detail["has_sbom"] and not detail["errors"]
    assert detail["status"] == "failed" and detail["source"] == "job", detail["status"]
    sbom = api.request(scan + "/sbom")
    assert sbom["bomFormat"] == "CycloneDX"
    assert ("crab-demo-leaf", "1.0.0") in {(x["name"], x["version"]) for x in sbom["components"]}
    markdown = api.request(scan + "/report?format=markdown", raw=True).decode()
    assert markdown.startswith("# CRAB") and "CRAB-PY-001" in markdown
    with zipfile.ZipFile(io.BytesIO(api.request(scan + "/report?format=docx", raw=True))) as doc:
        assert doc.testzip() is None
        xml = ElementTree.fromstring(doc.read("word/document.xml"))
        assert "CRAB-PY-001" in "".join(xml.itertext())
    return {"job_id": job["id"], "scan_id": job["scan_id"], "component": "crab-demo-leaf@1.0.0",
            "exports": ["markdown", "docx"]}


def run_stack(backend, project, env, target, report):
    password = secrets.token_hex(20)
    env = dict(env, CRAB_SCAN_DIR=str(target.parent), CRAB_ADMIN_USERNAME="admin",
               CRAB_ADMIN_PASSWORD=secrets.token_hex(20), POSTGRES_PASSWORD=password,
               CRAB_LOGIN_MAX_FAILURES_PER_CLIENT="2", CRAB_WORKERS="1", CRAB_WORKER_TOKEN="",
               CRAB_BIND="127.0.0.1", CRAB_PORT="0", CRAB_GIT_HOSTS="", COMPOSE_PROFILES="",
               CRAB_DATABASE_URL=f"postgresql+psycopg://crab:{password}@db:5432/crab" if backend == "postgres" else "")
    args = ["docker", "compose", "--env-file", os.devnull, "-p", project, "-f", str(ROOT / "compose.yaml"),
            "-f", str(ROOT / "tests/deployment/compose.smoke.yaml")]
    if backend == "postgres":
        args += ["--profile", "postgres"]

    def compose(*options, capture=False):
        result = subprocess.run([*args, *options], env=env, check=True, text=True,
                                stdout=subprocess.PIPE if capture else None)
        return result.stdout.strip() if capture else None

    try:
        compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "api")
        api = API(compose("port", "api", "8080", capture=True))
        api.session = api.request("/auth/login", {"username": "admin", "password": env["CRAB_ADMIN_PASSWORD"]})["token"]
        worker = api.request("/tokens", {"name": "smoke-worker", "scopes": ["worker"]})["token"]
        env["CRAB_WORKER_TOKEN"] = worker
        api.request("/projects", {"key": "smoke", "name": "Offline smoke", "scan_path": "/scan/inventory"})
        job_body = {"source": {"type": "path", "path": "/scan/inventory"},
                    "options": {"engines": "none", "sbom": True}}
        job = api.request("/projects/smoke/jobs", job_body)
        compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", "worker")
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            job = api.request(f"/jobs/{job['id']}")
            if job["status"] in {"succeeded", "failed", "cancelled"}:
                break
            time.sleep(1)
        assert job["status"] == "succeeded" and job["attempts"] == 1, (job["status"], job.get("error"))
        result = verify_exports(api, job)
        if backend == "sqlite":
            query = ("import sqlite3; db=sqlite3.connect('file:/var/lib/crab/crab.db?mode=ro', uri=True); "
                     "print(db.execute('SELECT count(*) FROM scans WHERE job_id=?', "
                     f"({int(job['id'])},)).fetchone()[0])")
            assert compose("exec", "-T", "api", "python", "-c", query, capture=True) == "1"
        if backend == "postgres":
            db_id = compose("ps", "-q", "db", capture=True)
            result["postgres_image"] = subprocess.check_output(
                ["docker", "inspect", "-f", "{{.Config.Image}}", db_id], text=True).strip()
            compose("stop", "worker")
            result.update(verify_postgres(api, compose, worker, job_body, report))
        return result
    finally:
        compose("down", "--volumes", "--timeout", "10")
