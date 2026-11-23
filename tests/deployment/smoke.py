"""Build the operator images, exercise them, and write release qualification evidence."""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from compose_checks import ROOT, run_stack


def output(*args):
    return subprocess.check_output(args, text=True, cwd=ROOT).strip()


def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)


def build(role, image, evidence):
    dockerfile = ROOT / f"deployments/docker/{role}.Dockerfile"
    args = ["INSTALL_PWSH=true", "PREFETCH_DB=true"] if role == "scanner" else []
    metadata = evidence / f"{role}-build.json"
    command = ["docker", "buildx", "build", "--load", "--provenance=false", "--progress=plain",
               "--metadata-file", str(metadata), "-f", str(dockerfile), "-t", image]
    for arg in args:
        command.extend(["--build-arg", arg])
    run(*command, ".")
    digest = json.loads(metadata.read_text())["containerimage.digest"]
    assert digest.startswith("sha256:")
    return {"manifest_digest": digest, "image_id": output("docker", "image", "inspect", "-f", "{{.Id}}", image),
            "build_args": args, "dockerfile": str(dockerfile.relative_to(ROOT)),
            "base_images": [line.split("=", 1)[1] for line in dockerfile.read_text().splitlines()
                            if line.startswith("ARG ") and "_IMAGE=" in line]}


def offline(image, directory, evidence):
    dependencies = directory / "dependencies"
    dependencies.mkdir()
    (dependencies / "requirements.txt").write_text("requests==2.19.0\n")
    args = ["docker", "run", "--rm", "--network", "none", "-v", f"{dependencies}:/target:ro",
            image, "scan", "/target", "--engines", "trivy,osv-scanner"]
    result = subprocess.run(args, stdout=subprocess.PIPE, check=False)
    assert result.returncode == 1, f"offline scan returned {result.returncode} (expected policy exit 1): {result.stdout[-1500:]}"
    report = json.loads(result.stdout)
    expected = {"trivy", "osv"}
    assert not report["errors"] and report["policy"]["passed"] is False
    assert {r["producer"] for r in report["imports"]} == expected
    assert all(r["origin"] == "engine" and r["status"] == "complete" and r["producer_version"]
               for r in report["imports"]), report["imports"]
    findings = report["findings"]
    assert {f["producer"] for f in findings} == expected
    assert all((f["package"]["name"], f["package"]["version"]) == ("requests", "2.19.0") for f in findings)
    (evidence / "offline-report.json").write_bytes(result.stdout)
    # The advisory databases roll independently of the pinned scanner binary. Identify the exact snapshot.
    script = ("import hashlib,json,pathlib; root=pathlib.Path('/opt/crab/cache'); "
              "print(json.dumps({str(p.relative_to(root)):hashlib.file_digest(p.open('rb'),'sha256').hexdigest() "
              "for p in sorted(root.rglob('*')) if p.is_file()}))")
    hashes = json.loads(output("docker", "run", "--rm", "--network", "none", "--entrypoint", "python", image, "-c", script))
    assert hashes
    (evidence / "database-sha256.json").write_text(json.dumps(hashes, indent=2) + "\n")
    return report


def git_pinning(image, project):
    fixture = ROOT / "tests/deployment/git_fixture.py"
    network, server = project + "-git", project + "-origin"
    opts = ["--network", network, "-v", f"{fixture}:/fixture.py:ro", "--entrypoint", "python"]
    run("docker", "network", "create", "--internal", network)
    try:
        run("docker", "run", "-d", "--name", server, "--network-alias", "crab-git.test", *opts,
            image, "/fixture.py", "serve")
        try:
            return output("docker", "run", "--rm", *opts, image, "/fixture.py", "checkout")
        finally:
            run("docker", "rm", "-f", server)
    finally:
        run("docker", "network", "rm", network)


def main(evidence):
    evidence.mkdir(parents=True, exist_ok=False)
    project = "crab-smoke-" + uuid.uuid4().hex[:12]
    images = {role: project + ":" + role for role in ("server", "scanner")}
    inputs = ["compose.yaml", "pyproject.toml", "web/package-lock.json", "crab_risk_scan/engines.lock.json",
              *[str(p.relative_to(ROOT)) for p in sorted((ROOT / "deployments/docker").glob("requirements-*.txt"))],
              *[str(p.relative_to(ROOT)) for p in sorted((ROOT / "crab_risk_scan/engines").glob("*-requirements.txt"))]]
    record = {"commit": output("git", "rev-parse", "HEAD"), "architecture": platform.machine(),
              "docker": output("docker", "--version"), "compose": output("docker", "compose", "version"),
              "buildx": output("docker", "buildx", "version"), "images": {}, "tests": {},
              "input_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in inputs}}
    if os.getenv("GITHUB_RUN_ID"):
        record["ci_run"] = (f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}"
                            f"/actions/runs/{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}")
    try:
        for role, image in images.items():
            record["images"][role] = build(role, image, evidence)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            report = offline(images["scanner"], directory, evidence)
            record["tests"]["network_none"] = {"exit": 1, "findings": len(report["findings"]),
                                                "engines": ["trivy", "osv"]}
            target = directory / "inventory"
            shutil.copytree(ROOT / "examples/inventory", target)
            shutil.copy(ROOT / "examples/demo/client.py", target)
            env = dict(os.environ, SMOKE_SERVER_IMAGE=images["server"], SMOKE_SCANNER_IMAGE=images["scanner"])
            for backend in ("sqlite", "postgres"):
                record["tests"][backend] = run_stack(backend, project + "-" + backend, env, target, report)
            record["tests"]["git_pinning"] = git_pinning(images["scanner"], project)
        record["passed"] = True
    finally:
        record.setdefault("passed", False)
        (evidence / "qualification.json").write_text(json.dumps(record, indent=2) + "\n")
        for image in images.values():
            subprocess.run(["docker", "image", "rm", image], check=False)
    print(json.dumps(record["tests"], indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="new directory for build metadata, reports and test results")
    main(parser.parse_args().evidence.resolve())
