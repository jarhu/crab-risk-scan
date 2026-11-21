import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import jsonschema

from crab_risk_scan import runner

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/report-v3.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "crab_risk_scan/schemas/report-v3.schema.json").read_text(encoding="utf-8"))
TOKEN = "SYNTHETIC_CANARY_TOKEN_1234"
CI_PREFIXES = ("GITHUB_", "GITLAB_", "CI_", "BUILD_", "SYSTEM_", "RUNNER_")
CI_NAMES = ("GITLAB_CI", "TF_BUILD", "JENKINS_URL", "CRAB_TOKEN", "CHANGE_BRANCH", "BRANCH_NAME",
            "GIT_BRANCH", "GIT_COMMIT", "GIT_URL", "WORKSPACE", "CRAB_CACHE_DIR")
EXPECTED = {"report.json", "report.sarif", "report.md", "report.html", "report.csv",
            "gl-code-quality-report.json", "crab-run.json"}


def clean_environ(**extra):
    """The test process environment without any real CI variables."""
    environ = {key: value for key, value in os.environ.items()
               if not key.startswith(CI_PREFIXES) and key not in CI_NAMES}
    environ.update(extra)
    return environ


def parse_outputs(text):
    """Parse GITHUB_OUTPUT's `name<<delimiter` syntax."""
    values, lines = {}, iter(text.splitlines())
    for line in lines:
        name, delimiter = line.split("<<", 1)
        body = []
        for item in lines:
            if item == delimiter:
                break
            body.append(item)
        values[name] = "\n".join(body)
    return values


def result(report=None, exit_code=1, sboms=None):
    return SimpleNamespace(report=copy.deepcopy(report or FIXTURE), sboms=sboms or {}, exit_code=exit_code)


def finding(**fields):
    base = {"fingerprint": "a" * 64, "producer": "opengrep", "rule": "crab-js-eval", "severity": "high",
            "message": "Review dynamic code evaluation.", "path": "src/app.js", "line": 3, "suppressed": False}
    base.update(fields)
    return base


GITHUB = {
    "GITHUB_ACTIONS": "true", "GITHUB_SHA": "4f1c2e9abc", "GITHUB_REF": "refs/heads/main",
    "GITHUB_REF_NAME": "main", "GITHUB_REF_TYPE": "branch", "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example/demo-service", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
    "GITHUB_WORKSPACE": "/home/runner/work/demo-service/demo-service",
}


class PlatformDetection(unittest.TestCase):
    def test_github_push(self):
        platform = runner.detect_platform(GITHUB)
        self.assertEqual(platform, runner.Platform(
            "github", "4f1c2e9abc", "main", "https://github.com/example/demo-service",
            "https://github.com/example/demo-service/actions/runs/123/attempts/2",
            "/home/runner/work/demo-service/demo-service"))

    def test_github_pull_request_and_tag(self):
        pull = runner.detect_platform(GITHUB | {"GITHUB_HEAD_REF": "feature/login", "GITHUB_REF": "refs/pull/7/merge",
                                                "GITHUB_REF_NAME": "7/merge", "GITHUB_REF_TYPE": "branch"})
        self.assertEqual(pull.branch, "feature/login")
        tag = runner.detect_platform(GITHUB | {"GITHUB_REF": "refs/tags/v1.0.0", "GITHUB_REF_NAME": "v1.0.0",
                                               "GITHUB_REF_TYPE": "tag"})
        self.assertIsNone(tag.branch)

    def test_gitlab_merge_request(self):
        platform = runner.detect_platform({
            "GITLAB_CI": "true", "CI_COMMIT_SHA": "b" * 40, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "topic/a",
            "CI_PROJECT_URL": "https://gitlab.example.com/group/demo",
            "CI_PIPELINE_URL": "https://gitlab.example.com/group/demo/-/pipelines/55", "CI_PROJECT_DIR": "/builds/demo"})
        self.assertEqual(platform, runner.Platform(
            "gitlab", "b" * 40, "topic/a", "https://gitlab.example.com/group/demo",
            "https://gitlab.example.com/group/demo/-/pipelines/55", "/builds/demo"))

    def test_gitlab_branch_pipeline(self):
        platform = runner.detect_platform({"GITLAB_CI": "true", "CI_COMMIT_SHA": "c" * 40, "CI_COMMIT_BRANCH": "main"})
        self.assertEqual((platform.name, platform.branch, platform.repository), ("gitlab", "main", None))

    def test_azure_pipelines(self):
        platform = runner.detect_platform({
            "TF_BUILD": "True", "BUILD_SOURCEVERSION": "d" * 40, "BUILD_SOURCEBRANCH": "refs/heads/feature/x",
            "BUILD_REPOSITORY_URI": "https://org@dev.azure.com/org/My%20Project/_git/demo",
            "SYSTEM_COLLECTIONURI": "https://dev.azure.com/org/", "SYSTEM_TEAMPROJECT": "My Project",
            "BUILD_BUILDID": "42", "BUILD_SOURCESDIRECTORY": "/agent/_work/1/s"})
        self.assertEqual(platform, runner.Platform(
            "azure", "d" * 40, "feature/x", "https://dev.azure.com/org/My%20Project/_git/demo",
            "https://dev.azure.com/org/My%20Project/_build/results?buildId=42", "/agent/_work/1/s"))
        pull = runner.detect_platform({"TF_BUILD": "True", "BUILD_SOURCEBRANCH": "refs/pull/3/merge",
                                       "SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/topic"})
        self.assertEqual(pull.branch, "topic")
        tag = runner.detect_platform({"TF_BUILD": "True", "BUILD_SOURCEBRANCH": "refs/tags/v1"})
        self.assertIsNone(tag.branch)

    def test_jenkins_strips_credentials(self):
        platform = runner.detect_platform({
            "JENKINS_URL": "https://ci.example.com/", "GIT_COMMIT": "e" * 40, "GIT_BRANCH": "origin/release/1.2",
            "GIT_URL": f"https://deploy:{TOKEN}@git.example.com/demo.git",
            "BUILD_URL": "https://ci.example.com/job/demo/9/", "WORKSPACE": "/var/jenkins/demo"})
        self.assertEqual(platform, runner.Platform(
            "jenkins", "e" * 40, "release/1.2", "https://git.example.com/demo.git",
            "https://ci.example.com/job/demo/9/", "/var/jenkins/demo"))
        self.assertNotIn(TOKEN, json.dumps(platform.__dict__))
        multibranch = runner.detect_platform({"JENKINS_URL": "https://ci.example.com/", "BRANCH_NAME": "PR-4",
                                              "CHANGE_BRANCH": "topic/b", "GIT_URL": "git@git.example.com:demo.git"})
        self.assertEqual((multibranch.branch, multibranch.repository), ("topic/b", None))

    def test_local_and_priority(self):
        self.assertEqual(runner.detect_platform({}), runner.Platform("local"))
        both = runner.detect_platform(GITHUB | {"JENKINS_URL": "https://ci.example.com/"})
        self.assertEqual(both.name, "github")

    def test_rejects_malformed_values(self):
        platform = runner.detect_platform(GITHUB | {
            "GITHUB_SHA": "abc def", "GITHUB_REF_NAME": "main\n::error::x", "GITHUB_RUN_ID": "1;rm",
            "GITHUB_SERVER_URL": "javascript:alert(1)"})
        self.assertEqual((platform.revision, platform.branch, platform.repository, platform.run_url),
                         (None, None, None, None))

    def test_path_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            sub = Path(folder) / "services" / "api"
            sub.mkdir(parents=True)
            self.assertEqual(runner.path_prefix(sub, folder), "services/api/")
            self.assertEqual(runner.path_prefix(folder, folder), "")
            self.assertEqual(runner.path_prefix(folder, sub), "")
            self.assertEqual(runner.path_prefix(sub, None), "")


class Annotations(unittest.TestCase):
    def test_escaping(self):
        self.assertEqual(runner.github_data("100% done\r\nnext"), "100%25 done%0D%0Anext")
        self.assertEqual(runner.github_property("a:b,c%\nd"), "a%3Ab%2Cc%25%0Ad")
        self.assertEqual(runner.azure_data("50%\r\n"), "50%AZP25%0D%0A")
        self.assertEqual(runner.azure_property("a;b]c%\n"), "a%3Bb%5Dc%AZP25%0A")

    def test_github_annotations_from_fixture(self):
        lines = runner.github_annotations(FIXTURE, 50)
        unsuppressed = [f for f in FIXTURE["findings"] if not f["suppressed"]]
        self.assertEqual(len(lines), len(unsuppressed))
        self.assertTrue(lines[0].startswith(
            "::error file=config/app.env,line=3,endLine=3,col=12,endColumn=32,"
            "title=CRAB critical%3A gitleaks/aws-access-token::Review the credential detector match"))
        self.assertIn(f"Fingerprint {FIXTURE['findings'][0]['fingerprint']}.", lines[0])
        for item in FIXTURE["findings"]:
            if item["suppressed"]:
                self.assertFalse(any(item["fingerprint"] in line for line in lines))
        levels = [line.split(" ", 1)[0].split("::")[1] for line in lines]
        self.assertEqual(levels[:5], ["error"] * 5)
        self.assertIn("warning", levels)
        self.assertEqual(levels[-1], "notice")   # unknown severity
        self.assertEqual(len(runner.github_annotations(FIXTURE, 2)), 2)
        self.assertEqual(runner.github_annotations(FIXTURE, 0), [])

    def test_untrusted_paths_cannot_inject_commands(self):
        report = {"findings": [finding(path="src/a,b:c\n::error::forged.js", message="Line one\nline two 100%",
                                       line=4, end_line=2, column=0)]}
        [line] = runner.github_annotations(report, 5, prefix="web/")
        self.assertNotIn("\n", line)
        self.assertEqual(line.count("::"), 2)
        self.assertIn("file=web/src/a%2Cb%3Ac%0A%3A%3Aerror%3A%3Aforged.js,line=4,title=", line)
        self.assertIn("::Line one%0Aline two 100%25", line)
        self.assertNotIn("endLine", line)   # end line before the start line is dropped
        self.assertNotIn("col=", line)      # column 0 is invalid
        [azure] = runner.azure_annotations(report, 5)
        self.assertNotIn("\n", azure)
        self.assertTrue(azure.startswith("##vso[task.logissue type=error;sourcepath=src/a,b:c%0A::error::forged.js;"
                                         "linenumber=4;code=opengrep/crab-js-eval;]CRAB high: Line one%0A"))

    def test_findings_without_location(self):
        report = {"findings": [finding(path=None, line=None, severity="low", producer="trivy-image", rule="CVE-2099-1",
                                       image_digest="sha256:" + "f" * 64,
                                       package={"name": "zlib", "version": "1.0"}, fixed_version="1.1")]}
        [line] = runner.github_annotations(report, 1)
        self.assertTrue(line.startswith("::notice title=CRAB low%3A trivy-image/CVE-2099-1::"))
        self.assertIn("Package zlib@1.0. Fixed in 1.1. Image sha256:", line)
        [azure] = runner.azure_annotations(report, 1)
        self.assertTrue(azure.startswith("##vso[task.logissue type=warning;code=trivy-image/CVE-2099-1;]"))

    def test_azure_annotations_from_fixture(self):
        lines = runner.azure_annotations(FIXTURE, 3)
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith(
            "##vso[task.logissue type=error;sourcepath=config/app.env;linenumber=3;columnnumber=12;"
            "code=gitleaks/aws-access-token;]CRAB critical: "))


class Publishing(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.out = self.root / "results"

    def tearDown(self):
        self.folder.cleanup()

    def finish(self, scan=None, environ=None, **kwargs):
        stdout, stderr = io.StringIO(), io.StringIO()
        environ = environ if environ is not None else {}
        code = runner.finish(scan or result(), directory=self.root, output_dir=self.out,
                             platform=kwargs.pop("platform", runner.detect_platform(environ)),
                             environ=environ, stdout=stdout, stderr=stderr, **kwargs)
        return code, stdout.getvalue(), stderr.getvalue()

    def run_record(self):
        return json.loads((self.out / "crab-run.json").read_text(encoding="utf-8"))

    def test_artifact_set(self):
        code, stdout, _ = self.finish()
        self.assertEqual(code, 1)
        self.assertEqual({p.name for p in self.out.iterdir()}, EXPECTED)
        self.assertEqual(json.loads((self.out / "report.json").read_text(encoding="utf-8")), FIXTURE)
        self.assertEqual(json.loads((self.out / "report.sarif").read_text(encoding="utf-8"))["version"], "2.1.0")
        self.assertIsInstance(json.loads((self.out / "gl-code-quality-report.json").read_text(encoding="utf-8")), list)
        record = self.run_record()
        self.assertEqual(record["outputs"], ["report.json", "report.sarif", "report.md", "report.html", "report.csv",
                                             "gl-code-quality-report.json"])
        self.assertEqual((record["exit_code"], record["scan_exit_code"], record["platform"]["name"]), (1, 1, "local"))
        self.assertEqual(record["counts"]["critical"], 3)
        self.assertIsNone(record["upload"])
        self.assertIn("Top 10 unsuppressed findings:", stdout)
        self.assertIn("Policy: failed (6 actionable, 2 suppressed)", stdout)
        self.assertIn("Exit status: 1", stdout)

    def test_sbom_and_extra_formats(self):
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        extra = self.root / "extra" / "findings.csv"
        code, _, _ = self.finish(result(sboms={"cyclonedx-json": sbom}), extra_formats=["vex", "json"],
                                 extra_outputs=[extra])
        self.assertEqual(code, 1)
        self.assertEqual({p.name for p in self.out.iterdir()}, EXPECTED | {"sbom.cdx.json", "report.vex.json"})
        self.assertEqual(json.loads((self.out / "sbom.cdx.json").read_text(encoding="utf-8")), sbom)
        self.assertTrue(extra.is_file())
        self.assertIn(str(extra), self.run_record()["outputs"])

    def test_exit_status_semantics(self):
        self.assertEqual(self.finish(no_fail=True)[0], 0)
        self.assertEqual(self.run_record()["exit_code"], 0)
        failed = copy.deepcopy(FIXTURE)
        failed["errors"] = [{"reason": "timeout", "producer": "checkov"}]
        code, stdout, _ = self.finish(result(failed, exit_code=2), no_fail=True)
        self.assertEqual(code, 2)
        self.assertIn("Errors: 1 (timeout)", stdout)
        passed = copy.deepcopy(FIXTURE)
        passed["policy"]["passed"] = True
        self.assertEqual(self.finish(result(passed, exit_code=0))[0], 0)

    def test_artifact_failure_exits_two(self):
        self.out = self.root / "occupied"
        self.out.write_text("not a folder", encoding="utf-8")
        code, _, stderr = self.finish()
        self.assertEqual(code, 2)
        self.assertIn("writing artifacts failed", stderr)

    def test_github_summary_annotations_and_outputs(self):
        summary, outputs = self.root / "summary.md", self.root / "output.txt"
        summary.write_text("existing\n", encoding="utf-8")
        environ = GITHUB | {"GITHUB_WORKSPACE": str(self.root), "GITHUB_STEP_SUMMARY": str(summary),
                            "GITHUB_OUTPUT": str(outputs)}
        code, stdout, _ = self.finish(environ=environ, annotations=4)
        self.assertEqual(code, 1)
        self.assertEqual(sum(line.startswith("::error ") for line in stdout.splitlines()), 4)
        text = summary.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("existing\n"))
        self.assertIn((self.out / "report.md").read_text(encoding="utf-8").strip(), text)
        values = parse_outputs(outputs.read_text(encoding="utf-8"))
        self.assertEqual((values["exit-code"], values["passed"], values["actionable"], values["critical"],
                          values["upload-status"], values["sbom"]), ("1", "false", "6", "3", "not_configured", ""))
        self.assertEqual(Path(values["sarif"]), (self.out / "report.sarif").resolve())
        self.assertEqual(Path(values["results-dir"]), self.out.resolve())
        self.assertTrue(Path(values["run"]).is_file())
        self.assertEqual(self.run_record()["platform"]["run_url"],
                         "https://github.com/example/demo-service/actions/runs/123/attempts/2")
        self.assertNotIn("workspace", self.run_record()["platform"])

    def test_github_annotation_paths_follow_the_workspace(self):
        directory = self.root / "services" / "api"
        directory.mkdir(parents=True)
        stdout = io.StringIO()
        runner.finish(result(), directory=directory, output_dir=self.out,
                      platform=runner.detect_platform(GITHUB | {"GITHUB_WORKSPACE": str(self.root)}),
                      environ={}, stdout=stdout, stderr=io.StringIO(), annotations=1)
        self.assertIn("::error file=services/api/config/app.env,", stdout.getvalue())

    def test_large_markdown_uses_compact_summary(self):
        summary = self.root / "summary.md"
        runner.append_github_summary(summary, "x" * (runner.SUMMARY_LIMIT + 1), "compact")
        self.assertEqual(summary.read_text(encoding="utf-8"), "compact\n\n")
        compact = runner.compact_markdown(FIXTURE, 1)
        self.assertTrue(compact.startswith("## CRAB scan"))
        self.assertIn("exceeds the job summary size limit", compact)

    def test_azure_commands(self):
        environ = {"TF_BUILD": "True", "BUILD_SOURCESDIRECTORY": str(self.root)}
        code, stdout, _ = self.finish(environ=environ, annotations=2)
        self.assertEqual(code, 1)
        lines = stdout.splitlines()
        self.assertEqual(sum(line.startswith("##vso[task.logissue type=error;") for line in lines), 2)
        self.assertIn(f"##vso[task.uploadsummary]{(self.out / 'report.md').resolve()}", lines)

    def test_jenkins_console_summary_is_sanitized(self):
        report = copy.deepcopy(FIXTURE)
        report["findings"][0]["path"] = "config/\x1b[31mapp.env"
        code, stdout, _ = self.finish(result(report), environ={"JENKINS_URL": "https://ci.example.com/"},
                                      annotations=1)
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", stdout)
        self.assertIn("CRITICAL gitleaks/aws-access-token  config/?[31mapp.env:3", stdout)
        self.assertIn("Coverage: 9 of 10 inputs complete; psscriptanalyzer skipped (not_installed)", stdout)


class StubServer:
    """Local CRAB API stub that records requests and replies with a configured status."""

    def __init__(self, status=201, body=None, headers=None):
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                stub.requests.append({"path": self.path, "headers": dict(self.headers),
                                      "body": json.loads(self.rfile.read(length))})
                data = json.dumps(body if body is not None else {}).encode()
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class Upload(Publishing):
    def upload(self, stub, **kwargs):
        kwargs.setdefault("token", TOKEN)
        environ = GITHUB | {"GITHUB_OUTPUT": str(self.root / "output.txt")}
        code, stdout, stderr = self.finish(environ=environ, server=stub.url + "/", project="demo-service",
                                           annotations=0, **kwargs)
        record = (self.out / "crab-run.json").read_text(encoding="utf-8")
        for text in (stdout, stderr, record, (self.root / "output.txt").read_text(encoding="utf-8")):
            self.assertNotIn(TOKEN, text)
        return code, stdout, stderr, json.loads(record)["upload"]

    def test_success(self):
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        with StubServer(201, {"id": 7, "url": "https://crab.example.com/scans/7"}) as stub:
            code, stdout, _, upload = self.upload(stub, scan=result(sboms={"cyclonedx-json": sbom}))
        self.assertEqual(code, 1)
        self.assertEqual((upload["status"], upload["http_status"], upload["scan_id"], upload["url"]),
                         ("uploaded", 201, 7, "https://crab.example.com/scans/7"))
        [request] = stub.requests
        self.assertEqual(request["path"], "/api/v1/projects/demo-service/scans")
        self.assertEqual(request["headers"]["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(request["body"]["report"], FIXTURE)
        self.assertEqual(request["body"]["sbom"], sbom)
        self.assertEqual(request["body"]["source"], "runner")
        self.assertEqual(request["body"]["ci"], {"platform": "github", "run_url":
                         "https://github.com/example/demo-service/actions/runs/123/attempts/2"})
        self.assertIn("Upload: scan 7 stored at https://crab.example.com/scans/7", stdout)
        values = parse_outputs((self.root / "output.txt").read_text(encoding="utf-8"))
        self.assertEqual((values["upload-status"], values["scan-url"]), ("uploaded", "https://crab.example.com/scans/7"))

    def test_unauthorized_is_a_warning(self):
        with StubServer(401, {"detail": "Invalid token\x1b[2J"}) as stub:
            code, stdout, stderr, upload = self.upload(stub)
        self.assertEqual(code, 1)
        self.assertEqual((upload["status"], upload["http_status"], upload["reason"]), ("failed", 401, "http_401"))
        self.assertEqual(upload["detail"], "Invalid token?[2J")
        self.assertIn("warning: upload to", stderr)
        self.assertIn("::warning title=CRAB::upload to", stdout)
        self.assertIn("Upload: failed (http_401)", stdout)

    def test_server_error_without_and_with_require_upload(self):
        with StubServer(503) as stub:
            code, _, _, upload = self.upload(stub)
        self.assertEqual((code, upload["reason"]), (1, "http_503"))
        with StubServer(500) as stub:
            code, _, stderr, upload = self.upload(stub, require_upload=True)
        self.assertEqual((code, upload["reason"]), (2, "http_500"))
        self.assertIn("error: upload to", stderr)
        self.assertEqual(self.run_record()["exit_code"], 2)

    def test_redirects_are_not_followed(self):
        with StubServer(307, headers={"Location": "https://elsewhere.example.com/collect"}) as stub:
            code, _, _, upload = self.upload(stub)
        self.assertEqual((code, upload["reason"], len(stub.requests)), (1, "http_307", 1))

    def test_missing_token_and_unreachable_server(self):
        with StubServer() as stub:
            _, _, _, upload = self.upload(stub, token=None)
        self.assertEqual((upload["reason"], stub.requests), ("missing_token", []))
        with StubServer() as stub:
            url = stub.url
        code, _, _ = self.finish(server=url, project="demo-service", token=TOKEN, require_upload=True)
        self.assertEqual(code, 2)
        self.assertTrue(self.run_record()["upload"]["reason"].startswith("connection_error"))

    def test_upload_validates_inputs(self):
        self.assertEqual(runner.upload("ftp://example.com", "p", TOKEN, {})["reason"], "invalid_server_url")
        self.assertEqual(runner.upload(f"https://u:{TOKEN}@example.com", "p", TOKEN, {})["reason"],
                         "invalid_server_url")
        self.assertEqual(runner.upload("https://example.com", "p\n", TOKEN, {})["reason"], "invalid_project")
        self.assertEqual(runner.upload("https://example.com", "p", "a\nb", {})["reason"], "invalid_token")

    def test_plain_http_to_a_remote_server_sends_nothing(self):
        # Regression (security review F20): the token went out over plain HTTP and only a warning followed.
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("request sent")):
            result = runner.upload("http://crab.example.com", "demo-service", TOKEN, {})
        self.assertEqual(result["reason"], "insecure_server_url")


class CommandLine(unittest.TestCase):
    def run_ci(self, *args, environ=None):
        return subprocess.run([sys.executable, "-m", "crab_risk_scan", "ci", *map(str, args)], capture_output=True,
                              text=True, cwd=ROOT, env=environ or clean_environ())

    def test_help_lists_scan_and_runner_flags(self):
        completed = self.run_ci("--help")
        self.assertEqual(completed.returncode, 0)
        for flag in ("--engines", "--trivy", "--policy", "--exceptions", "--fail-on", "--sbom", "--new-since",
                     "--cache-dir", "--output-dir", "--server", "--token", "--project", "--annotations",
                     "--no-fail", "--require-upload"):
            self.assertIn(flag, completed.stdout)

    def test_usage_errors(self):
        self.assertEqual(self.run_ci("examples/demo", "--server", "https://crab.example.com").returncode, 2)
        self.assertEqual(self.run_ci("examples/demo", "--require-upload").returncode, 2)
        self.assertEqual(self.run_ci("examples/demo", "--server", "ftp://x", "--project", "p").returncode, 2)
        insecure = self.run_ci("examples/demo", "--server", "http://crab.example.com", "--project", "p",
                               "--token", TOKEN)
        self.assertEqual(insecure.returncode, 2)
        self.assertIn("must use https", insecure.stderr)

    def test_end_to_end_on_github(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            out, summary, outputs = folder / "results", folder / "summary.md", folder / "output.txt"
            environ = clean_environ(**(GITHUB | {"GITHUB_WORKSPACE": str(ROOT), "GITHUB_STEP_SUMMARY": str(summary),
                                                 "GITHUB_OUTPUT": str(outputs)}))
            completed = self.run_ci("examples/demo", "--engines", "none", "--trivy", "examples/trivy-fs.json",
                                    "--output-dir", out, environ=environ)
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual({p.name for p in out.iterdir()}, EXPECTED)
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            jsonschema.Draft202012Validator(SCHEMA).validate(report)
            self.assertEqual((report["revision"], report["branch"], report["repository"]),
                             ("4f1c2e9abc", "main", "https://github.com/example/demo-service"))
            self.assertIn("::warning file=examples/demo/Dockerfile,line=2,", completed.stdout)
            self.assertTrue(summary.read_text(encoding="utf-8").strip())
            self.assertEqual(parse_outputs(outputs.read_text(encoding="utf-8"))["exit-code"], "1")
            run = json.loads((out / "crab-run.json").read_text(encoding="utf-8"))
            self.assertEqual((run["platform"]["name"], run["exit_code"]), ("github", 1))

            no_fail = self.run_ci("examples/demo", "--engines", "none", "--trivy", "examples/trivy-fs.json",
                                  "--output-dir", out, "--no-fail", "--revision", "override1")
            self.assertEqual(no_fail.returncode, 0, no_fail.stderr)
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual((report["revision"], report["branch"]), ("override1", None))


if __name__ == "__main__":
    unittest.main()
