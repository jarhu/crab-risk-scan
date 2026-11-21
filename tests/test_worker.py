import argparse
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from crab_risk_scan import worker as worker_module
from crab_risk_scan.worker import Client, Heartbeat, JobError, Worker

ROOT = Path(__file__).resolve().parents[1]
ADMIN_PASSWORD = "admin-password-1"

try:
    import uvicorn

    from crab_risk_scan.server.app import create_app
    from crab_risk_scan.server.config import Settings
    SERVER = True
except ImportError:  # the server extra is optional
    SERVER = False


class WorkerUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(os.path.realpath(self.temp.name)) / "repos"
        (self.root / "demo").mkdir(parents=True)
        self.worker = Worker(Client("http://127.0.0.1:9", "crab_x"), "unit", scan_roots=[self.root],
                             stream=io.StringIO())

    def tearDown(self):
        self.temp.cleanup()

    def test_path_sources_are_confined(self):
        self.assertEqual(self.worker.resolve_path(str(self.root / "demo")), self.root / "demo")
        for path in (str(self.root / "demo" / ".." / ".."), "relative", str(self.root / "missing")):
            with self.subTest(path=path), self.assertRaises(JobError):
                self.worker.resolve_path(path)
        closed = Worker(Client("http://127.0.0.1:9", "crab_x"), "unit", stream=io.StringIO())
        with self.assertRaisesRegex(JobError, "disabled"):
            closed.resolve_path(str(self.root / "demo"))

    def test_git_requires_opt_in_and_safe_inputs(self):
        beat = Heartbeat(None, 1, "unit", 30, io.StringIO())
        with self.assertRaisesRegex(JobError, "--allow-git"):
            self.worker.checkout("https://example.com/r.git", None, self.root / "c", beat)
        git = Worker(Client("http://127.0.0.1:9", "crab_x"), "unit", allow_git=True, stream=io.StringIO())
        for url, ref in (("file:///etc", None), ("https://u:p@example.com/r.git", None),
                         ("https://example.com/r.git", "--upload-pack=x"), ("https://example.com/r.git", "a/../b")):
            with self.subTest(url=url, ref=ref), self.assertRaises(JobError):
                git.checkout(url, ref, self.root / "c", beat)

    def test_scan_command(self):
        output = Path(self.temp.name) / "out"
        command = self.worker.command(self.root / "demo", output, {"engines": "none", "sbom": True, "fail_on": "high"},
                                      revision="a" * 40, branch="main", repository="https://example.com/r")
        self.assertEqual(command[:5], [sys.executable, "-m", "crab_risk_scan", "scan", str(self.root / "demo")])
        self.assertEqual(command[5:], ["--output", str(output / "report.json"), "--sbom", "--output",
                                       str(output / "sbom.cdx.json"), "--engines", "none", "--fail-on", "high",
                                       "--revision", "a" * 40, "--branch", "main", "--repository",
                                       "https://example.com/r"])
        with self.assertRaises(JobError):
            self.worker.command(self.root, output, {"engines": "auto --policy x"})
        with self.assertRaises(JobError):
            self.worker.command(self.root, output, {"fail_on": "severe"})

    def test_path_sources_reject_unc_and_device_paths_without_resolving(self):
        original = os.path.realpath

        def guarded(path, *args, **kwargs):
            text = os.fspath(path)
            if len(text) >= 2 and text[0] in "\\/" and text[1] in "\\/":
                raise AssertionError(f"realpath called for {text!r}")
            return original(path, *args, **kwargs)
        with mock.patch("os.path.realpath", side_effect=guarded):
            for path in ("\\\\attacker.example\\share", "//attacker.example/share", "\\\\?\\UNC\\host\\share",
                         "\\\\.\\pipe\\crab", "\\\\?\\" + str(self.root / "demo")):
                with self.subTest(path=path), self.assertRaisesRegex(JobError, "UNC or device"):
                    self.worker.resolve_path(path)
        outside = str(Path(self.temp.name) / "elsewhere")

        def outside_guard(path, *args, **kwargs):
            if os.fspath(path).startswith(outside):
                raise AssertionError("realpath called for the job path")
            return original(path, *args, **kwargs)
        with mock.patch("os.path.realpath", side_effect=outside_guard):
            with self.assertRaisesRegex(JobError, "outside"):
                self.worker.resolve_path(outside)

    def git_worker(self, git_hosts=()):
        return Worker(Client("http://127.0.0.1:9", "crab_x"), "unit", allow_git=True, git_hosts=git_hosts,
                      stream=io.StringIO())

    @staticmethod
    def resolved(*addresses):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 443))
                for a in addresses]

    def test_git_runs_with_a_minimal_environment_and_a_pinned_address(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout="a" * 40 + "\n", stderr="")
        beat = Heartbeat(None, 1, "unit", 30, io.StringIO())
        directory = Path(self.temp.name) / "checkout"
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "SYNTHETIC_SECRET", "HTTPS_PROXY": "http://proxy:1",
                                          "GIT_ASKPASS": "/bin/askpass"}), \
                mock.patch.object(worker_module.shutil, "which", return_value="git"), \
                mock.patch.object(worker_module.socket, "getaddrinfo", return_value=self.resolved("93.184.216.34")), \
                mock.patch.object(worker_module.subprocess, "run", side_effect=run):
            revision = self.git_worker((("example.com", None),)).checkout("https://Example.com/r.git", "main",
                                                                          directory, beat)
        self.assertEqual(revision, "a" * 40)
        self.assertEqual(len(calls), 4)
        allowed = {"PATH", "HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT",
                   "GIT_LFS_SKIP_SMUDGE", "GIT_ALLOW_PROTOCOL", "SYSTEMROOT", "TEMP", "TMP"}
        for command, kwargs in calls:
            env = kwargs["env"]
            self.assertLessEqual(set(env), allowed)
            self.assertEqual((env["GIT_CONFIG_NOSYSTEM"], env["GIT_CONFIG_GLOBAL"], env["GIT_ALLOW_PROTOCOL"]),
                             ("1", os.devnull, "http:https"))
            self.assertEqual(env["HOME"], str(Path(self.temp.name) / "git-home"))
            self.assertNotIn("SYNTHETIC_SECRET", json.dumps(env))
            pairs = {command[i + 1] for i, part in enumerate(command) if part == "-c"}
            for setting in ("credential.helper=", "http.followRedirects=false", "filter.lfs.smudge=",
                            "filter.lfs.process=", "filter.lfs.required=false", "submodule.recurse=false",
                            "protocol.allow=never", "protocol.http.allow=always", "protocol.https.allow=always",
                            "http.curloptResolve=example.com:443:93.184.216.34"):
                self.assertIn(setting, pairs)

    def test_git_rejects_internal_addresses_and_unlisted_hosts(self):
        beat = Heartbeat(None, 1, "unit", 30, io.StringIO())
        directory = Path(self.temp.name) / "checkout"
        for addresses in (("127.0.0.1",), ("169.254.169.254",), ("93.184.216.34", "10.0.0.1", "::1"),
                          ("fe80::1",), ("0.0.0.0",), ("224.0.0.1",), ("240.0.0.1",), ("::ffff:127.0.0.1",)):
            with self.subTest(addresses=addresses), \
                    mock.patch.object(worker_module.shutil, "which", return_value="git"), \
                    mock.patch.object(worker_module.socket, "getaddrinfo", return_value=self.resolved(*addresses)), \
                    mock.patch.object(worker_module.subprocess, "run", side_effect=AssertionError("git ran")):
                with self.assertRaisesRegex(JobError, "loopback"):
                    self.git_worker().checkout("https://example.com/r.git", None, directory, beat)
        with mock.patch.object(worker_module.shutil, "which", return_value="git"), \
                mock.patch.object(worker_module.socket, "getaddrinfo", side_effect=AssertionError("resolved")):
            with self.assertRaisesRegex(JobError, "--git-host"):
                self.git_worker((("git.example.com", None),)).checkout("https://example.com/r.git", None,
                                                                       directory, beat)
            with self.assertRaisesRegex(JobError, "--git-host"):
                self.git_worker((("example.com", None),)).checkout("https://example.com:8443/r.git", None,
                                                                   directory, beat)

    def test_git_failures_are_reported_as_categories_without_stderr(self):
        beat = Heartbeat(None, 1, "unit", 30, io.StringIO())
        directory = Path(self.temp.name) / "checkout"
        stderr = "fatal: could not read Username for 'https://example.com': terminal prompts disabled SYNTHETIC_SECRET"

        def run(command, **kwargs):
            code = 128 if "fetch" in command else 0
            return subprocess.CompletedProcess(command, code, stdout="", stderr=stderr if code else "")
        with mock.patch.object(worker_module.shutil, "which", return_value="git"), \
                mock.patch.object(worker_module.socket, "getaddrinfo", return_value=self.resolved("93.184.216.34")), \
                mock.patch.object(worker_module.subprocess, "run", side_effect=run):
            with self.assertRaises(JobError) as caught:
                self.git_worker().checkout("https://example.com/r.git", None, directory, beat)
        self.assertEqual(str(caught.exception), "git fetch failed: authentication required or repository not found")
        self.assertEqual(caught.exception.log, "")
        cases = {"fatal: unable to access 'https://x/': Could not resolve host: x": "could not connect",
                 "fatal: couldn't find remote ref refs/heads/nope": "reference not found",
                 "fatal: unable to access 'https://x/': The requested URL returned error: 403":
                     "authentication required or repository not found",
                 "error: RPC failed; curl 28 Operation timed out": "timed out",
                 "something unexpected": "git failed with status 7"}
        for text, category in cases.items():
            with self.subTest(text=text):
                self.assertEqual(worker_module.git_failure(text, 7), category)

    def test_cli_requires_token_and_http_server(self):
        args = argparse.Namespace(server="http://127.0.0.1:9", token=None, name=None, once=True, poll_interval=1,
                                  allow_git=False, scan_root=[], git_host=[], timeout=10)
        env = dict(os.environ)
        env.pop("CRAB_WORKER_TOKEN", None)
        result = subprocess.run([sys.executable, "-m", "crab_risk_scan", "worker", "--server", "http://127.0.0.1:9",
                                 "--once"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2)
        self.assertIn("CRAB_WORKER_TOKEN", result.stderr)
        args.token, args.server = "crab_x", "ftp://example.com"
        self.assertEqual(worker_module.run(args), 2)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(SERVER, "server extra not installed")
class WorkerEndToEndTests(unittest.TestCase):
    """A live uvicorn server and the real worker command running `scan --engines none`."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        base = Path(cls.temp.name)
        cls.roots = Path(os.path.realpath(base)) / "repos"
        repo = cls.roots / "service"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "app.py").write_text("import subprocess\n\nsubprocess.call('ls', shell=True)\n",
                                             encoding="utf-8")
        (repo / "README.md").write_text("# Synthetic service\n", encoding="utf-8")
        cls.repo = repo
        cls.settings = Settings(database_url=f"sqlite:///{(base / 'crab.db').as_posix()}", data_dir=base,
                                scan_roots=(cls.roots,), admin_password=ADMIN_PASSWORD, scheduler=False,
                                lease_seconds=3, static_dir=base / "static")
        cls.app = create_app(cls.settings)
        cls.port = free_port()
        cls.server = uvicorn.Server(uvicorn.Config(cls.app, host="127.0.0.1", port=cls.port, log_level="warning",
                                                   lifespan="on"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 30
        while not cls.server.started:
            if time.monotonic() > deadline or not cls.thread.is_alive():
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.05)
        cls.url = f"http://127.0.0.1:{cls.port}"
        cls.admin = Client(cls.url, cls.login())
        cls.admin.request("POST", "/projects", {"key": "service", "name": "Service",
                                                "repository_url": "https://example.com/service"})
        cls.token = cls.admin.request("POST", "/tokens", {"name": "worker", "scopes": ["worker"]})[1]["token"]

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(30)
        cls.app.state.engine.dispose()
        cls.temp.cleanup()

    @classmethod
    def login(cls):
        import urllib.request
        request = urllib.request.Request(cls.url + "/api/v1/auth/login", method="POST",
                                         data=json.dumps({"username": "admin", "password": ADMIN_PASSWORD}).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())["token"]

    def enqueue(self, path, options=None):
        return self.admin.request("POST", "/projects/service/jobs",
                                  {"source": {"type": "path", "path": str(path)},
                                   "options": options or {"engines": "none"}})[1]

    def run_worker(self, *extra):
        return subprocess.run([sys.executable, "-m", "crab_risk_scan", "worker", "--server", self.url,
                               "--token", self.token, "--name", "e2e", "--once", "--poll-interval", "1", *extra],
                              cwd=ROOT, capture_output=True, text=True, timeout=600)

    def test_worker_runs_a_scan_and_uploads_the_report(self):
        job = self.enqueue(self.repo)
        result = self.run_worker("--scan-root", str(self.roots))
        self.assertEqual(result.returncode, 0, result.stderr)
        detail = self.admin.request("GET", f"/jobs/{job['id']}")[1]
        self.assertEqual(detail["status"], "succeeded", detail)
        self.assertEqual(detail["worker"], "e2e")
        scan = self.admin.request("GET", f"/scans/{detail['scan_id']}")[1]
        self.assertEqual(scan["source"], "job")
        self.assertEqual(scan["target"], "service")
        self.assertEqual(scan["repository"], "https://example.com/service")
        self.assertNotIn(str(self.roots), json.dumps(scan))
        self.assertIn(scan["status"], ("passed", "failed"))
        report = self.admin.request("GET", f"/scans/{detail['scan_id']}/report?format=json")
        self.assertEqual(report[1]["schema_version"], 3)
        workers = self.admin.request("GET", "/workers")[1]["items"]
        self.assertIn(("e2e", None), [(w["name"], w["current_job"]) for w in workers])

    def test_worker_rejects_paths_outside_its_scan_roots(self):
        other = self.roots / "narrow"
        other.mkdir(exist_ok=True)
        job = self.enqueue(self.repo)
        result = self.run_worker("--scan-root", str(other))
        self.assertEqual(result.returncode, 1)
        detail = self.admin.request("GET", f"/jobs/{job['id']}")[1]
        self.assertEqual(detail["status"], "failed")
        self.assertIn("outside this worker's scan roots", detail["error"])

    def test_empty_queue_exits_cleanly(self):
        result = self.run_worker("--scan-root", str(self.roots))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_heartbeat_observes_cancellation(self):
        job = self.enqueue(self.repo)
        client = Client(self.url, self.token)
        status, claim = client.request("POST", "/workers/claim", {"worker": "hb", "capabilities": {"git": False}})
        self.assertEqual((status, claim["job"]["id"]), (200, job["id"]))
        beat = Heartbeat(client, job["id"], "hb", claim["lease_seconds"], io.StringIO())
        beat.start()
        try:
            time.sleep(1.5)
            self.assertEqual(self.admin.request("GET", f"/jobs/{job['id']}")[1]["status"], "running")
            self.admin.request("POST", f"/jobs/{job['id']}/cancel")
            self.assertTrue(beat.cancelled.wait(10))
            self.assertFalse(beat.lost)
        finally:
            beat.stop()


if __name__ == "__main__":
    unittest.main()
