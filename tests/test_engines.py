import functools
import hashlib
import http.server
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from crab_risk_scan import engines
from crab_risk_scan.pipeline import ScanOptions


def context(engine, target, work, **overrides):
    files = engines.inventory(target)
    values = dict(engine=engine, executable=Path(sys.executable), target=target, work=work,
                  report=work.root / "report.json", files=files, cache_dir=work.root / "cache", offline=True,
                  image=None, version="1.0.0")
    values.update(overrides)
    return engines.Context(**values)


class Folder(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.target = self.base / "repo"
        self.target.mkdir()

    def workspace(self):
        stack = engines.private_workspace(self.target)
        work = stack.__enter__()
        self.addCleanup(stack.__exit__, None, None, None)
        return work


class CommandTests(Folder):
    def build(self, name, **overrides):
        work = self.workspace()
        ctx = context(name, self.target, work, **overrides)
        return ctx, engines.REGISTRY[name].build(ctx)

    def assert_private(self, ctx, argv):
        # Reports and configuration files live in the private workspace, never in the target.
        for value in argv:
            if value.startswith(str(ctx.work.root)):
                self.assertFalse(Path(value).resolve().is_relative_to(self.target))

    def test_opengrep(self):
        (self.target / "app.ts").write_text("x")
        ctx, (command,) = self.build("opengrep")
        argv = command.argv
        self.assertEqual(argv[1], "scan")
        self.assertEqual(argv[argv.index("--config") + 1], engines.RULE_PACK.name)
        self.assertEqual((ctx.work.cwd / engines.RULE_PACK.name).read_bytes(), engines.RULE_PACK.read_bytes())
        self.assertEqual(argv[argv.index("--output") + 1], str(ctx.report))
        for flag in ("--json", "--no-git-ignore", "--disable-nosem", "--x-ignore-semgrepignore-files"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[-1], str(self.target))
        self.assert_private(ctx, argv)

    def test_bandit_ignores_target_configuration(self):
        (self.target / ".bandit").write_text("[bandit]\nskips = B323\n")
        ctx, (command,) = self.build("bandit")
        argv = command.argv
        ini = Path(argv[argv.index("--ini") + 1])
        self.assertTrue(ini.is_relative_to(ctx.work.cwd))
        self.assertEqual(ini.read_text(), "[bandit]\n")
        self.assertIn("--ignore-nosec", argv)
        self.assertEqual(argv[argv.index("-r") + 1], str(self.target))

    def test_gitleaks(self):
        ctx, (command,) = self.build("gitleaks")
        argv = command.argv
        config = Path(argv[argv.index("--config") + 1])
        self.assertIn("useDefault = true", config.read_text())
        for flag in ("--redact", "--ignore-gitleaks-allow"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--exit-code") + 1], "99")
        self.assertEqual(argv[argv.index("--gitleaks-ignore-path") + 1], str(ctx.work.cwd))
        self.assertEqual(argv[argv.index("--report-path") + 1], str(ctx.report))

    def test_checkov_frameworks_and_offline(self):
        (self.target / "main.tf").write_text("x")
        (self.target / "Dockerfile").write_text("FROM scratch")
        ctx, (command,) = self.build("checkov")
        argv = command.argv
        frameworks = argv[argv.index("--framework") + 1:argv.index("--output")]
        self.assertEqual(frameworks, ["terraform", "dockerfile"])
        for flag in ("--skip-download", "--soft-fail", "--compact", "--quiet"):
            self.assertIn(flag, argv)
        # A separate "--directory" token would make Checkov load the target's .checkov.yaml.
        self.assertIn(f"--directory={self.target}", argv)
        self.assertNotIn("--directory", argv)
        self.assertTrue(Path(argv[argv.index("--config-file") + 1]).is_relative_to(ctx.work.cwd))
        self.assertEqual(command.stdout, ctx.report)

    def test_checkov_helm_framework_only_online(self):
        # Regression (security review F18): `helm template --dependency-update` downloads chart
        # dependencies and writes them into the target, so offline scans must not select helm.
        (self.target / "Chart.yaml").write_text("apiVersion: v2\nname: demo\nversion: 1.0.0\n")
        (self.target / "main.tf").write_text("x")
        files = engines.inventory(self.target)
        self.assertNotIn("helm", engines.checkov_frameworks(files))
        self.assertIn("helm", engines.checkov_frameworks(files, online=True))
        _, (command,) = self.build("checkov")
        self.assertNotIn("helm", command.argv)
        self.assertIn("kubernetes", command.argv)

    def test_shellcheck_norc_and_batches(self):
        for index in range(engines.SHELLCHECK_BATCH + 3):
            (self.target / f"s{index:03}.sh").write_text("echo $HOME\n")
        (self.target / "notes.txt").write_text("x")
        ctx, commands = self.build("shellcheck")
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn("--norc", command.argv)
            self.assertNotIn("-x", command.argv)
            self.assertTrue(command.stdout.is_relative_to(ctx.work.output))
        files = [a for c in commands for a in c.argv[c.argv.index("--") + 1:]]
        self.assertEqual(len(files), engines.SHELLCHECK_BATCH + 3)
        self.assertTrue(all(Path(f).is_relative_to(self.target) and f.endswith(".sh") for f in files))

    def test_psscriptanalyzer(self):
        ctx, (command,) = self.build("psscriptanalyzer")
        argv = command.argv
        self.assertIn("-NoProfile", argv)
        self.assertEqual(argv[argv.index("-File") + 1], str(engines.PSSA_SCRIPT))
        self.assertTrue(engines.PSSA_SCRIPT.is_file())
        self.assertEqual(argv[-3:-1], [str(self.target), str(ctx.report)])
        self.assertIn("PSAvoidUsingPlainTextForPassword", argv[-1].split(","))

    def test_trivy_offline_flags(self):
        ctx, (command,) = self.build("trivy")
        argv = command.argv
        self.assertEqual(argv[1], "filesystem")
        self.assertEqual(argv[argv.index("--cache-dir") + 1], str(ctx.cache_dir / "trivy"))
        for flag in ("--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-version-check"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--pkg-types") + 1], "library")
        self.assertEqual(argv[argv.index("--scanners") + 1], "vuln")
        self.assertTrue(Path(argv[argv.index("--config") + 1]).is_relative_to(ctx.work.cwd))
        self.assertTrue(Path(argv[argv.index("--ignorefile") + 1]).is_relative_to(ctx.work.cwd))
        online = self.build("trivy", offline=False)[1][0].argv
        self.assertNotIn("--skip-db-update", online)
        self.assertNotIn("--offline-scan", online)

    def test_trivy_image_uses_local_sources_offline(self):
        ctx, (command,) = self.build("trivy-image", image="registry.example/app:1")
        argv = command.argv
        self.assertEqual(argv[1], "image")
        self.assertEqual(argv[-2:], ["--", "registry.example/app:1"])
        self.assertEqual(argv[argv.index("--image-src") + 1], "docker,containerd,podman")
        self.assertEqual(argv[argv.index("--pkg-types") + 1], "os,library")

    def test_osv_offline_and_config(self):
        ctx, (command,) = self.build("osv-scanner")
        argv = command.argv
        self.assertEqual(argv[1:3], ["scan", "source"])
        self.assertIn("--offline-vulnerabilities", argv)
        self.assertIn("--no-resolve", argv)
        self.assertTrue(Path(argv[argv.index("--config") + 1]).is_relative_to(ctx.work.cwd))
        env = engines.REGISTRY["osv-scanner"].env(ctx)
        self.assertEqual(env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"], str(ctx.cache_dir / "osv"))


class ClassificationTests(unittest.TestCase):
    def test_exit_statuses(self):
        cases = {
            "opengrep": {0: "complete", 1: "failed", 2: "failed"},
            "bandit": {0: "complete", 1: "complete", 2: "failed"},
            "gitleaks": {0: "complete", 99: "complete", 1: "failed"},
            "checkov": {0: "complete", 1: "failed", 2: "failed"},
            "shellcheck": {0: "complete", 1: "complete", 2: "partial", 3: "failed", 4: "failed"},
            "psscriptanalyzer": {0: "complete", 1: "failed"},
            "trivy": {0: "complete", 1: "failed"},
            "trivy-image": {0: "complete", 1: "failed"},
            "osv-scanner": {0: "complete", 1: "complete", 127: "failed", 128: "skipped", 129: "failed"},
        }
        for name, expected in cases.items():
            for code, status in expected.items():
                with self.subTest(engine=name, code=code):
                    self.assertEqual(engines.REGISTRY[name].classify(code), status)

    def test_selection(self):
        self.assertEqual(engines.parse_selection("auto"), "auto")
        self.assertEqual(engines.parse_selection("bandit, gitleaks,bandit"), "bandit,gitleaks")
        self.assertEqual(engines.selected("gitleaks,bandit"), ["bandit", "gitleaks"])
        self.assertEqual(engines.selected("none"), [])
        with self.assertRaises(ValueError):
            engines.parse_selection("semgrep")
        with self.assertRaises(ValueError):
            engines.parse_selection("trivy-image")
        self.assertEqual(engines.parse_selection("trivy-image", image="app:1"), "trivy-image")


class DiscoveryTests(Folder):
    def fake(self, folder):
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / engines.executable_name("gitleaks")
        path.write_bytes(b"#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
        return path

    def test_rejects_executables_inside_target(self):
        inside = self.fake(self.target / "bin")
        outside = self.fake(self.base / "trusted")
        self.assertEqual(engines.discover("gitleaks", inside, self.target), (None, "invalid_engine_path"))
        self.assertEqual(engines.discover("gitleaks", outside, self.target), (outside, None))
        with mock.patch.dict(os.environ, {"CRAB_ENGINE_DIR": str(inside.parent), "PATH": str(inside.parent)}):
            self.assertEqual(engines.discover("gitleaks", None, self.target), (None, "not_installed"))
        with mock.patch.dict(os.environ, {"CRAB_ENGINE_DIR": str(inside.parent),
                                          "PATH": os.pathsep.join([str(inside.parent), str(outside.parent)])}):
            self.assertEqual(engines.discover("gitleaks", None, self.target), (outside, None))

    def test_order_and_relative_entries(self):
        first = self.fake(self.base / "engines")
        second = self.fake(self.base / "path")
        with mock.patch.dict(os.environ, {"CRAB_ENGINE_DIR": str(first.parent), "PATH": str(second.parent)}):
            self.assertEqual(engines.discover("gitleaks", None, self.target)[0], first)
        with mock.patch.dict(os.environ, {"CRAB_ENGINE_DIR": "relative", "PATH": "relative"}):
            self.assertEqual(engines.discover("gitleaks", None, self.target), (None, "not_installed"))
        self.assertEqual(engines.discover("gitleaks", Path("relative/gitleaks"), self.target),
                         (None, "invalid_engine_path"))

    def test_missing_engines_are_recorded(self):
        (self.target / "app.py").write_text("x = 1\n")
        empty = self.base / "empty"
        empty.mkdir()
        with mock.patch.dict(os.environ, {"CRAB_ENGINE_DIR": str(empty), "PATH": str(empty)}):
            with tempfile.TemporaryDirectory() as work:
                auto = engines.run_engines(ScanOptions(self.target, engines="auto"), Path(work))
                named = engines.run_engines(ScanOptions(self.target, engines="bandit"), Path(work))
        statuses = {producer: (meta["status"], meta.get("reason"), path) for producer, path, meta in auto}
        self.assertEqual(statuses["bandit"], ("skipped", "not_installed", None))
        self.assertEqual(statuses["gitleaks"], ("skipped", "not_installed", None))
        self.assertEqual(statuses["shellcheck"], ("skipped", "not_applicable", None))
        self.assertEqual(statuses["trivy-image"], ("skipped", "not_applicable", None))
        self.assertEqual([p for p, _, _ in auto], ["opengrep", "bandit", "gitleaks", "checkov", "shellcheck",
                                                   "psscriptanalyzer", "trivy", "trivy-image", "osv"])
        self.assertTrue(all(meta["origin"] == "engine" for _, _, meta in auto))
        self.assertEqual(named, [("bandit", None, {"origin": "engine", "version": None, "rule_pack": "bandit-default",
                                                   "status": "failed", "reason": "not_installed"})])


class IsolationTests(Folder):
    def test_restricted_environment_and_private_directories(self):
        work = self.workspace()
        out = work.output / "probe.json"
        script = ("import json, os, sys; json.dump({'env': dict(os.environ), 'cwd': os.getcwd(), "
                  "'stdin': sys.stdin.read() if sys.stdin else ''}, sys.stdout)")
        with mock.patch.dict(os.environ, {"CRAB_SYNTHETIC_SECRET": "SYNTHETIC_CANARY", "TRIVY_CONFIG": "x",
                                          "PATH": os.pathsep.join([str(self.target), os.environ["PATH"]])}):
            outcome = engines.run_isolated([sys.executable, "-c", script], work, timeout=60, target=self.target,
                                           stdout=out, env={"EXTRA": "1"})
        self.assertEqual(outcome.returncode, 0)
        data = json.loads(out.read_text())
        self.assertNotIn("CRAB_SYNTHETIC_SECRET", data["env"])
        self.assertNotIn("TRIVY_CONFIG", data["env"])
        self.assertEqual(data["env"]["EXTRA"], "1")
        self.assertEqual(Path(data["env"]["HOME"]), work.home)
        self.assertEqual(Path(data["cwd"]).resolve(), work.cwd.resolve())
        self.assertEqual(data["stdin"], "")
        path = next(v for k, v in data["env"].items() if k.upper() == "PATH")
        self.assertNotIn(str(self.target), path.split(os.pathsep))

    def test_timeout(self):
        work = self.workspace()
        outcome = engines.run_isolated([sys.executable, "-c", "import time; time.sleep(30)"], work, timeout=1)
        self.assertTrue(outcome.timed_out)
        self.assertIsNone(outcome.returncode)

    def test_workspace_outside_target(self):
        with self.assertRaises(engines.EngineError):
            with engines.private_workspace(self.target, parent=self.target):
                pass


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class Server:
    def __init__(self, folder):
        handler = functools.partial(QuietHandler, directory=str(folder))
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class InstallTests(Folder):
    def setUp(self):
        super().setUp()
        self.files = self.base / "served"
        self.files.mkdir()
        self.server = Server(self.files)
        self.addCleanup(self.server.close)
        self.dest = self.base / "engines"
        self.platform = engines.current_platform()

    def publish(self, name, data):
        (self.files / name).write_bytes(data)
        return f"{self.server.url}/{name}", hashlib.sha256(data).hexdigest()

    def zip_bytes(self, members):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            for name, data in members.items():
                bundle.writestr(name, data)
        return buffer.getvalue()

    def tar_bytes(self, members, *, link=None):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                bundle.addfile(info, io.BytesIO(data))
            if link:
                info = tarfile.TarInfo(link)
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                bundle.addfile(info)
        return buffer.getvalue()

    def lock(self, tool, asset, **extra):
        return {"version": 1, "engines": {tool: dict({"version": "9.9.9", "install": "download",
                                                       "assets": {self.platform: asset}}, **extra)}}

    def install(self, lock, tool):
        return engines.install(self.dest, [tool], self.platform, lock=lock, log=lambda line: None)

    def test_verified_binary_and_archives(self):
        url, digest = self.publish("raw", b"binary")
        (result,) = self.install(self.lock("osv-scanner", {"url": url, "sha256": digest, "format": "binary"}),
                                 "osv-scanner")
        self.assertEqual(result[1], "installed", result)
        self.assertEqual((self.dest / "bin" / engines.executable_name("osv-scanner")).read_bytes(), b"binary")
        url, digest = self.publish("pkg.zip", self.zip_bytes({"dir/gitleaks.exe": b"zip", "lib.dll": b"dll",
                                                              "README": b"x"}))
        asset = {"url": url, "sha256": digest, "format": "zip", "member": "dir/gitleaks.exe", "files": ["lib.dll"]}
        self.assertEqual(self.install(self.lock("gitleaks", asset), "gitleaks")[0][1], "installed")
        self.assertEqual((self.dest / "bin" / engines.executable_name("gitleaks")).read_bytes(), b"zip")
        self.assertTrue((self.dest / "bin" / "lib.dll").is_file())
        self.assertFalse((self.dest / "bin" / "README").exists())
        url, digest = self.publish("pkg.tar.gz", self.tar_bytes({"syft": b"tar", "LICENSE": b"x"}))
        asset = {"url": url, "sha256": digest, "format": "tar.gz", "member": "syft"}
        self.assertEqual(self.install(self.lock("syft", asset), "syft")[0][1], "installed")
        self.assertEqual((self.dest / "bin" / engines.executable_name("syft")).read_bytes(), b"tar")

    def test_checksum_mismatch_installs_nothing(self):
        url, digest = self.publish("raw", b"tampered")
        asset = {"url": url, "sha256": hashlib.sha256(b"original").hexdigest(), "format": "binary"}
        (result,) = self.install(self.lock("trivy", asset), "trivy")
        self.assertEqual(result[1], "failed")
        self.assertIn("SHA-256 mismatch", result[2])
        self.assertFalse((self.dest / "bin" / engines.executable_name("trivy")).exists())
        self.assertEqual(sorted(p.name for p in (self.dest / "bin").iterdir()), [])

    def test_archive_traversal_rejected(self):
        cases = {
            "zip-parent": ("zip", self.zip_bytes({"../evil": b"x", "gitleaks": b"ok"})),
            "zip-absolute": ("zip", self.zip_bytes({"/abs/evil": b"x", "gitleaks": b"ok"})),
            "zip-drive": ("zip", self.zip_bytes({"C:/evil": b"x", "gitleaks": b"ok"})),
            "tar-parent": ("tar.gz", self.tar_bytes({"gitleaks": b"ok", "a/../../evil": b"x"})),
            "tar-link": ("tar.gz", self.tar_bytes({"gitleaks": b"ok"}, link="gitleaks-link")),
        }
        for name, (fmt, data) in cases.items():
            with self.subTest(case=name):
                url, digest = self.publish(name, data)
                asset = {"url": url, "sha256": digest, "format": fmt, "member": "gitleaks"}
                (result,) = self.install(self.lock("gitleaks", asset), "gitleaks")
                self.assertEqual(result[1], "failed", result)
                self.assertFalse((self.base / "evil").exists())
                self.assertFalse((self.dest / "evil").exists())
                self.assertFalse((self.dest / "bin" / engines.executable_name("gitleaks")).exists())

    def test_module_install(self):
        url, digest = self.publish("mod.nupkg", self.zip_bytes({"Mod.psd1": b"@{}", "sub/Mod.dll": b"x"}))
        lock = {"version": 1, "engines": {"psscriptanalyzer": {
            "version": "1.0.0", "install": "module", "module": "Mod", "requires": "pwsh",
            "assets": {"any": {"url": url, "sha256": digest, "format": "zip"}}}}}
        (result,) = self.install(lock, "psscriptanalyzer")
        self.assertEqual(result[1], "installed", result)
        self.assertTrue((self.dest / "modules/Mod/1.0.0/sub/Mod.dll").is_file())

    def test_missing_platform_asset(self):
        lock = {"version": 1, "engines": {"trivy": {"version": "1", "install": "download", "assets": {}}}}
        self.assertEqual(self.install(lock, "trivy")[0][1], "failed")


class LockFileTests(unittest.TestCase):
    def test_pinned_versions_and_digests(self):
        lock = engines.load_lock()["engines"]
        self.assertEqual(set(lock), set(engines.TOOLS))
        pinned = {"opengrep": "2.0.0", "bandit": "1.9.4", "checkov": "3.2.495", "gitleaks": "8.28.0",
                  "syft": "1.32.0", "psscriptanalyzer": "1.24.0"}
        for tool, version in pinned.items():
            self.assertEqual(lock[tool]["version"], version)
        for tool, entry in lock.items():
            with self.subTest(tool=tool):
                if entry["install"] == "pip":
                    self.assertEqual(entry["package"], f"{tool}=={entry['version']}")
                    self.assert_hash_locked(engines.pip_requirements(entry), entry["package"])
                    continue
                expected = {"any"} if entry["install"] == "module" else set(engines.PLATFORMS)
                self.assertEqual(set(entry["assets"]), expected)
                for asset in entry["assets"].values():
                    self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")
                    self.assertTrue(asset["url"].startswith("https://github.com/"))
                    self.assertIn(entry["version"], asset["url"])
                    if asset["format"] != "binary":
                        self.assertIn(asset["format"], ("zip", "tar.gz", "tar.xz"))
                        if entry["install"] == "download":
                            self.assertTrue(asset["member"])

    def assert_hash_locked(self, path, package):
        pins = []
        for block in re.split(r"\n(?=\S)", path.read_text(encoding="utf-8")):
            if block.startswith("#") or not block.strip():
                continue
            requirement = block.split("\\", 1)[0].strip()
            self.assertRegex(requirement, r"^[A-Za-z0-9._-]+==[^\s;]+( ; .+)?$")
            self.assertRegex(block, r"--hash=sha256:[0-9a-f]{64}")
            pins.append(requirement.split(" ;", 1)[0])
        self.assertIn(package, pins)

    def test_rule_pack_languages(self):
        suffixes = engines.rule_pack_suffixes()
        self.assertTrue({".js", ".ts", ".rs"} <= suffixes)


class CacheTests(unittest.TestCase):
    def test_default_cache_dir(self):
        with mock.patch.dict(os.environ, {"CRAB_CACHE_DIR": os.path.abspath("cache-test")}):
            self.assertEqual(engines.default_cache_dir(), Path(os.path.abspath("cache-test")))
        with mock.patch.dict(os.environ):
            os.environ.pop("CRAB_CACHE_DIR", None)
            self.assertEqual(engines.default_cache_dir().name, "crab-risk-scan")


class SbomPathTests(unittest.TestCase):
    def test_absolute_target_paths_become_source_relative(self):
        from crab_risk_scan.sbom import relativize
        for target, separator in ((Path("/home/runner/work/repo"), "/"),
                                  (Path("C:/Users/runner/AppData/Local/Temp/repo"), "\\")):
            native = str(target)
            document = {"metadata": {"component": {"name": "repo"}}, "components": [
                {"type": "file", "name": native + separator + "package-lock.json"},
                {"type": "file", "name": target.as_posix() + "/web/package.json"},
                {"type": "library", "name": "left-pad", "properties": [{"name": "syft:location:0:path",
                                                                       "value": "/package-lock.json"}]},
                {"type": "file", "name": native}]}
            cleaned = relativize(document, target)
            self.assertEqual([c["name"] for c in cleaned["components"]],
                             ["/package-lock.json", "/web/package.json", "left-pad", "/"])
            self.assertNotIn(target.as_posix(), json.dumps(cleaned))
            self.assertNotIn(json.dumps(native)[1:-1], json.dumps(cleaned))


class PipInstallTests(Folder):
    def test_pip_engines_install_hash_locked_wheels_in_isolated_mode(self):
        # Regression (security review F14, F19): pip engines installed unhashed packages, and
        # `python -m venv`/`-m pip` ran with the caller's working directory on sys.path.
        dest = self.base / "engines"
        dest.mkdir()
        entry = engines.load_lock()["engines"]["bandit"]
        calls = []
        with mock.patch("crab_risk_scan.engines.subprocess.run",
                        side_effect=lambda argv, **kw: calls.append((argv, kw))), \
                mock.patch("crab_risk_scan.engines._write_file"), \
                mock.patch("crab_risk_scan.engines._windows_launcher", return_value=b""):
            engines._install_pip("bandit", entry, dest)
        (venv_argv, venv_kw), (pip_argv, pip_kw) = calls
        self.assertEqual(venv_argv[1:4], ["-I", "-m", "venv"])
        self.assertEqual(pip_argv[1:4], ["-I", "-m", "pip"])
        self.assertEqual((venv_kw["cwd"], pip_kw["cwd"]), (dest, dest))
        for flag in ("--require-hashes", "--no-deps", "--only-binary"):
            self.assertIn(flag, pip_argv)
        self.assertEqual(Path(pip_argv[pip_argv.index("-r") + 1]), engines.pip_requirements(entry))
        self.assertNotIn(entry["package"], pip_argv)


class DeadlineTests(Folder):
    def test_engine_timeout_bounds_all_commands_together(self):
        # Regression (security review F21): each command got the full timeout, so ShellCheck's
        # batches could run for (batches x timeout) seconds.
        work = self.workspace()
        nap = engines.Command([sys.executable, "-c", "import time; time.sleep(0.7)"])
        engine = engines.Engine("napper", "napper", "napper", "none", lambda ctx: [nap, nap, nap],
                                lambda code: "complete", lambda files, options: True)
        ctx = context("napper", self.target, work)
        started = time.monotonic()
        self.assertEqual(engines.run_engine(engine, ctx, 1), ("failed", "timeout"))
        self.assertLess(time.monotonic() - started, 2.5)
