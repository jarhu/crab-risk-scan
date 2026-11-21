import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from crab_risk_scan import pipeline
from crab_risk_scan.pipeline import ScanOptions

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples/demo"


def parse(*argv):
    parser = argparse.ArgumentParser()
    pipeline.add_scan_arguments(parser)
    return parser.parse_args([str(a) for a in argv])


def cli(*args, env=None):
    return subprocess.run([sys.executable, "-m", "crab_risk_scan", *map(str, args)], capture_output=True,
                          text=True, cwd=ROOT, env=env)


class Folder(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()


class OptionTests(Folder):
    def test_defaults(self):
        options = pipeline.options_from_args(parse("repo"))
        self.assertEqual(options, ScanOptions(Path("repo")))
        self.assertTrue(options.offline)
        self.assertEqual(options.engine_timeout, 900)

    def test_full_surface(self):
        engine = self.base / "bin" / "gitleaks"
        args = parse("repo", "--engines", "bandit,gitleaks", "--trivy", "t.json", "--bandit", "b.json",
                     "--sarif", "s.sarif", "--trivy-image", "i.json", "--run-manifest", "run.json",
                     "--revision", "abc123", "--branch", "feature/x", "--repository", "https://example.test/r",
                     "--image", "app:1", "--policy", "p.json", "--exceptions", "e.json", "--fail-on", "none",
                     "--new-since", "base.json", "--epss", "epss.csv.gz", "--kev", "kev.json", "--online",
                     "--cache-dir", self.base / "cache", "--engine-path", f"gitleaks={engine}",
                     "--engine-timeout", "30", "--output", "out.json", "--format", "markdown")
        options = pipeline.options_from_args(args)
        self.assertEqual(options.engines, "bandit,gitleaks")
        self.assertEqual(options.imports, [("trivy", Path("t.json")), ("bandit", Path("b.json")),
                                           ("sarif", Path("s.sarif")), ("trivy-image", Path("i.json"))])
        self.assertEqual((options.revision, options.branch, options.repository, options.image),
                         ("abc123", "feature/x", "https://example.test/r", "app:1"))
        self.assertEqual(options.fail_on, "none")
        self.assertFalse(options.offline)
        self.assertEqual(options.engine_paths, {"gitleaks": engine})
        self.assertEqual(options.engine_timeout, 30)
        self.assertEqual(options.sbom_formats, [])
        self.assertEqual(args.format, "markdown")

    def test_sbom_formats(self):
        self.assertEqual(pipeline.options_from_args(parse("repo", "--sbom")).sbom_formats, ["cyclonedx-json"])
        options = pipeline.options_from_args(parse("repo", "--output", "x.spdx.json", "--output", "r.json"))
        self.assertEqual(options.sbom_formats, ["cyclonedx-json", "spdx-json"])
        options = pipeline.options_from_args(parse("repo", "--output", "bom.cdx.json"))
        self.assertEqual(options.sbom_formats, ["cyclonedx-json"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse("repo", "--sbom", "--inventory", "bom.json")

    def test_invalid_options(self):
        rejected = [("repo", "--repository", "https://user:SYNTHETIC_CANARY@example.test/r"),
                    ("repo", "--repository", "ftp://example.test/r"),
                    ("repo", "--engine-path", "gitleaks=relative/gitleaks"),
                    ("repo", "--engine-path", "unknown=/x"),
                    ("repo", "--engine-timeout", "0"),
                    ("repo", "--fail-on", "severe"),
                    ("repo", "--revision", "bad revision"),
                    ("repo", "--image", "-x")]
        for argv in rejected:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parse(*argv)
        target = self.base / "repo"
        target.mkdir()
        inconsistent = [(target, "--engines", "semgrep"), (target, "--engines", "trivy-image"),
                        (target, "--cache-dir", target / "cache"), (target, "--mojo-grammar", "relative.so"),
                        (target, "--engine-path", f"gitleaks={self.base / 'a'}",
                         "--engine-path", f"gitleaks={self.base / 'b'}")]
        for argv in inconsistent:
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                pipeline.options_from_args(parse(*argv))


class ExecuteTests(Folder):
    def test_exit_statuses(self):
        clean = self.base / "clean"
        clean.mkdir()
        (clean / "ok.py").write_text("print(1)\n")
        self.assertEqual(pipeline.execute(ScanOptions(clean, engines="none")).exit_code, 0)
        result = pipeline.execute(ScanOptions(DEMO, engines="none"))
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.sboms, {})
        self.assertEqual(pipeline.execute(ScanOptions(DEMO, engines="none", fail_on="high")).exit_code, 0)
        self.assertEqual(pipeline.execute(ScanOptions(self.base / "absent", engines="none")).exit_code, 2)
        broken = self.base / "broken.json"
        broken.write_text("{")
        result = pipeline.execute(ScanOptions(clean, engines="none", imports=[("bandit", broken)]))
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.report["imports"][0]["origin"], "report")

    def test_missing_engines(self):
        empty = self.base / "empty"
        empty.mkdir()
        with mock.patch.dict(os.environ, {"CRAB_ENGINE_DIR": str(empty), "PATH": str(empty)}):
            auto = pipeline.execute(ScanOptions(DEMO, engines="auto"))
            required = pipeline.execute(ScanOptions(DEMO, engines="all"))
        self.assertEqual(auto.exit_code, 1)
        imports = {i["producer"]: i for i in auto.report["imports"]}
        self.assertEqual((imports["bandit"]["status"], imports["bandit"]["reason"]), ("skipped", "not_installed"))
        self.assertEqual(imports["bandit"]["origin"], "engine")
        self.assertEqual((imports["shellcheck"]["status"], imports["shellcheck"]["reason"]),
                         ("skipped", "not_applicable"))
        self.assertEqual(required.exit_code, 2)
        failed = {i["producer"] for i in required.report["imports"] if i["status"] == "failed"}
        self.assertEqual(failed, {"bandit", "gitleaks", "checkov"})

    def test_sbom_without_syft_is_an_error(self):
        empty = self.base / "empty"
        empty.mkdir()
        with mock.patch.dict(os.environ, {"CRAB_ENGINE_DIR": str(empty), "PATH": str(empty)}):
            result = pipeline.execute(ScanOptions(DEMO, engines="none", sbom_formats=["cyclonedx-json"]))
        self.assertEqual(result.exit_code, 2)
        self.assertIn({"reason": "sbom_not_installed", "producer": "syft"}, result.report["errors"])
        self.assertNotIn("inventory", result.report)


class OutputTests(Folder):
    def test_output_files_and_directory(self):
        out = self.base / "out"
        run = cli("scan", DEMO, "--engines", "none", "--output", self.base / "single.sarif",
                  "--output-dir", out)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(run.stdout, "")
        self.assertEqual(sorted(p.name for p in out.iterdir()), sorted(pipeline.DIRECTORY_OUTPUTS))
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(json.loads((self.base / "single.sarif").read_text(encoding="utf-8"))["version"], "2.1.0")
        self.assertIn("CRAB-PY-001", (out / "report.csv").read_text(encoding="utf-8"))

    def test_stdout_format_and_unknown_extension(self):
        run = cli("scan", DEMO, "--engines", "none", "--format", "sarif")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads(run.stdout)["version"], "2.1.0")
        target = self.base / "report.txt"
        run = cli("scan", DEMO, "--engines", "none", "--output", target, "--format", "markdown")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("CRAB-CTR-001", target.read_text(encoding="utf-8"))
        run = cli("scan", DEMO, "--engines", "none", "--output", self.base / "report.unknown")
        self.assertEqual(run.returncode, 2)
        self.assertIn("cannot write outputs", run.stderr)

    def test_usage_errors_exit_2(self):
        run = cli("scan", DEMO, "--engines", "semgrep")
        self.assertEqual(run.returncode, 2)
        self.assertIn("unknown engine", run.stderr)

    def test_report_and_gate(self):
        saved = self.base / "demo.json"
        self.assertEqual(cli("scan", DEMO, "--engines", "none", "--output", saved).returncode, 1)
        rendered = self.base / "demo.md"
        run = cli("report", saved, "--output", rendered)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("CRAB-PY-001", rendered.read_text(encoding="utf-8"))
        run = cli("report", saved, "--format", "csv")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("CRAB-CTR-001", run.stdout)
        gate = cli("gate", saved)
        self.assertEqual(gate.returncode, 1, gate.stderr)
        self.assertFalse(json.loads(gate.stdout)["passed"])
        gate = cli("gate", saved, "--fail-on", "high")
        self.assertEqual(gate.returncode, 0, gate.stderr)
        self.assertTrue(json.loads(gate.stdout)["passed"])
        legacy = self.base / "legacy.json"
        legacy.write_text(json.dumps({"schema_version": 2}))
        self.assertEqual(cli("gate", legacy).returncode, 2)
        self.assertEqual(cli("report", legacy, "--format", "json").returncode, 2)

    def test_rules_and_engines_listing(self):
        run = cli("rules")
        self.assertEqual(run.returncode, 0)
        self.assertTrue(Path(run.stdout.strip()).is_file())
        empty = self.base / "empty"
        empty.mkdir()
        env = dict(os.environ, CRAB_ENGINE_DIR=str(empty), PATH=str(empty))
        run = cli("engines", "--json", env=env)
        self.assertEqual(run.returncode, 0, run.stderr)
        rows = {row["name"]: row for row in json.loads(run.stdout)}
        self.assertEqual(rows["opengrep"]["pinned"], "2.0.0")
        self.assertEqual(rows["syft"]["status"], "not_installed")
        self.assertEqual(rows["trivy"]["engines"], ["trivy", "trivy-image"])
