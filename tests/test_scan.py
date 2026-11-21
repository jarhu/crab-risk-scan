import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "crab_risk_scan/schemas/report-v3.schema.json"


def validate(report):
    try:
        import jsonschema
    except ImportError:
        return False
    jsonschema.validate(report, json.loads(SCHEMA.read_text(encoding="utf-8")))
    return True


class ScanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def run_scan(self, status, *extra):
        result = subprocess.run([sys.executable, "-m", "crab_risk_scan", "scan", str(self.root),
                                 "--engines", "none", *extra], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(result.returncode, status, result.stderr + result.stdout[:2000])
        return json.loads(result.stdout)

    def test_demo(self):
        self.root = ROOT / "examples/demo"
        report = self.run_scan(1)
        self.assertEqual(report["schema_version"], 3)
        self.assertEqual(report["target"], "demo")
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual([(f["path"], f["line"], f["rule"], f["severity"], f["kind"]) for f in report["findings"]],
                         [("Dockerfile", 2, "CRAB-CTR-001", "medium", "review"),
                          ("client.py", 4, "CRAB-PY-001", "medium", "review")])
        self.assertEqual(report["imports"], [])
        self.assertFalse(report["policy"]["passed"])
        self.assertEqual(report, self.run_scan(1))
        if not validate(report):
            self.skipTest("jsonschema is not installed")

    def test_clean(self):
        (self.root / "safe.py").write_text('# ssl._create_unverified_context()\nssl.create_default_context()')
        (self.root / "Dockerfile").write_text("FROM builder\nUSER root\nFROM final\nUSER app")
        report = self.run_scan(0)
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(report["findings"], [])
        self.assertTrue(report["policy"]["passed"])

    def test_fail_on_threshold(self):
        (self.root / "Dockerfile").write_text("FROM base\nUSER root")
        self.assertEqual(len(self.run_scan(0, "--fail-on", "high")["findings"]), 1)
        self.assertEqual(len(self.run_scan(1, "--fail-on", "medium")["findings"]), 1)

    def test_incomplete_takes_priority(self):
        (self.root / "bad.py").write_bytes(b"\xff")
        (self.root / "Dockerfile").write_text("FROM base\nUSER root:root")
        report = self.run_scan(2)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["errors"], [{"path": "bad.py", "reason": "UnicodeDecodeError"}])

    def test_missing(self):
        self.root /= "absent"
        self.assertEqual(self.run_scan(2)["errors"][0]["reason"], "expected_directory")

    def test_exclusions(self):
        (self.root / ".git").mkdir()
        (self.root / ".git/hidden.py").write_text("invalid syntax")
        self.assertEqual(self.run_scan(0)["files_scanned"], 0)

    def test_symlink(self):
        (self.root / "ignored.txt").write_text("invalid syntax")
        try:
            (self.root / "copy.py").symlink_to(self.root / "ignored.txt")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation privilege unavailable")
            raise
        self.assertEqual(self.run_scan(0)["files_scanned"], 0)

    def test_limits(self):
        (self.root / "large.py").write_bytes(b" " * (1024 * 1024 + 1))
        (self.root / "broken.py").write_text("if (")
        report = self.run_scan(2)
        self.assertEqual([e["reason"] for e in report["errors"]], ["SyntaxError", "size_limit"])

    def test_target_name_only(self):
        report = self.run_scan(0)
        self.assertEqual(report["target"], self.root.name)
        self.assertNotIn(str(self.root.parent), json.dumps(report))
