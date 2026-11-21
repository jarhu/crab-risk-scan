"""Run the pinned infrastructure, secrets, dependency and SBOM engines through `scan` in CI.

Requires CRAB_ENGINE_DIR (from `engines install`), pwsh with the installed PSScriptAnalyzer module, and for
the dependency test a CRAB_CACHE_DIR prepared with `crab-risk-scan db update`.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from test_live_engines import engine_run
from test_reports import cli

TOKEN = "ghp_" + "SYNTHETICCANARY0001" + "k7Qz2RmX9vLb4TfNw"  # synthetic, 36 characters after the prefix


@unittest.skipUnless(os.getenv("CRAB_ENGINE_DIR"), "requires engines installed with `engines install`")
class InfrastructureTests(unittest.TestCase):
    def test_terraform_powershell_and_redacted_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src"
            target.mkdir()
            tf = '''resource "aws_security_group" "demo" {
  description = "fixture"
  ingress {
    description = "fixture"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["NETWORK"]
  }
}
'''
            (target / "exposed.tf").write_text(tf.replace("NETWORK", "0.0.0.0/0"))
            (target / "restricted.tf").write_text(tf.replace('"demo"', '"internal"').replace("NETWORK", "10.0.0.0/24"))
            (target / "plain.ps1").write_text("param([string] $Password)\n")
            (target / "secure.ps1").write_text("param([SecureString] $Password)\n")
            (target / "demo.env").write_text(f"GITHUB_TOKEN={TOKEN}\n")
            # Target-controlled configuration that would hide the results above.
            (target / ".gitleaks.toml").write_text('[allowlist]\npaths = [".*"]\n')
            (target / "PSScriptAnalyzerSettings.psd1").write_text("@{ ExcludeRules = @('*') }\n")
            (target / ".checkov.yaml").write_text("skip-check:\n  - CKV_AWS_24\n  - CKV_AWS_23\n")
            report = engine_run(self, target, "checkov,psscriptanalyzer,gitleaks", 1)
            run_text = json.dumps(report)
            self.assertNotIn(TOKEN, run_text)
            self.assertNotIn("SYNTHETICCANARY", run_text)
            hits = report["findings"]
            self.assertIn(("checkov", "exposed.tf"), {(f["producer"], f["path"]) for f in hits})
            self.assertNotIn(("checkov", "restricted.tf", "CKV_AWS_24"),
                             {(f["producer"], f["path"], f["rule"]) for f in hits})
            self.assertEqual({f["path"] for f in hits if f["producer"] == "psscriptanalyzer"}, {"plain.ps1"})
            self.assertEqual({f["path"] for f in hits if f["producer"] == "gitleaks"}, {"demo.env"})

    @unittest.skipUnless(os.getenv("CRAB_CACHE_DIR"), "requires databases prepared with `db update`")
    def test_offline_dependency_engines(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src"
            target.mkdir()
            (target / "requirements.txt").write_text("requests==2.19.0\n")
            report = engine_run(self, target, "trivy,osv-scanner", 1)
            producers = {f["producer"] for f in report["findings"]}
            self.assertEqual(producers, {"trivy", "osv"})
            self.assertTrue(all(f["package"]["name"] == "requests" for f in report["findings"]))
            self.assertTrue(report["imports"][0]["rule_pack"].startswith("trivy-db"))

    def test_sbom_formats_from_one_run(self):
        root = Path(__file__).resolve().parents[1] / "examples/inventory"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run = cli("scan", root, "--engines", "none", "--sbom", "--output", out / "report.json",
                      "--output", out / "bom.spdx.json", "--output-dir", out / "dir")
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            names = {(c["name"], c["version"]) for c in report["inventory"]["components"]}
            self.assertIn(("crab-demo-leaf", "1.0.0"), names)
            spdx = json.loads((out / "bom.spdx.json").read_text(encoding="utf-8"))
            self.assertTrue(spdx["spdxVersion"].startswith("SPDX-"))
            cdx = json.loads((out / "dir" / "sbom.cdx.json").read_text(encoding="utf-8"))
            self.assertEqual(cdx["bomFormat"], "CycloneDX")
            serialized = json.dumps(cdx) + json.dumps(spdx)
            for form in {str(root.parent), root.parent.as_posix(), json.dumps(str(root.parent))[1:-1]}:
                self.assertNotIn(form, serialized)
