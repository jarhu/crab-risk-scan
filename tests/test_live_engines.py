"""Run the pinned source engines through `scan` in CI.

The CI job installs them with `crab-risk-scan engines install --dest DIR` and sets CRAB_ENGINE_DIR=DIR/bin.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from test_reports import cli


def engine_run(test, target, engines, status, *extra):
    run = cli("scan", target, "--engines", engines, *extra)
    test.assertEqual(run.returncode, status, run.stderr + run.stdout[:3000])
    report = json.loads(run.stdout)
    for entry in report["imports"]:
        test.assertEqual((entry["origin"], entry["status"]), ("engine", "complete"), entry)
        test.assertIsNotNone(entry["producer_version"])
    return report


@unittest.skipUnless(os.getenv("CRAB_ENGINE_DIR"), "requires engines installed with `engines install`")
class LiveEngineTests(unittest.TestCase):
    def test_opengrep_language_pack(self):
        files = {
            "browser.js": ("node.innerHTML = html;", "node.textContent = html;"),
            "server.js": ("child_process.exec(command);", "child_process.execFile(file, args);"),
            "wrapper.ts": ("function render(x: string) { node.innerHTML = x; }",
                           "function render(x: string) { node.textContent = x; }"),
            "widget.tsx": ("const el = <div dangerouslySetInnerHTML={{__html: html}} />;",
                           "const el = <div>{html}</div>;"),
            "lib.rs": ("unsafe fn cast(x: u32) -> f32 { std::mem::transmute(x) }",
                       "fn cast(x: u32) -> f32 { f32::from_bits(x) }"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "src"
            target.mkdir()
            for name, (positive, clean) in files.items():
                (target / name).write_text(positive)
                (target / ("safe_" + name)).write_text(clean)
            # Target-controlled ignore files must not hide results.
            (target / ".semgrepignore").write_text("*\n")
            (target / ".gitignore").write_text("*\n")
            report = engine_run(self, target, "opengrep", 1)
            self.assertEqual(report["imports"][0]["rule_pack"], "crab-opengrep-v1")
            hits = report["findings"]
            self.assertEqual({hit["path"] for hit in hits}, set(files))
            self.assertEqual(len(hits), len(files))
            self.assertTrue(all(hit["rule"].startswith("crab-") for hit in hits))

    def test_bandit_and_shellcheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "client.py").write_text("import ssl\nssl._create_unverified_context()  # nosec\n")
            (root / "script.sh").write_text('#!/bin/bash\necho $HOME\necho "$HOME"\n')
            (root / ".shellcheckrc").write_text("disable=SC2086\n")
            (root / ".bandit").write_text("[bandit]\nskips = B323\n")
            report = engine_run(self, root, "bandit,shellcheck", 1)
            self.assertEqual({f["producer"] for f in report["findings"]}, {"crab", "shellcheck", "bandit"})
            self.assertIn(2, [len(g["observations"]) for g in report["groups"]])

    def test_auto_records_every_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("print('ok')\n")
            run = cli("scan", root, "--engines", "auto")
            report = json.loads(run.stdout)
            statuses = {i["producer"]: (i["status"], i.get("reason")) for i in report["imports"]}
            self.assertEqual(statuses["bandit"], ("complete", None))
            self.assertEqual(statuses["shellcheck"], ("skipped", "not_applicable"))
            self.assertEqual(statuses["trivy-image"], ("skipped", "not_applicable"))
            self.assertTrue(all(i["origin"] == "engine" for i in report["imports"]))
