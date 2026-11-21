import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from crab_risk_scan.adapters import checkov, gitleaks, sarif
from crab_risk_scan.evidence import assign_fingerprints, fingerprint, purl_key
from test_reports import cli, validate


def sarif_result(rule="G204", uri="cmd.go", line=2, **extra):
    location = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
    return dict({"ruleId": rule, "message": {"text": "SYNTHETIC_CANARY"}, "locations": [location]}, **extra)


def sarif_doc(results, rules=(), name="GoSec", **driver):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": dict({"name": name, "rules": list(rules)}, **driver)},
                                          "results": results}]}


class ArchitectureTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.folder = Path(scratch.name)
        self.root = self.folder / "repo"
        self.root.mkdir()

    def save(self, name, doc):
        path = self.folder / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def collect(self, expected, *args):
        run = cli("scan", self.root, "--engines", "none", *args)
        self.assertEqual(run.returncode, expected, run.stderr + run.stdout[:2000])
        self.assertNotIn("SYNTHETIC_CANARY", run.stdout + run.stderr)
        data = json.loads(run.stdout)
        if "schema_version" in data:
            validate(data)
        return data

    def test_scanner_contracts_clean_malformed_partial_and_redaction(self):
        cases = {
            "bandit": ({"results": [], "errors": []}, {"test_id": "B323", "filename": "x.py",
                "line_number": 3, "issue_severity": "MEDIUM", "issue_confidence": "HIGH"}),
            "opengrep": ({"version": "2.0.0", "errors": [], "results": []},
                {"path": "x.ts", "check_id": "test", "extra": {"severity": "WARNING"},
                 "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 8}}),
            "gitleaks": ([], {"RuleID": "test", "File": "x.env", "StartLine": 1, "EndLine": 1,
                               "Secret": "SYNTHETIC_CANARY", "Match": "SYNTHETIC_CANARY"}),
            "checkov": ({"check_type": "terraform", "results": {"failed_checks": []}},
                {"check_id": "CKV_DEMO_1", "file_path": "/main.tf", "repo_file_path": "/main.tf",
                 "resource": "aws.example",
                 "file_line_range": [1, 3], "code_block": [[1, "SYNTHETIC_CANARY"]]}),
            "shellcheck": ([], {"code": 2086, "level": "info", "file": "run.sh", "line": 2,
                                "endLine": 2, "column": 1, "endColumn": 3}),
            "psscriptanalyzer": ([], {"RuleName": "PSAvoidUsingPlainTextForPassword",
                "ScriptPath": "x.ps1", "Severity": "Warning", "Extent": {
                    "StartLineNumber": 2, "EndLineNumber": 2, "StartColumnNumber": 1, "EndColumnNumber": 3}}),
            "sarif": (sarif_doc([]), sarif_result()),
        }
        for engine, (doc, row) in cases.items():
            with self.subTest(engine=engine):
                path = self.save("report.json", doc)
                self.collect(0, "--" + engine, path)
                rows = doc if isinstance(doc, list) else doc["runs"][0]["results"] if engine == "sarif" \
                    else doc["results"]
                if engine == "checkov":
                    rows = rows["failed_checks"]
                rows.append(row)
                self.save("report.json", doc)
                hit, = self.collect(1, "--" + engine, path)["findings"]
                self.assertEqual(hit["producer"], "gosec" if engine == "sarif" else engine)
                rows.append({"ruleId": "G204", "ruleIndex": 7} if engine == "sarif" else {})
                self.save("report.json", doc)
                self.assertEqual(self.collect(2, "--" + engine, path)["findings"], [])

    def test_source_grouping_and_producer_partial(self):
        call = "ssl._create_unverified_context()"
        (self.root / "x.py").write_text(f"({call}, {call})")
        start = 1
        row = {"test_id": "B323", "filename": "x.py", "line_number": 1, "line_range": [1],
               "col_offset": start, "end_col_offset": start + len(call),
               "issue_severity": "MEDIUM", "issue_confidence": "HIGH", "code": "SYNTHETIC_CANARY"}
        path = self.save("bandit.json", {"results": [row], "errors": [{"reason": "SYNTHETIC_CANARY"}]})
        doc = self.collect(2, "--bandit", path)
        # Two identical calls on one line stay distinct observations.
        self.assertEqual(len({f["fingerprint"] for f in doc["findings"]}), 3)
        self.assertEqual(sorted(len(g["observations"]) for g in doc["groups"]), [1, 2])
        self.assertEqual(doc["imports"][0]["status"], "partial")

    def test_inserted_line_keeps_fingerprint_and_exception(self):
        # Regression: docs/gap-analysis.md section 2, an inserted line dropped the suppression.
        source = "import ssl\nctx = ssl._create_unverified_context()\n"
        (self.root / "client.py").write_text(source)
        (self.root / "Dockerfile").write_text("FROM scratch\nUSER root\n")

        def bandit(line):
            return self.save("bandit.json", {"errors": [], "results": [
                {"test_id": "B323", "filename": "client.py", "line_number": line, "line_range": [line],
                 "col_offset": 6, "end_col_offset": 38, "issue_severity": "MEDIUM", "issue_confidence": "HIGH"}]})

        first = self.collect(1, "--bandit", bandit(2))
        exceptions = self.save("exceptions.json", {"version": 2, "exceptions": [
            {"fingerprint": f["fingerprint"], "status": "accepted", "reason": "Reviewed fixture",
             "reviewer": "security-team", "ticket": "SEC-1"} for f in first["findings"]]})
        self.assertEqual(self.collect(0, "--bandit", bandit(2), "--exceptions", exceptions)["policy"]["suppressed"],
                         3)
        (self.root / "client.py").write_text("# inserted comment\n\n" + source)
        (self.root / "Dockerfile").write_text("# syntax=docker/dockerfile:1\nFROM scratch\nUSER root\n")
        moved = self.collect(0, "--bandit", bandit(4), "--exceptions", exceptions)
        self.assertEqual(sorted(f["fingerprint"] for f in moved["findings"]),
                         sorted(f["fingerprint"] for f in first["findings"]))
        self.assertEqual({f["line"] for f in moved["findings"]}, {3, 4})
        self.assertTrue(all(f["suppressed"] and f["exception"]["ticket"] == "SEC-1" for f in moved["findings"]))
        self.assertEqual(moved["policy"]["stale_exceptions"], [])
        # Changing the flagged line itself is a different observation.
        (self.root / "client.py").write_text("import ssl\nctx = ssl._create_unverified_context(  )  # x\n")
        changed = self.collect(1, "--bandit", bandit(2), "--exceptions", exceptions)
        self.assertEqual(len(changed["policy"]["stale_exceptions"]), 2)

    def test_gitleaks_cloud_credential_fails_high_threshold(self):
        # Regression: docs/gap-analysis.md section 2, aws-access-token had severity unknown and exit 0.
        (self.root / "app.env").write_text("KEY=SYNTHETIC_CANARY\n")
        leaks = self.save("leaks.json", [{"RuleID": "aws-access-token", "File": "app.env", "StartLine": 1,
                                          "EndLine": 1, "StartColumn": 5, "EndColumn": 20,
                                          "Secret": "SYNTHETIC_CANARY", "Match": "SYNTHETIC_CANARY"}])
        policy = self.save("policy.json", {"version": 1, "gates": {"secrets": False}})
        doc = self.collect(1, "--gitleaks", leaks, "--fail-on", "high", "--policy", policy)
        hit, = doc["findings"]
        self.assertEqual((hit["severity"], hit["original_severity"], hit["category"]),
                         ("critical", "unknown", "secrets"))
        self.assertEqual(doc["policy"]["violations"], [{"gate": "severity", "count": 1}])

    def test_credential_fingerprints_follow_the_value_with_a_16_bit_tag(self):
        rows = [{"producer": "gitleaks", "rule": "generic-api-key", "path": "a.env", "line": 1, "end_line": 1,
                 "category": "secrets"}]
        (self.root / "a.env").write_text("KEY=placeholder-0001\n")
        first = assign_fingerprints([dict(r) for r in rows], self.root)[0]["fingerprint"]
        (self.root / "a.env").write_text("# moved\nKEY=placeholder-0001\n")
        moved = assign_fingerprints([dict(rows[0], line=2, end_line=2)], self.root)[0]["fingerprint"]
        self.assertEqual(first, moved)
        # Regression (security review F2): a real key swapped in at the same position used to keep the
        # placeholder's fingerprint, so its exception silently suppressed the real key.
        (self.root / "a.env").write_text("# moved\nKEY=real-key-value-0002\n")
        swapped = assign_fingerprints([dict(rows[0], line=2, end_line=2)], self.root)[0]["fingerprint"]
        self.assertNotEqual(first, swapped)
        # Only 16 bits of the line hash enter the fingerprint, so it cannot confirm a guessed value.
        line_hash = hashlib.sha256(b"KEY=real-key-value-0002").hexdigest()
        self.assertEqual(swapped, fingerprint(["gitleaks", "generic-api-key", "a.env", line_hash[:4], 0]))
        # Hard-coded password rules use the credential scheme too (security review F4).
        (self.root / "b.py").write_text('password = "Summer2026!"\n')
        b105 = assign_fingerprints([{"producer": "bandit", "rule": "B105", "path": "b.py", "line": 1,
                                     "end_line": 1, "category": "sast"}], self.root)[0]["fingerprint"]
        tag = hashlib.sha256(b'password = "Summer2026!"').hexdigest()[:4]
        self.assertEqual(b105, fingerprint(["bandit", "B105", "b.py", tag, 0]))
        source = [{"producer": "bandit", "rule": "B1", "path": "a.py", "line": 1, "end_line": 1}]
        (self.root / "a.py").write_bytes(b"x = 1\r\n")
        crlf = assign_fingerprints([dict(r) for r in source], self.root)[0]["fingerprint"]
        (self.root / "a.py").write_bytes(b"x  =  1\n")
        self.assertEqual(crlf, assign_fingerprints([dict(r) for r in source], self.root)[0]["fingerprint"])

    def test_exception_for_a_placeholder_does_not_cover_a_swapped_secret(self):
        leaks = self.save("leaks.json", [{"RuleID": "generic-api-key", "File": "app.env", "StartLine": 1,
                                          "EndLine": 1, "StartColumn": 5, "EndColumn": 24}])
        (self.root / "app.env").write_text("KEY=placeholder-value-01\n")
        hit, = self.collect(1, "--gitleaks", leaks)["findings"]
        exceptions = self.save("exceptions.json", {"version": 2, "exceptions": [
            {"fingerprint": hit["fingerprint"], "status": "false_positive", "reason": "Test placeholder",
             "reviewer": "dev-lead"}]})
        self.assertEqual(self.collect(0, "--gitleaks", leaks, "--exceptions", exceptions)["policy"]["suppressed"], 1)
        (self.root / "app.env").write_text("KEY=SYNTHETIC_CANARY_REAL\n")
        doc = self.collect(1, "--gitleaks", leaks, "--exceptions", exceptions)
        self.assertFalse(doc["findings"][0]["suppressed"])
        self.assertEqual(doc["policy"]["stale_exceptions"], [hit["fingerprint"]])

    def test_checkov_secret_results_drop_the_secret_hash(self):
        secret_hash = "25910f981e85ca04baf359199dd0bd4a3ae738b6"
        (self.root / "config.py").write_text("token = 'value'\n")
        row = {"check_id": "CKV_SECRET_6", "file_path": "/config.py", "repo_file_path": "/config.py",
               "resource": secret_hash, "file_line_range": [1, 1]}
        out = checkov({"check_type": "secrets", "results": {"failed_checks": [row]}}, self.root)
        hit, = out.findings
        self.assertEqual((hit["category"], hit["module"], hit["severity"]), ("secrets", "Sniffer", "high"))
        self.assertNotIn("resource", hit)
        self.assertNotIn(secret_hash, json.dumps(hit))

    def test_checkov_virtual_root_on_windows_and_posix(self):
        rows = [{"check_id": "CKV_AWS_24", "file_path": virtual, "repo_file_path": "/crab-synth/infra/main.tf",
                 "resource": "aws_security_group.demo", "file_line_range": [1, 2]}
                for virtual in ("\\infra\\main.tf", "/infra/main.tf")]
        graph = dict(rows[0], file_path="\\main.tf", file_abs_path=str(self.root / "infra" / "main.tf"))
        foreign = dict(rows[1], file_abs_path=str(self.folder / "elsewhere" / "main.tf"))
        out = checkov({"check_type": "terraform", "results": {"failed_checks": rows + [graph, foreign]}}, self.root)
        self.assertEqual([f["path"] for f in out.findings], ["infra/main.tf"] * 4)

    def test_gitleaks_severity_table(self):
        rows = [{"RuleID": rule, "File": "x.env", "StartLine": 1, "EndLine": 1}
                for rule in ("private-key", "aws-access-token", "gcp-api-key", "github-pat", "generic-api-key",
                             "slack-webhook-url")]
        result = gitleaks(rows, self.root)
        self.assertEqual([(f["rule"], f["severity"]) for f in result.findings],
                         [("private-key", "critical"), ("aws-access-token", "critical"), ("gcp-api-key", "critical"),
                          ("github-pat", "critical"), ("generic-api-key", "medium"), ("slack-webhook-url", "high")])
        self.assertTrue(all(f["original_severity"] == "unknown" and f["cwe"] == ["CWE-798"]
                            for f in result.findings))

    def test_sarif_severity_cwe_help_and_category(self):
        rules = [{"id": "R1", "helpUri": "https://example.test/r1", "properties": {
                     "security-severity": "9.1", "tags": ["external/cwe/cwe-079", "security"]}},
                 {"id": "R2", "defaultConfiguration": {"level": "note"}, "helpUri": "javascript:alert(1)",
                  "relationships": [{"target": {"id": "89", "toolComponent": {"name": "CWE"}}}]},
                 {"id": "R3", "properties": {"tags": ["secrets", "CWE-798"]}, "helpUri": "https://x.test/a b"},
                 {"id": "R4", "properties": {"tags": ["terraform"], "security-severity": "0"},
                  "helpUri": "https://x.test/" + "a" * 2048}]
        results = [sarif_result("R1", line=1), sarif_result("R1", line=2, properties={"security-severity": "4.0"}),
                   sarif_result("R2"), sarif_result("R2", level="error"), sarif_result("R3"), sarif_result("R4"),
                   sarif_result("R5", level="none"), sarif_result("R5"), sarif_result("R6", kind="pass")]
        out = sarif(sarif_doc(results, rules, version="2.22.0"), self.root)
        self.assertFalse(out.partial)
        self.assertEqual(out.version, "2.22.0")
        found = [(f["rule"], f["severity"], f["original_severity"], f["category"], f.get("cwe"), f.get("help_uri"))
                 for f in out.findings]
        self.assertEqual(found, [
            ("R1", "critical", "9.1", "sast", ["CWE-79"], "https://example.test/r1"),
            ("R1", "medium", "4", "sast", ["CWE-79"], "https://example.test/r1"),
            ("R2", "low", "note", "sast", ["CWE-89"], None),
            ("R2", "high", "error", "sast", ["CWE-89"], None),
            ("R3", "medium", "warning", "secrets", ["CWE-798"], None),
            ("R4", "info", "0", "iac", None, None),
            ("R5", "info", "none", "sast", None, None),
            ("R5", "medium", "warning", "sast", None, None)])
        self.assertTrue(all(f["producer"] == "gosec" and f["producer_version"] == "2.22.0" for f in out.findings))
        self.assertNotIn("SYNTHETIC_CANARY", json.dumps(out.findings))

    def test_sarif_locations_runs_and_partial_execution(self):
        inside = (self.root / "src" / "a.c").resolve()
        base = {"SRC": {"uri": self.root.resolve().as_uri() + "/"}}
        first = {"tool": {"driver": {"name": "Clang Static Analyzer!", "semanticVersion": "18.1.0"}},
                 "originalUriBaseIds": base,
                 "invocations": [{"executionSuccessful": False}],
                 "artifacts": [{"location": {"uri": "src/b.c"}}],
                 "results": [
                     {"ruleId": "core.NullDereference", "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "src/a.c", "uriBaseId": "SRC"},
                         "region": {"startLine": 3, "endLine": 4, "startColumn": 2, "endColumn": 9}}}]},
                     {"ruleId": "core.DivideZero", "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": inside.as_uri()}, "region": {"startLine": 5}}}]},
                     {"ruleId": "core.Leak", "locations": [{"physicalLocation": {"artifactLocation": {"index": 0}}}]},
                     {"ruleId": "core.Outside", "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": self.folder.resolve().as_uri() + "/other.c"},
                         "region": {"startLine": 1}}}]},
                     {"ruleId": "core.Remote", "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "https://example.test/x.c"}, "region": {"startLine": 1}}}]},
                     {"ruleId": "core.Nowhere"}]}
        second = {"tool": {"driver": {"name": ""}}, "results": [sarif_result("X1", uri="./lib/x.py")]}
        out = sarif({"version": "2.1.0", "runs": [first, second]}, self.root)
        self.assertTrue(out.partial)
        self.assertIsNone(out.version)
        located = [(f["producer"], f["rule"], f["path"], f["line"], f.get("end_line"), f.get("column"),
                    f.get("end_column")) for f in out.findings]
        self.assertEqual(located, [
            ("clang-static-analyzer", "core.NullDereference", "src/a.c", 3, 4, 2, 9),
            ("clang-static-analyzer", "core.DivideZero", "src/a.c", 5, 5, None, None),
            ("clang-static-analyzer", "core.Leak", "src/b.c", None, None, None, None),
            ("sarif", "X1", "lib/x.py", 2, 2, None, None)])
        with self.assertRaises(ValueError):
            sarif({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}},
                                                 "results": [sarif_result("X", uri="../escape.c")]}]}, self.root)
        with self.assertRaises(ValueError):
            sarif({"version": "2.0.0", "runs": []}, self.root)

    def test_package_url_join_key(self):
        self.assertEqual(purl_key("pkg:PyPI/Django_Rest.Framework@3.0?arch=x#src"),
                         purl_key("pkg:pypi/django-rest-framework@3.0"))
        self.assertEqual(purl_key("pkg:npm/%40Scope/Name", "1.0"), "pkg:npm/@scope/name@1.0")
        self.assertNotEqual(purl_key("pkg:maven/Org/Lib@1"), purl_key("pkg:maven/org/lib@1"))
        self.assertIsNone(purl_key("not-a-purl"))

    def test_correlation_inventory_image_scope_and_exceptions(self):
        trivy = {"SchemaVersion": 2, "ArtifactType": "filesystem", "Results": [
            {"Class": "lang-pkgs", "Type": "npm", "Target": "package-lock.json", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2099-1000", "PkgName": "widget", "InstalledVersion": "1", "Severity": "HIGH"}]}]}
        fs = self.save("trivy.json", trivy)
        osv = {"results": [{"source": {"path": str(self.root / "package-lock.json"), "type": "lockfile"},
               "packages": [{"package": {"name": "widget", "version": "1", "ecosystem": "npm"},
                             "vulnerabilities": [{"id": "GHSA-demo", "aliases": ["CVE-2099-1000"]}]}]}]}
        other = self.save("osv.json", osv)
        images = []
        for char in "ab":
            trivy.update(ArtifactType="container_image", Metadata={"RepoDigests": ["registry/img@sha256:" + char*64]})
            images += ["--trivy-image", self.save(char+".json", trivy)]
        bom = self.save("inventory.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
            {"name": name, "version": "1", "purl": "pkg:npm/" + name + "@1"} for name in ("widget", "clean")]})
        # Supply this source SBOM only to the corresponding source reports.
        args = ["--trivy", fs, "--osv", other, "--inventory", bom]
        doc = self.collect(1, *args)
        self.assertEqual(len(doc["groups"]), 1)
        self.assertEqual([len(c["observations"]) for c in doc["inventory"]["components"]], [2, 0])
        doc = self.collect(1, *args, *images)
        self.assertEqual(sorted(len(g["observations"]) for g in doc["groups"]), [1, 1, 2])
        keys = [f["fingerprint"] for f in doc["findings"]]
        exceptions = self.save("exceptions.json", {"version": 2, "exceptions": [
            {"fingerprint": k, "status": "accepted", "reviewer": "maintainer", "reason": "reviewed fixture"}
            for k in keys]})
        self.collect(0, *args, *images, "--exceptions", exceptions)
        self.collect(0, *args, "--fail-on", "critical")
        data = self.collect(2, *args, *images, "--exceptions", exceptions, "--bandit", self.folder/"missing",
                            "--format", "sarif")
        run, = data["runs"]
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        self.assertEqual(sum(not x.get("properties", {}).get("syntheticLocation") for x in run["results"]), 2)
        self.assertTrue(all(x["suppressions"] for x in run["results"]))
        osv["results"][0]["source"]["path"] = "elsewhere/package-lock.json"
        self.save("osv.json", osv)
        self.assertEqual(len(self.collect(1, *args)["groups"]), 2)
        baseline = self.save("baseline.json", {"version": 1, "suppressions": [
            {"fingerprint": k, "reviewer": "maintainer", "reason": "reviewed fixture"} for k in keys]})
        run = cli("scan", self.root, "--engines", "none", *args, "--exceptions", baseline)
        self.assertEqual(run.returncode, 2)
        self.assertIn({"reason": "invalid_exceptions"}, json.loads(run.stdout)["errors"])
        self.assertIn("version 1", run.stderr)

    def test_manifest_provenance_and_failed_producer(self):
        self.save("leaks.json", [])
        entry = {"producer": "gitleaks", "version": "8.24.3", "rule_pack": "team-v1",
                 "status": "complete", "file": "leaks.json"}
        manifest = self.save("run.json", {"version": 1, "revision": "abc", "reports": [
            entry, dict(entry, status="failed", file="missing.json"),
            {"producer": "checkov", "version": None, "rule_pack": None, "status": "skipped",
             "reason": "not_installed"}]})
        doc = self.collect(2, "--run-manifest", manifest)
        self.assertEqual(doc["revision"], "abc")
        self.assertEqual([(i["origin"], i["status"]) for i in doc["imports"]],
                         [("manifest", "complete"), ("manifest", "failed"), ("manifest", "skipped")])
        self.assertEqual(doc["imports"][0]["rule_pack"], "team-v1")
        self.assertEqual(doc["imports"][2]["reason"], "not_installed")
        self.assertEqual([e["reason"] for e in doc["errors"]], ["producer_failed"])

    def test_html_forms(self):
        (self.root / "form.html").write_text('<!-- <form action="http://test"> -->\n<form action="/save">')
        self.collect(0)
        (self.root / "form.html").write_text('<FORM action="http://example.invalid/save">')
        hit, = self.collect(1)["findings"]
        self.assertEqual((hit["rule"], hit["kind"], hit["cwe"]), ("CRAB-HTML-001", "review", ["CWE-319"]))
        (self.root / "form.html").write_text('<form action="http://a.test"></form><form action="http://b.test">')
        self.assertEqual(len(self.collect(1)["groups"]), 2)

    @unittest.skipUnless(os.getenv("CRAB_MOJO_GRAMMAR"), "requires optional Pinch parsers")
    def test_parser_gates(self):
        flags = ["--mojo-grammar", os.environ["CRAB_MOJO_GRAMMAR"]]
        sql = self.root / "table.sql"
        sql.write_text("GRANT SELECT ON TABLE sample TO reader;")
        mojo = self.root / "demo.mojo"
        mojo.write_text('fn main():\n    # external_call["demo", Int]()\n    pass\n')
        self.collect(0, *flags)
        sql.write_text("GRANT SELECT ON TABLE sample TO PUBLIC;")
        mojo.write_text('fn main():\n    external_call["demo", Int]()\n')
        doc = self.collect(1, *flags)
        self.assertEqual({f["rule"] for f in doc["findings"]}, {"CRAB-SQL-001", "CRAB-MOJO-001"})
        sql.write_text("GRANT SELECT ON TABLE")
        mojo.write_text("fn main(:\n")
        self.assertEqual(len(self.collect(2, *flags)["errors"]), 2)
