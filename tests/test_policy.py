import copy
import gzip
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import jsonschema

from crab_risk_scan import enrich
from crab_risk_scan.policy import (PolicyError, exit_status, license_acceptable, parse_exceptions, parse_policy,
                                   reevaluate)
from crab_risk_scan.reporting import collect
from test_reports import ROOT, cli, validate

SCHEMAS = ROOT / "crab_risk_scan/schemas"
POLICY = {"version": 1, "fail_on": "high", "new_only": False, "include_review": True,
          "gates": {"secrets": True, "malicious": True, "kev": True, "epss": 0.1, "licenses": True,
                    "max": {"medium": 10}},
          "rules": {"disabled": ["shellcheck/SC2086"], "severity": {"gitleaks/generic-api-key": "medium"}},
          "licenses": {"deny": ["AGPL-3.0-only"], "allow": [], "severity": "high"}}
EXCEPTIONS = {"version": 2, "exceptions": [
    {"fingerprint": "a" * 64, "status": "accepted", "reason": "Compensating control", "reviewer": "security-team",
     "expires": "2027-03-31", "ticket": "SEC-42"},
    {"fingerprint": "b" * 64, "status": "not_affected", "justification": "code_not_reachable",
     "reason": "Feature disabled", "reviewer": "platform-team"},
    {"fingerprint": "c" * 64, "status": "false_positive", "reason": "Test fixture", "reviewer": "dev-lead"}]}
TODAY = date(2026, 11, 20)


def schema(name):
    return jsonschema.Draft202012Validator(json.loads((SCHEMAS / name).read_text(encoding="utf-8")),
                                           format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)


class PolicyFileTests(unittest.TestCase):
    def test_documented_examples_parse_and_validate(self):
        schema("policy-v1.schema.json").validate(POLICY)
        schema("exceptions-v2.schema.json").validate(EXCEPTIONS)
        rules = parse_policy(POLICY)
        self.assertEqual((rules.source, rules.fail_on, rules.gates["epss"], rules.gates["max"]),
                         ("policy-file", "high", 0.1, {"medium": 10}))
        self.assertEqual(rules.disabled, {"shellcheck/SC2086"})
        self.assertEqual(rules.deny, {"agpl-3.0-only"})
        entries = parse_exceptions(EXCEPTIONS)
        self.assertEqual(entries["b" * 64]["justification"], "code_not_reachable")
        self.assertEqual(entries["a" * 64], {"status": "accepted", "reason": "Compensating control",
                                             "reviewer": "security-team", "expires": "2027-03-31",
                                             "ticket": "SEC-42"})

    def test_invalid_policies(self):
        cases = [dict(POLICY, version=2), dict(POLICY, extra=True), dict(POLICY, fail_on="severe"),
                 dict(POLICY, new_only="yes"), dict(POLICY, gates={"epss": 2}), dict(POLICY, gates={"epss": True}),
                 dict(POLICY, gates={"unknown": True}), dict(POLICY, gates={"max": {"medium": -1}}),
                 dict(POLICY, rules={"disabled": ["SC2086"]}), dict(POLICY, rules={"severity": {"a/b": "huge"}}),
                 dict(POLICY, licenses={"deny": [" MIT"]}), dict(POLICY, licenses={"severity": "none"}), []]
        validator = schema("policy-v1.schema.json")
        for doc in cases:
            with self.subTest(doc=doc):
                with self.assertRaises(PolicyError) as caught:
                    parse_policy(doc)
                self.assertEqual(caught.exception.reason, "invalid_policy")
                self.assertFalse(validator.is_valid(doc))

    def test_invalid_exceptions_and_v1_baseline(self):
        entry = EXCEPTIONS["exceptions"][0]
        cases = [{"version": 2, "exceptions": [entry, entry]},
                 {"version": 2, "exceptions": [dict(entry, fingerprint="A" * 64)]},
                 {"version": 2, "exceptions": [dict(entry, status="wont_fix")]},
                 {"version": 2, "exceptions": [dict(entry, reason=" ")]},
                 {"version": 2, "exceptions": [dict(entry, expires="2027-02-30")]},
                 {"version": 2, "exceptions": [dict(entry, justification="code_not_present")]},
                 {"version": 2, "exceptions": [dict(EXCEPTIONS["exceptions"][1], justification=None)]},
                 {"version": 2, "exceptions": [dict(entry, note="x")]},
                 {"version": 3, "exceptions": []}]
        validator = schema("exceptions-v2.schema.json")
        for doc in cases:
            with self.subTest(doc=doc):
                with self.assertRaises(PolicyError) as caught:
                    parse_exceptions(doc)
                self.assertEqual(caught.exception.reason, "invalid_exceptions")
                if doc["exceptions"] and doc["exceptions"][0] is not entry:
                    self.assertFalse(validator.is_valid(doc))
        with self.assertRaises(PolicyError) as caught:
            parse_exceptions({"version": 1, "suppressions": []})
        self.assertIn("version 1", str(caught.exception))
        self.assertIn("version 2", str(caught.exception))

    def test_run_manifest_schema(self):
        validator = schema("run-manifest-v1.schema.json")
        good = {"version": 1, "revision": "abc", "reports": [
            {"producer": "bandit", "version": "1.8.6", "rule_pack": "bandit-default", "status": "complete",
             "file": "bandit.json"},
            {"producer": "sarif", "version": "2.22.0", "rule_pack": "gosec", "status": "failed"},
            {"producer": "checkov", "version": None, "rule_pack": None, "status": "skipped",
             "reason": "not_installed"}]}
        validator.validate(good)
        for bad in ({"producer": "bandit", "version": "1", "rule_pack": "x", "status": "complete"},
                    {"producer": "bandit", "version": None, "rule_pack": "x", "status": "complete", "file": "a"},
                    {"producer": "bandit", "version": "1", "rule_pack": "x", "status": "complete",
                     "file": "../a.json"}):
            self.assertFalse(validator.is_valid(dict(good, reports=[bad])))

    def test_license_expressions(self):
        deny, allow = frozenset({"agpl-3.0-only"}), frozenset({"mit", "apache-2.0"})
        self.assertTrue(license_acceptable("MIT OR AGPL-3.0-only", deny, frozenset()))
        self.assertFalse(license_acceptable("MIT AND AGPL-3.0-only", deny, frozenset()))
        self.assertFalse(license_acceptable("agpl-3.0-only", deny, frozenset()))
        self.assertTrue(license_acceptable("(MIT OR GPL-2.0-only) AND Apache-2.0", frozenset(), allow))
        self.assertFalse(license_acceptable("GPL-2.0-only WITH Classpath-exception-2.0", frozenset(), allow))
        self.assertFalse(license_acceptable("Custom License", frozenset(), allow))
        self.assertTrue(license_acceptable("Apache-2.0 WITH LLVM-exception", frozenset(), allow))


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.folder = Path(scratch.name)
        self.root = self.folder / "repo"
        self.root.mkdir()
        (self.root / "Dockerfile").write_text("FROM scratch\nUSER root\n")
        (self.root / "run.sh").write_text("#!/bin/sh\necho $1\n")
        (self.root / "app.env").write_text("TOKEN=SYNTHETIC_CANARY\n")
        self.inputs = [
            ("shellcheck", self.save("shellcheck.json", [
                {"code": 2086, "level": "warning", "file": "run.sh", "line": 2, "endLine": 2, "column": 6,
                 "endColumn": 8}]), {"origin": "report"}),
            ("gitleaks", self.save("gitleaks.json", [
                {"RuleID": "generic-api-key", "File": "app.env", "StartLine": 1, "EndLine": 1}]), {"origin": "report"}),
            ("trivy", self.save("trivy.json", {"SchemaVersion": 2, "ArtifactType": "filesystem", "Results": [
                {"Class": "lang-pkgs", "Type": "npm", "Target": "package-lock.json", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2099-0001", "PkgName": "widget", "InstalledVersion": "1.0.0",
                     "Severity": "LOW"},
                    {"VulnerabilityID": "GHSA-xxxx-0002", "PkgName": "widget", "InstalledVersion": "1.0.0",
                     "Severity": "LOW"}]}]}), {"origin": "report"}),
            ("osv", self.save("osv.json", {"results": [{"source": {"path": "package-lock.json", "type": "lockfile"},
                "packages": [{"package": {"name": "evil", "version": "6.6.6", "ecosystem": "npm"},
                              "vulnerabilities": [{"id": "MAL-2026-0001"}]}]}]}), {"origin": "report"})]
        self.inventory = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                          "metadata": {"component": {"name": "app", "bom-ref": "app"}},
                          "dependencies": [{"ref": "app", "dependsOn": ["w"]}],
                          "components": [
                              {"name": "widget", "version": "1.0.0", "purl": "pkg:npm/widget@1.0.0", "bom-ref": "w",
                               "licenses": [{"expression": "MIT OR AGPL-3.0-only"}]},
                              {"name": "agpl-lib", "version": "2.0.0", "purl": "pkg:npm/agpl-lib@2.0.0",
                               "licenses": [{"license": {"id": "AGPL-3.0-only"}}]},
                              {"name": "odd", "version": "1.0", "licenses": [{"license": {"name": "Custom"}}]}]}

    def save(self, name, doc):
        path = self.folder / name
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def run_collect(self, **options):
        from crab_risk_scan.pipeline import scan
        options.setdefault("today", TODAY)
        report = collect(scan(self.root), root=self.root, inputs=self.inputs, revision="head", **options)
        self.assertNotIn("SYNTHETIC_CANARY", json.dumps(report))
        return validate(report)

    def find(self, report, rule):
        return [f for f in report["findings"] if f["rule"] == rule]

    def test_default_policy_matches_previous_threshold(self):
        report = self.run_collect()
        result = report["policy"]
        self.assertEqual((result["source"], result["minimum_severity"], result["passed"]),
                         ("default", "unknown", False))
        self.assertEqual(result["actionable"], len(report["findings"]))
        self.assertEqual([v["gate"] for v in result["violations"]], ["severity", "secrets", "malicious"])
        self.assertEqual(exit_status(report), 1)
        self.assertEqual(sum(len(g["observations"]) for g in report["groups"]), len(report["findings"]))

    def test_rules_licenses_and_gates(self):
        policy = self.save("policy.json", POLICY)
        report = self.run_collect(policy=policy, inventory=self.inventory)
        self.assertEqual(self.find(report, "SC2086"), [])
        self.assertEqual(report["policy"]["disabled_findings"], 1)
        leak, = self.find(report, "generic-api-key")
        self.assertEqual((leak["severity"], leak["original_severity"]), ("medium", "unknown"))
        license_, = self.find(report, "CRAB-LIC-001")
        self.assertEqual((license_["license"], license_["severity"], license_["risk_type"], license_["package"]["purl"],
                          license_["inventory_components"]),
                         ("AGPL-3.0-only", "high", "license", "pkg:npm/agpl-lib@2.0.0", [1]))
        components = report["inventory"]["components"]
        self.assertEqual(components[1]["observations"], [license_["fingerprint"]])
        self.assertEqual([c["direct"] for c in components], [True, None, None])
        self.assertEqual(report["policy"]["violations"], [{"gate": "severity", "count": 2},
                                                          {"gate": "secrets", "count": 1},
                                                          {"gate": "malicious", "count": 1},
                                                          {"gate": "licenses", "count": 1}])
        strict = self.save("strict.json", dict(POLICY, fail_on="none", gates={"max": {"low": 1}, "secrets": False,
                                                                              "malicious": False, "licenses": False},
                                               licenses={"allow": ["MIT"]}))
        report = self.run_collect(policy=strict, inventory=self.inventory)
        self.assertEqual({f["license"] for f in self.find(report, "CRAB-LIC-001")}, {"AGPL-3.0-only", "Custom"})
        self.assertEqual(report["policy"]["violations"], [{"gate": "max:low", "count": 2, "limit": 1}])
        self.assertEqual(self.run_collect(policy=strict, fail_on="critical")["policy"]["minimum_severity"],
                         "critical")

    def test_exceptions_expiry_stale_and_review_scope(self):
        base = self.run_collect()
        ctr, = self.find(base, "CRAB-CTR-001")
        malicious, = self.find(base, "MAL-2026-0001")
        exceptions = self.save("exceptions.json", {"version": 2, "exceptions": [
            {"fingerprint": ctr["fingerprint"], "status": "not_affected", "justification": "protected_at_runtime",
             "reason": "Runtime enforces non-root", "reviewer": "platform-team"},
            {"fingerprint": malicious["fingerprint"], "status": "accepted", "reason": "Expired review",
             "reviewer": "security-team", "expires": "2026-11-20"},
            {"fingerprint": "d" * 64, "status": "false_positive", "reason": "Gone", "reviewer": "dev-lead"}]})
        report = self.run_collect(exceptions=exceptions)
        ctr, = self.find(report, "CRAB-CTR-001")
        malicious, = self.find(report, "MAL-2026-0001")
        self.assertTrue(ctr["suppressed"])
        self.assertEqual(ctr["exception"]["justification"], "protected_at_runtime")
        self.assertFalse(malicious["suppressed"])
        self.assertNotIn("exception", malicious)
        self.assertEqual(report["policy"]["expired_exceptions"],
                         [{"fingerprint": malicious["fingerprint"], "expires": "2026-11-20"}])
        self.assertEqual(report["policy"]["stale_exceptions"], ["d" * 64])
        self.assertEqual(report["policy"]["suppressed"], 1)
        earlier = self.run_collect(exceptions=exceptions, today=date(2026, 11, 19))
        self.assertTrue(self.find(earlier, "MAL-2026-0001")[0]["suppressed"])
        no_review = self.save("policy.json", {"version": 1, "include_review": False, "fail_on": "medium",
                                              "gates": {"secrets": False, "malicious": False}})
        report = self.run_collect(policy=no_review)
        self.assertEqual(report["policy"]["actionable"], 3)

    def test_comparison_and_new_only(self):
        base_report = self.run_collect()
        (self.root / "Dockerfile").write_text("FROM scratch\nUSER 1000\n")
        (self.root / "app.py").write_text("import ssl\nssl._create_unverified_context()\n")
        base = self.save("base.json", base_report)
        policy = self.save("policy.json", {"version": 1, "new_only": True, "fail_on": "medium"})
        report = self.run_collect(new_since=base, policy=policy)
        comparison = report["comparison"]
        self.assertEqual((comparison["base_revision"], comparison["new"], comparison["unchanged"]),
                         ("head", 1, len(report["findings"]) - 1))
        fixed, = comparison["fixed"]
        self.assertEqual((fixed["rule"], fixed["category"], fixed["line"]), ("CRAB-CTR-001", "iac", 2))
        new, = [f for f in report["findings"] if f["new"]]
        self.assertEqual(new["rule"], "CRAB-PY-001")
        self.assertEqual(report["policy"]["violations"], [{"gate": "severity", "count": 1}])
        bad = self.save("bad.json", {"schema_version": 2, "findings": []})
        report = self.run_collect(new_since=bad)
        self.assertIn({"reason": "invalid_comparison_base"}, report["errors"])
        self.assertNotIn("comparison", report)
        self.assertEqual(exit_status(report), 2)

    def test_epss_kev_enrichment_and_invalid_inputs(self):
        epss = self.folder / "epss.csv.gz"
        epss.write_bytes(gzip.compress(b"#model_version:v2025.03.14,score_date:2026-11-19T12:00:00+0000\n"
                                       b"cve,epss,percentile\nCVE-2099-0001,0.42000,0.91000\n"
                                       b"CVE-2099-0002,0.01000,0.10000\n"))
        kev = self.save("kev.json", {"title": "SYNTHETIC_CANARY", "vulnerabilities": [{"cveID": "CVE-2099-0002"}]})
        self.inputs[2][1].write_text(json.dumps({"SchemaVersion": 2, "ArtifactType": "filesystem", "Results": [
            {"Class": "lang-pkgs", "Type": "npm", "Target": "package-lock.json", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2099-0001", "PkgName": "widget", "InstalledVersion": "1.0.0",
                 "Severity": "LOW"}]}]}))
        self.inputs.append(("osv", self.save("osv2.json", {"results": [
            {"source": {"path": "package-lock.json", "type": "lockfile"},
             "packages": [{"package": {"name": "other", "version": "1.0.0", "ecosystem": "npm"},
                           "vulnerabilities": [{"id": "GHSA-demo", "aliases": ["CVE-2099-0002"]}]}]}]}),
                            {"origin": "report"}))
        policy = self.save("policy.json", {"version": 1, "fail_on": "none", "gates": {"epss": 0.4, "secrets": False,
                                                                                  "malicious": False}})
        report = self.run_collect(epss=epss, kev=kev, policy=policy)
        cve, = self.find(report, "CVE-2099-0001")
        ghsa, = self.find(report, "GHSA-demo")
        self.assertEqual(cve["epss"], {"score": 0.42, "percentile": 0.91, "date": "2026-11-19"})
        self.assertNotIn("kev", cve)
        self.assertEqual((ghsa["epss"]["score"], ghsa["kev"]), (0.01, True))
        self.assertEqual(report["policy"]["violations"], [{"gate": "kev", "count": 1}, {"gate": "epss", "count": 1}])
        plain = self.folder / "epss.csv"
        plain.write_text("cve,epss,percentile\nCVE-2099-0001,0.5,0.9\n")
        self.assertEqual(enrich.load_epss(plain).scores, {"CVE-2099-0001": (0.5, 0.9)})
        bad_epss = self.folder / "bad.csv"
        bad_epss.write_text("cve,epss,percentile\nCVE-2099-0001,1.5,0.9\n")
        bad_kev = self.save("bad-kev.json", {"vulnerabilities": [{"cveID": "not-a-cve"}]})
        bad_policy = self.save("bad-policy.json", {"version": 1, "fail_on": "severe"})
        report = self.run_collect(epss=bad_epss, kev=bad_kev, policy=bad_policy,
                                  exceptions=self.save("v1.json", {"version": 1, "suppressions": []}))
        self.assertEqual(sorted(e["reason"] for e in report["errors"]),
                         ["invalid_epss", "invalid_exceptions", "invalid_kev", "invalid_policy"])

    def test_reevaluate_and_gate_cli(self):
        report = self.run_collect(inventory=self.inventory)
        again = reevaluate(report, today=TODAY)
        self.assertEqual(again, report)
        self.assertEqual(json.dumps(again), json.dumps(report))
        original = copy.deepcopy(report)
        relaxed = reevaluate(report, fail_on="critical", policy=self.save("p.json", {
            "version": 1, "gates": {"secrets": False, "malicious": False},
            "licenses": {"deny": ["AGPL-3.0-only"], "severity": "low"}}), today=TODAY)
        self.assertEqual(report, original)
        self.assertEqual(relaxed["policy"]["minimum_severity"], "critical")
        self.assertEqual(len(self.find(relaxed, "CRAB-LIC-001")), 1)
        self.assertEqual(relaxed["policy"]["violations"], [{"gate": "severity", "count": 1},
                                                           {"gate": "licenses", "count": 1}])
        validate(relaxed)
        exceptions = self.save("exceptions.json", {"version": 2, "exceptions": [
            {"fingerprint": f["fingerprint"], "status": "accepted", "reason": "Reviewed", "reviewer": "lead"}
            for f in report["findings"]]})
        quiet = reevaluate(report, exceptions=exceptions, today=TODAY)
        self.assertTrue(quiet["policy"]["passed"])
        self.assertEqual(exit_status(quiet), 0)
        # Without a new exceptions file, attached exceptions survive another evaluation.
        self.assertTrue(reevaluate(quiet, today=TODAY)["policy"]["passed"])
        with self.assertRaises(ValueError):
            reevaluate({"schema_version": 2})
        saved = self.save("report.json", report)
        run = cli("gate", saved, "--exceptions", exceptions)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        self.assertTrue(json.loads(run.stdout)["passed"])
        run = cli("gate", saved, "--fail-on", "none")
        self.assertEqual(run.returncode, 1, run.stderr + run.stdout)
