"""SARIF 2.1.0 export of a CRAB report.

GitHub code scanning rejects a whole file when any result lacks a physical
location with a start line, and GitLab drops such results. Findings without a
checkout location (image-internal packages, inventory license findings)
therefore receive a synthetic, repository-relative URI
``crab-image/<algorithm>-<digest>/<ecosystem>/<name>/<version>`` or
``crab-inventory/<ecosystem>/<name>/<version>``, start line 1, a logical location
naming the package, and ``properties.syntheticLocation: true``.
"""
import re
from urllib.parse import quote

from . import summary

CVE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

INFORMATION_URI = "https://github.com/jarhu/crab-risk-scan"
HELP_FALLBACK = INFORMATION_URI + "/blob/main/docs/reporting.md"

LEVELS = {"critical": "error", "high": "error", "medium": "warning",
          "unknown": "warning", "low": "note", "info": "note"}

# GitHub bands: critical > 9.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9.
SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "unknown": 5.0, "low": 3.0, "info": 1.0}
BANDS = {"critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9), "low": (0.1, 3.9)}


def security_severity(severity, findings):
    band = BANDS.get(severity)
    scores = [f["cvss"]["score"] for f in findings
              if f["severity"] == severity and f.get("cvss") and band
              and band[0] <= f["cvss"]["score"] <= band[1]]
    return f"{max(scores) if scores else SECURITY_SEVERITY[severity]:.1f}"


def help_uri(findings):
    for finding in findings:
        if finding.get("help_uri"):
            return finding["help_uri"]
    url = summary.advisory_url(findings[0]["rule"])
    return url or HELP_FALLBACK


def build_rules(report):
    grouped = {}
    for finding in report["findings"]:
        grouped.setdefault(summary.rule_id(finding), []).append(finding)
    rules = []
    for identifier in sorted(grouped):
        findings = grouped[identifier]
        first = findings[0]
        severity = min((f["severity"] for f in findings), key=summary.SEVERITY_RANK.__getitem__)
        cwes = sorted({number for f in findings for number in summary.cwe_numbers(f)})
        categories = sorted({f["category"] for f in findings})
        cves = sorted({identifier.lower() for f in findings for identifier in [f["rule"], *(f.get("aliases") or ())]
                       if CVE.match(identifier)})
        # GitHub reads external/cwe/cwe-N; GitLab reads cwe-N and cve-YYYY-N. GitLab keeps 10 tags.
        tags = ["security", *categories, *cves, *(f"external/cwe/cwe-{n}" for n in cwes),
                *(f"cwe-{n}" for n in cwes)]
        uri = help_uri(findings)
        guidance = summary.CATEGORY_RECOMMENDATIONS[first["category"]]
        rules.append({
            "id": identifier,
            "name": first["rule"],
            "shortDescription": {"text": first["message"]},
            "fullDescription": {"text": first["message"]},
            "help": {"text": f"{guidance} Reference: {uri}",
                     "markdown": f"{guidance}\n\n[Reference]({summary.markdown_url(uri)})"},
            "helpUri": uri,
            "defaultConfiguration": {"level": LEVELS[severity]},
            "properties": {
                "tags": tags[:10],
                "security-severity": security_severity(severity, findings),
                "precision": "medium" if first["kind"] == "review" else "high",
                "problem.severity": "recommendation" if LEVELS[severity] == "note" else LEVELS[severity],
            },
        })
    return rules


def package_segments(finding):
    package = finding.get("package") or {}
    if not package.get("name"):
        return []
    parts = [package.get("ecosystem") or "unknown", package["name"]]
    if package.get("version"):
        parts.append(package["version"])
    return [quote(part, safe="") for part in parts]


def synthetic_uri(finding):
    """Stable pseudo-path; the package segment keeps GitLab and GitHub identities distinct per package."""
    segments = package_segments(finding)
    if finding.get("image_digest"):
        return "/".join(["crab-image", finding["image_digest"].replace(":", "-"), *segments])
    if segments:
        return "/".join(["crab-inventory", *segments])
    return "crab-inventory/unlocated"


def build_location(finding):
    path = summary.checkout_path(finding)
    if path:
        location = {"artifactLocation": {"uri": quote(path, safe="/")}}
        region = {"startLine": finding.get("line") or 1}
        if finding.get("line"):
            region["endLine"] = finding.get("end_line") or finding["line"]
            if finding.get("column"):
                region["startColumn"] = finding["column"]
                if finding.get("end_column"):
                    region["endColumn"] = finding["end_column"]
        location["region"] = region
        return {"physicalLocation": location}, not finding.get("line")
    result = {"physicalLocation": {"artifactLocation": {"uri": synthetic_uri(finding)},
                                   "region": {"startLine": 1}}}
    logical = {"kind": "module"}
    reference = summary.package_ref(finding)
    if reference:
        logical["name"] = summary.package_label(finding)
        logical["fullyQualifiedName"] = (finding["image_digest"] + "!" + reference
                                         if finding.get("image_digest") else reference)
        result["logicalLocations"] = [logical]
    elif finding.get("image_digest"):
        logical["name"] = finding["image_digest"]
        result["logicalLocations"] = [logical]
    return result, True


def result_properties(finding, approximate):
    properties = {"category": finding["category"], "kind": finding["kind"]}
    if finding.get("cwe"):
        properties["cwe"] = list(finding["cwe"])
    reference = summary.package_ref(finding)
    if reference:
        properties["package"] = reference
    if finding.get("fixed_version"):
        properties["fixedVersion"] = finding["fixed_version"]
    if finding.get("cvss"):
        properties["cvss"] = finding["cvss"]["score"]
        if finding["cvss"].get("vector"):
            properties["cvssVector"] = finding["cvss"]["vector"]
    if finding.get("epss"):
        properties["epss"] = finding["epss"]["score"]
        if finding["epss"].get("percentile") is not None:
            properties["epssPercentile"] = finding["epss"]["percentile"]
    properties["kev"] = finding.get("kev") is True
    if "new" in finding:
        properties["new"] = bool(finding["new"])
    if finding.get("risk_type"):
        properties["riskType"] = finding["risk_type"]
    if finding.get("license"):
        properties["license"] = finding["license"]
    if finding.get("image_digest"):
        properties["imageDigest"] = finding["image_digest"]
    if finding.get("original_severity") and finding["original_severity"] != finding["severity"]:
        properties["originalSeverity"] = finding["original_severity"]
    if approximate:
        properties["syntheticLocation" if not summary.checkout_path(finding) else "lineUnknown"] = True
    return properties


def build_suppression(finding):
    exception = finding.get("exception") or {}
    suppression = {"kind": "external", "status": "accepted"}
    if exception.get("reason"):
        suppression["justification"] = exception["reason"]
    properties = {"exceptionStatus": exception.get("status") or "unknown"}
    for key, name in (("justification", "vexJustification"), ("reviewer", "reviewer"),
                      ("expires", "expires"), ("ticket", "ticket")):
        if exception.get(key):
            properties[name] = exception[key]
    suppression["properties"] = properties
    return suppression


def notifications(report):
    entries = []
    for error in report.get("errors") or ():
        parts = [error["reason"]]
        if error.get("producer"):
            parts.append(f"producer {error['producer']}")
        if error.get("input") is not None:
            parts.append(f"input {error['input']}")
        if error.get("path"):
            parts.append(f"path {error['path']}")
        notification = {"level": "error", "message": {"text": ", ".join(parts)},
                        "descriptor": {"id": error["reason"]}}
        entries.append(notification)
    for entry in report["imports"]:
        if entry["status"] in ("skipped", "partial"):
            text = f"{entry['producer']} {entry['status']}"
            if entry.get("reason"):
                text += f": {entry['reason']}"
            entries.append({"level": "note" if entry["status"] == "skipped" else "warning",
                            "message": {"text": text}, "descriptor": {"id": f"coverage/{entry['status']}"}})
    return entries


def render(report):
    rules = build_rules(report)
    index = {rule["id"]: position for position, rule in enumerate(rules)}
    results = []
    for finding in report["findings"]:
        identifier = summary.rule_id(finding)
        location, approximate = build_location(finding)
        result = {
            "ruleId": identifier,
            "ruleIndex": index[identifier],
            "level": LEVELS[finding["severity"]],
            "message": {"text": f"{summary.title(finding)}: {finding['message']}"},
            "locations": [location],
            "partialFingerprints": {"crab/v2": finding["fingerprint"]},
            "properties": result_properties(finding, approximate),
        }
        if finding.get("suppressed"):
            result["suppressions"] = [build_suppression(finding)]
        results.append(result)
    version = report["tool"]["version"]
    run = {
        "tool": {"driver": {"name": "CRAB", "fullName": "CRAB risk scan", "version": version,
                            "semanticVersion": version, "informationUri": INFORMATION_URI,
                            "rules": rules}},
        "automationDetails": {"id": "crab-risk-scan/"},
        "results": results,
        "invocations": [{"executionSuccessful": not report.get("errors"),
                         "toolExecutionNotifications": notifications(report)}],
        "properties": {"target": report["target"], "policyStatus": summary.policy_status(report)},
    }
    if report.get("repository") and report.get("revision"):
        provenance = {"repositoryUri": report["repository"], "revisionId": report["revision"]}
        if report.get("branch"):
            provenance["branch"] = report["branch"]
        run["versionControlProvenance"] = [provenance]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [run]}
