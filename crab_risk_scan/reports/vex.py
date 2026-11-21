"""CycloneDX 1.6 VEX document for dependency and container vulnerabilities.

License findings are policy results, not vulnerabilities, and are excluded.
Exceptions only set an analysis state while they suppress the finding; an
expired exception leaves the vulnerability ``in_triage``.
"""
import hashlib
import uuid

from . import summary

CATEGORIES = ("sca", "container")
STATES = {"accepted": "exploitable", "false_positive": "false_positive", "not_affected": "not_affected"}


def cvss_method(vector):
    if not vector:
        return "other"
    if vector.startswith("CVSS:4.0/"):
        return "CVSSv4"
    if vector.startswith("CVSS:3.1/"):
        return "CVSSv31"
    if vector.startswith("CVSS:3.0/"):
        return "CVSSv3"
    if vector.startswith(("AV:", "(AV:")):
        return "CVSSv2"
    return "other"


def score_severity(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def ratings(finding):
    cvss = finding.get("cvss")
    if cvss:
        rating = {"score": cvss["score"], "severity": score_severity(cvss["score"]),
                  "method": cvss_method(cvss.get("vector"))}
        if cvss.get("vector"):
            rating["vector"] = cvss["vector"]
        if cvss.get("source"):
            rating["source"] = {"name": cvss["source"]}
        return [rating]
    return [{"severity": finding["severity"], "method": "other", "source": {"name": "crab-risk-scan"}}]


def source(identifier):
    url = summary.advisory_url(identifier)
    upper = identifier.upper()
    if upper.startswith("CVE-"):
        return {"name": "NVD", "url": url}
    if upper.startswith("GHSA-"):
        return {"name": "GitHub", "url": url}
    if url:
        return {"name": "OSV", "url": url}
    return None


def component_ref(finding):
    package = finding.get("package") or {}
    if package.get("purl"):
        return package["purl"]
    digest = hashlib.sha256("\0".join(str(package.get(key) or "") for key in ("ecosystem", "name", "version"))
                            .encode("utf-8")).hexdigest()[:16]
    return f"crab-component-{digest}"


def analysis(finding):
    exception = finding.get("exception") if finding.get("suppressed") else None
    if not exception or exception.get("status") not in STATES:
        return {"state": "in_triage"}
    result = {"state": STATES[exception["status"]]}
    if exception["status"] == "accepted":
        result["response"] = ["will_not_fix"]
    if exception["status"] == "not_affected" and exception.get("justification"):
        result["justification"] = exception["justification"]
    if exception.get("reason"):
        result["detail"] = exception["reason"]
    return result


def render(report, generated_at=None):
    findings = [f for f in report["findings"]
                if f["category"] in CATEGORIES and f.get("package") and f.get("risk_type") != "license"]
    components = {}
    vulnerabilities = []
    for finding in findings:
        package = finding["package"]
        ref = component_ref(finding)
        if ref not in components:
            component = {"type": "library", "bom-ref": ref, "name": package["name"]}
            if package.get("version"):
                component["version"] = package["version"]
            if package.get("purl"):
                component["purl"] = package["purl"]
            components[ref] = component
        vulnerability = {"bom-ref": "crab-" + finding["fingerprint"], "id": finding["rule"]}
        origin = source(finding["rule"])
        if origin:
            vulnerability["source"] = origin
        references = []
        for alias in finding.get("aliases") or ():
            entry = {"id": alias}
            alias_source = source(alias)
            if alias_source:
                entry["source"] = alias_source
            else:
                entry["source"] = {"name": "unknown"}
            references.append(entry)
        if references:
            vulnerability["references"] = references
        vulnerability["ratings"] = ratings(finding)
        cwes = summary.cwe_numbers(finding)
        if cwes:
            vulnerability["cwes"] = cwes
        if finding.get("fixed_version"):
            vulnerability["recommendation"] = f"Upgrade {package['name']} to {finding['fixed_version']}."
        elif finding.get("risk_type") == "malicious":
            vulnerability["recommendation"] = f"Remove {package['name']} and rebuild from a clean lockfile."
        vulnerability["analysis"] = analysis(finding)
        affected = {"ref": ref}
        if package.get("version"):
            affected["versions"] = [{"version": package["version"], "status": "affected"}]
        vulnerability["affects"] = [affected]
        properties = [{"name": "crab:fingerprint", "value": finding["fingerprint"]},
                      {"name": "crab:category", "value": finding["category"]},
                      {"name": "crab:severity", "value": finding["severity"]}]
        if finding.get("risk_type"):
            properties.append({"name": "crab:risk_type", "value": finding["risk_type"]})
        if finding.get("kev") is True:
            properties.append({"name": "crab:kev", "value": "true"})
        if finding.get("epss"):
            properties.append({"name": "crab:epss", "value": str(finding["epss"]["score"])})
        if finding.get("image_digest"):
            properties.append({"name": "crab:image_digest", "value": finding["image_digest"]})
        vulnerability["properties"] = properties
        vulnerabilities.append(vulnerability)

    seed = "\n".join(["crab-risk-scan:vex", report["target"], report.get("revision") or "",
                      *sorted(f["fingerprint"] + ":" + analysis(f)["state"] for f in findings)])
    serial = uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(seed.encode("utf-8")).hexdigest())
    subject = {"type": "application", "bom-ref": "crab-subject", "name": report["target"]}
    if report.get("revision"):
        subject["version"] = report["revision"]
    metadata = {"tools": {"components": [{"type": "application", "name": report["tool"]["name"],
                                          "version": report["tool"]["version"]}]},
                "component": subject}
    stamp = summary.timestamp(generated_at)
    if stamp:
        metadata = {"timestamp": stamp, **metadata}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": [components[key] for key in sorted(components)],
        "vulnerabilities": vulnerabilities,
    }
