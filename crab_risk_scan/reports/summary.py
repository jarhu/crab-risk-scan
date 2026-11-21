"""Shared report model used by every human-readable and machine renderer.

All text produced here is written by CRAB. Producer free text never reaches a
report: titles and locations are built from structured fields only.
"""
import datetime as dt
from urllib.parse import quote

# Characters kept as they are in a URL placed inside Markdown. Everything else, including
# ( ) [ ] < > | \ ` " ' and spaces, is percent-encoded so a crafted URL cannot close the link,
# start an image, add a title or split a table cell. Existing %XX escapes stay intact.
MARKDOWN_URL_SAFE = ":/?#@!$&*+,;=%-._~"


def markdown_url(uri):
    """An http(s) URL encoded for a Markdown link destination, or None for other schemes."""
    if not isinstance(uri, str) or not uri.startswith(("https://", "http://")):
        return None
    return quote(uri, safe=MARKDOWN_URL_SAFE)


SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = ("sast", "secrets", "iac", "sca", "container")
KINDS = ("vulnerability", "review")

SEVERITY_RANK = {level: index for index, level in enumerate(SEVERITIES)}

SEVERITY_LABELS = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info", "unknown": "Unknown",
}

CATEGORY_LABELS = {
    "sast": "Static analysis",
    "secrets": "Secrets",
    "iac": "Infrastructure as code",
    "sca": "Dependencies",
    "container": "Container images",
}

KIND_LABELS = {"vulnerability": "Vulnerability", "review": "Review signal"}

EXCEPTION_LABELS = {
    "accepted": "Risk accepted",
    "false_positive": "False positive",
    "not_affected": "Not affected",
}

# Posture ratings, most severe first. The first matching condition wins.
POSTURE_LEVELS = (
    ("critical", "Critical",
     "At least one open finding is critical, is listed in CISA KEV or is a malicious package."),
    ("high", "High", "At least one open finding is high severity."),
    ("moderate", "Moderate", "At least one open finding is medium or of unknown severity."),
    ("low", "Low", "Open findings are low or informational only."),
    ("minimal", "Minimal", "No open findings."),
)

GATE_LABELS = {
    "severity": "findings at or above the severity threshold",
    "secrets": "exposed secrets",
    "malicious": "malicious packages",
    "kev": "known exploited vulnerabilities (CISA KEV)",
    "epss": "vulnerabilities above the EPSS threshold",
    "licenses": "license policy violations",
}

# CRAB-written guidance. Producer descriptions are never used.
CATEGORY_RECOMMENDATIONS = {
    "secrets": "Revoke and rotate every exposed credential, remove it from the repository history, "
               "and load secrets from a secret manager at run time.",
    "sast": "Fix the reported code paths, starting with the highest severity. Review each review "
            "signal with the code owner and record an exception with a reason when the code is safe.",
    "iac": "Correct the infrastructure definitions before the next deployment. Prefer secure "
           "defaults in shared modules so the fix applies to every environment.",
    "sca": "Upgrade affected dependencies to the listed fixed versions and regenerate the lockfile. "
           "Replace dependencies that have no fixed version or are no longer maintained.",
    "container": "Rebuild images on a patched base image, update the affected OS packages and "
                 "redeploy. Pin base images by digest.",
}

SIGNAL_RECOMMENDATIONS = {
    "malicious": "Remove malicious packages immediately, rebuild from a clean lockfile and rotate "
                 "credentials available to the build and runtime environments.",
    "kev": "Patch known exploited vulnerabilities first. CISA KEV lists them because attackers "
           "use them in the wild.",
    "license": "Replace dependencies whose licenses the policy denies, or obtain approval and "
               "update the policy.",
    "coverage": "Install or fix the skipped and failed scanners so the next scan covers every "
                "file type in the target.",
    "errors": "Resolve the scan errors. Results are incomplete until every input completes.",
    "expired": "Renew or remove expired exceptions. Expired exceptions no longer suppress findings.",
    "stale": "Remove stale exceptions. They match no current finding.",
}

FIXED_EPOCH = dt.datetime(1980, 1, 1, tzinfo=dt.timezone.utc)


def rule_id(finding):
    return f"{finding['producer']}/{finding['rule']}"


def is_open(finding):
    return not finding.get("suppressed")


def open_findings(report):
    return [finding for finding in report["findings"] if is_open(finding)]


def checkout_path(finding):
    """Repository-relative path, or None for image-internal and unlocated findings."""
    if finding.get("image_digest"):
        return None
    return finding.get("path") or None


def package_label(finding):
    package = finding.get("package") or {}
    name = package.get("name")
    if not name:
        return None
    version = package.get("version")
    return f"{name} {version}" if version else name


def package_ref(finding):
    package = finding.get("package") or {}
    if package.get("purl"):
        return package["purl"]
    if package.get("name"):
        version = package.get("version")
        return f"{package['name']}@{version}" if version else package["name"]
    return None


def title(finding):
    label = package_label(finding)
    risk = finding.get("risk_type")
    if label and risk == "malicious":
        return f"Malicious package {label}"
    if label and risk == "license":
        return f"Denied license {finding.get('license') or 'unknown'} in {label}"
    if label:
        return f"{finding['rule']} in {label}"
    return rule_id(finding)


def short_digest(digest):
    algorithm, _, value = digest.partition(":")
    return f"{algorithm}:{value[:12]}" if value else digest


def line_span(finding):
    line = finding.get("line")
    if not line:
        return ""
    end = finding.get("end_line")
    return f"{line}-{end}" if end and end != line else str(line)


def location(finding):
    path = checkout_path(finding)
    if path:
        span = line_span(finding)
        return f"{path}:{span}" if span else path
    if finding.get("image_digest"):
        text = "image " + short_digest(finding["image_digest"])
        if finding.get("path"):
            text += " " + finding["path"]
        return text
    reference = package_ref(finding)
    if reference:
        return reference
    if finding.get("manifest"):
        return finding["manifest"]
    return "not located"


def cwe_numbers(finding):
    numbers = []
    for entry in finding.get("cwe") or ():
        digits = str(entry).upper().removeprefix("CWE-")
        if digits.isdigit():
            numbers.append(int(digits))
    return numbers


def advisory_url(identifier):
    """Public advisory page for well-known advisory identifier schemes."""
    upper = identifier.upper()
    if upper.startswith("CVE-"):
        return "https://nvd.nist.gov/vuln/detail/" + quote(upper)
    if upper.startswith("GHSA-"):
        return "https://github.com/advisories/" + quote(identifier)
    if upper.startswith(("MAL-", "OSV-", "PYSEC-", "GO-", "RUSTSEC-")):
        return "https://osv.dev/vulnerability/" + quote(identifier)
    return None


def risk_key(indexed):
    index, finding = indexed
    exploited = finding.get("kev") is True or finding.get("risk_type") == "malicious"
    epss = (finding.get("epss") or {}).get("score") or 0.0
    cvss = (finding.get("cvss") or {}).get("score") or 0.0
    return (0 if exploited else 1, SEVERITY_RANK.get(finding["severity"], len(SEVERITIES)),
            -epss, -cvss, index)


def top_risks(report, limit=None):
    """Open findings ordered by risk: KEV and malicious first, then severity, EPSS and CVSS."""
    ranked = [finding for _, finding in sorted(
        ((index, finding) for index, finding in enumerate(report["findings"]) if is_open(finding)),
        key=risk_key)]
    return ranked if limit is None else ranked[:limit]


def counts(report):
    severity = dict.fromkeys(SEVERITIES, 0)
    category = dict.fromkeys(CATEGORIES, 0)
    kind = dict.fromkeys(KINDS, 0)
    matrix = {name: dict.fromkeys(SEVERITIES, 0) for name in CATEGORIES}
    for finding in open_findings(report):
        severity[finding["severity"]] = severity.get(finding["severity"], 0) + 1
        category[finding["category"]] = category.get(finding["category"], 0) + 1
        kind[finding["kind"]] = kind.get(finding["kind"], 0) + 1
        matrix.setdefault(finding["category"], dict.fromkeys(SEVERITIES, 0))[finding["severity"]] += 1
    total = sum(severity.values())
    suppressed = len(report["findings"]) - total
    return {"severity": severity, "category": category, "kind": kind, "matrix": matrix,
            "total": total, "suppressed": suppressed}


def signals(report):
    findings = open_findings(report)
    return {
        "kev": sum(1 for f in findings if f.get("kev") is True),
        "malicious": sum(1 for f in findings if f.get("risk_type") == "malicious"),
        "license": sum(1 for f in findings if f.get("risk_type") == "license"),
        "secrets": sum(1 for f in findings if f["category"] == "secrets"),
        "new": sum(1 for f in findings if f.get("new") is True),
        "fixable": sum(1 for f in findings if f.get("fixed_version")),
    }


def policy_status(report):
    """passed, failed or incomplete; incomplete wins because errors exit with status 2."""
    if report.get("errors"):
        return "incomplete"
    return "passed" if report["policy"]["passed"] else "failed"


def violation_text(violation, policy):
    gate = violation["gate"]
    count = violation["count"]
    if gate.startswith("max:"):
        level = gate.removeprefix("max:")
        return f"{count} open {level} findings exceed the limit of {violation.get('limit')}"
    if gate == "severity":
        return f"{count} open findings at or above {policy.get('minimum_severity')}"
    return f"{count} {GATE_LABELS.get(gate, gate)}"


def policy_summary(report):
    policy = report["policy"]
    return {
        "status": policy_status(report),
        "passed": policy["passed"],
        "source": policy["source"],
        "minimum_severity": policy["minimum_severity"],
        "new_only": policy["new_only"],
        "include_review": policy["include_review"],
        "actionable": policy["actionable"],
        "suppressed": policy["suppressed"],
        "disabled_findings": policy["disabled_findings"],
        "violations": [violation_text(violation, policy) for violation in policy["violations"]],
        "expired_exceptions": list(policy["expired_exceptions"]),
        "stale_exceptions": list(policy["stale_exceptions"]),
    }


def coverage(report):
    by_input = {}
    for finding in report["findings"]:
        for ordinal in finding.get("inputs") or ():
            by_input[ordinal] = by_input.get(ordinal, 0) + 1
    rows = []
    for entry in report["imports"]:
        rows.append({
            "input": entry["input"],
            "producer": entry["producer"],
            "origin": entry["origin"],
            "status": entry["status"],
            "reason": entry.get("reason") or "",
            "version": entry.get("producer_version") or "",
            "rule_pack": entry.get("rule_pack") or "",
            "targets": entry.get("targets"),
            "findings": by_input.get(entry["input"], 0),
        })
    return rows


def coverage_gap(entry):
    """True when an input did not fully cover its scope. An engine skipped as not applicable had nothing to scan."""
    if entry["status"] == "skipped":
        return entry.get("reason") != "not_applicable"
    return entry["status"] in ("failed", "partial")


def coverage_complete(report):
    return not report.get("errors") and not any(coverage_gap(entry) for entry in report["imports"])


def posture(report):
    findings = open_findings(report)
    present = {finding["severity"] for finding in findings}
    if any(f["severity"] == "critical" or f.get("kev") is True or f.get("risk_type") == "malicious"
           for f in findings):
        rating = "critical"
    elif "high" in present:
        rating = "high"
    elif present & {"medium", "unknown"}:
        rating = "moderate"
    elif findings:
        rating = "low"
    else:
        rating = "minimal"
    label, description = next((label, text) for key, label, text in POSTURE_LEVELS if key == rating)
    complete = coverage_complete(report)
    if not complete:
        description += " Coverage is incomplete, so the rating is a lower bound."
    return {"rating": rating, "label": label, "description": description, "coverage_complete": complete}


def recommendations(report):
    """Prioritized CRAB-written actions for the signals and categories present in the report."""
    found = signals(report)
    category_counts = counts(report)["category"]
    policy = report["policy"]
    actions = []
    for topic in ("malicious", "kev"):
        if found[topic]:
            actions.append({"topic": topic, "count": found[topic], "text": SIGNAL_RECOMMENDATIONS[topic]})
    for category in ("secrets", "sca", "container", "sast", "iac"):
        if category_counts[category]:
            actions.append({"topic": category, "count": category_counts[category],
                            "text": CATEGORY_RECOMMENDATIONS[category]})
    if found["license"]:
        actions.append({"topic": "license", "count": found["license"], "text": SIGNAL_RECOMMENDATIONS["license"]})
    if report.get("errors"):
        actions.append({"topic": "errors", "count": len(report["errors"]), "text": SIGNAL_RECOMMENDATIONS["errors"]})
    gaps = sum(1 for entry in report["imports"] if coverage_gap(entry))
    if gaps:
        actions.append({"topic": "coverage", "count": gaps, "text": SIGNAL_RECOMMENDATIONS["coverage"]})
    if policy["expired_exceptions"]:
        actions.append({"topic": "expired", "count": len(policy["expired_exceptions"]),
                        "text": SIGNAL_RECOMMENDATIONS["expired"]})
    if policy["stale_exceptions"]:
        actions.append({"topic": "stale", "count": len(policy["stale_exceptions"]),
                        "text": SIGNAL_RECOMMENDATIONS["stale"]})
    return actions


TOPIC_LABELS = {
    **CATEGORY_LABELS,
    "malicious": "Malicious packages",
    "kev": "Known exploited vulnerabilities",
    "license": "License policy",
    "coverage": "Scanner coverage",
    "errors": "Scan errors",
    "expired": "Expired exceptions",
    "stale": "Stale exceptions",
}


def exceptions(report):
    rows = []
    for finding in report["findings"]:
        exception = finding.get("exception")
        if not exception:
            continue
        rows.append({
            "fingerprint": finding["fingerprint"],
            "rule": rule_id(finding),
            "title": title(finding),
            "location": location(finding),
            "severity": finding["severity"],
            "suppressed": bool(finding.get("suppressed")),
            "status": exception.get("status") or "",
            "justification": exception.get("justification") or "",
            "reason": exception.get("reason") or "",
            "reviewer": exception.get("reviewer") or "",
            "expires": exception.get("expires") or "",
            "ticket": exception.get("ticket") or "",
        })
    return rows


def inventory_summary(report):
    inventory = report.get("inventory")
    if not inventory:
        return None
    components = inventory["components"]
    licenses = {}
    for component in components:
        for name in component.get("licenses") or ["(none declared)"]:
            licenses[name] = licenses.get(name, 0) + 1
    return {
        "format": inventory["format"],
        "spec_version": inventory["spec_version"],
        "components": len(components),
        "direct": sum(1 for c in components if c.get("direct") is True),
        "transitive": sum(1 for c in components if c.get("direct") is False),
        "with_findings": sum(1 for c in components if c.get("observations")),
        "licenses": sorted(licenses.items(), key=lambda item: (-item[1], item[0])),
    }


def signal_labels(finding):
    """Short CRAB labels for prioritization signals."""
    labels = []
    if finding.get("kev") is True:
        labels.append("KEV")
    if finding.get("risk_type") == "malicious":
        labels.append("Malicious")
    epss = finding.get("epss")
    if epss:
        labels.append(f"EPSS {epss['score']:.2f}")
    cvss = finding.get("cvss")
    if cvss:
        labels.append(f"CVSS {cvss['score']:.1f}")
    if finding.get("new") is True:
        labels.append("New")
    return labels


def status_label(finding):
    if finding.get("suppressed"):
        status = (finding.get("exception") or {}).get("status")
        return "Suppressed: " + EXCEPTION_LABELS.get(status, status or "exception")
    return "Open"


def timestamp(generated_at):
    """Printable form of the caller-supplied generation time, or None."""
    if generated_at is None:
        return None
    if isinstance(generated_at, dt.datetime):
        return generated_at.isoformat()
    if isinstance(generated_at, dt.date):
        return generated_at.isoformat()
    return str(generated_at)


def as_datetime(generated_at):
    """Aware datetime for document metadata; a fixed epoch keeps output deterministic."""
    if generated_at is None:
        return FIXED_EPOCH
    if isinstance(generated_at, dt.datetime):
        value = generated_at
    elif isinstance(generated_at, dt.date):
        value = dt.datetime(generated_at.year, generated_at.month, generated_at.day)
    else:
        value = dt.datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
    return value.astimezone(dt.timezone.utc) if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def metadata(report, generated_at=None):
    return {
        "target": report["target"],
        "repository": report.get("repository"),
        "revision": report.get("revision"),
        "branch": report.get("branch"),
        "tool": report["tool"]["name"],
        "tool_version": report["tool"]["version"],
        "files_scanned": report["files_scanned"],
        "generated_at": timestamp(generated_at),
    }


def build(report, generated_at=None):
    """Everything the renderers share, computed once."""
    return {
        "meta": metadata(report, generated_at),
        "counts": counts(report),
        "signals": signals(report),
        "policy": policy_summary(report),
        "coverage": coverage(report),
        "coverage_complete": coverage_complete(report),
        "posture": posture(report),
        "top": top_risks(report),
        "recommendations": recommendations(report),
        "exceptions": exceptions(report),
        "inventory": inventory_summary(report),
        "comparison": report.get("comparison"),
        "errors": list(report.get("errors") or ()),
    }
