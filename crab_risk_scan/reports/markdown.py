"""GitHub-flavoured Markdown reports: technical and executive variants.

Every value that comes from the report passes through ``esc``. It collapses line
breaks, escapes Markdown punctuation (including pipes and backticks) and turns
angle brackets and ampersands into entities, so a crafted path or rule cannot
break a table, open a code span, inject HTML or mention a user.
"""
from . import summary

PRIORITY_LIMIT = 25
EXECUTIVE_TOP = 10

_SPECIAL = set("\\`*_{}[]()#+!|~@")
_ENTITIES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}


def esc(value):
    if value is None:
        return ""
    text = " ".join(str(value).splitlines())
    out = []
    for char in text:
        if char in _ENTITIES:
            out.append(_ENTITIES[char])
        elif char in _SPECIAL:
            out.append("\\" + char)
        elif char < " " or char == "\x7f":
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines + [""]


def link(text, uri):
    safe = summary.markdown_url(uri)
    return f"[{esc(text)}]({safe})" if safe else esc(text)


def metadata_lines(model):
    meta = model["meta"]
    rows = [["Target", esc(meta["target"])]]
    if meta["repository"]:
        rows.append(["Repository", link(meta["repository"], meta["repository"])])
    rows.append(["Revision", esc(meta["revision"] or "not recorded")])
    rows.append(["Branch", esc(meta["branch"] or "not recorded")])
    rows.append(["Tool", esc(f"{meta['tool']} {meta['tool_version']}")])
    rows.append(["Files checked by built-in rules", str(meta["files_scanned"])])
    if meta["generated_at"]:
        rows.append(["Generated", esc(meta["generated_at"])])
    return table(["Field", "Value"], rows)


def policy_lines(model):
    policy = model["policy"]
    status = policy["status"]
    marker = {"passed": "TIP", "failed": "CAUTION", "incomplete": "WARNING"}[status]
    headline = {"passed": "Policy passed.",
                "failed": "Policy failed.",
                "incomplete": "Scan incomplete. Errors occurred, so the result is not conclusive."}[status]
    lines = [f"> [!{marker}]", f"> **{headline}** Threshold: {esc(policy['minimum_severity'])}. "
             f"Actionable findings: {policy['actionable']}. Suppressed: {policy['suppressed']}."]
    for text in policy["violations"]:
        lines.append(f"> - {esc(text)}")
    return lines + [""]


def severity_lines(model):
    counts = model["counts"]
    rows = [[summary.SEVERITY_LABELS[level], str(counts["severity"][level])] for level in summary.SEVERITIES]
    rows.append(["**Total open**", f"**{counts['total']}**"])
    rows.append(["Suppressed", str(counts["suppressed"])])
    return table(["Severity", "Open findings"], rows)


def category_lines(model):
    counts = model["counts"]
    headers = ["Category", *(summary.SEVERITY_LABELS[level] for level in summary.SEVERITIES), "Total"]
    rows = []
    for category in summary.CATEGORIES:
        cells = [str(counts["matrix"][category][level]) for level in summary.SEVERITIES]
        rows.append([summary.CATEGORY_LABELS[category], *cells, str(counts["category"][category])])
    lines = table(headers, rows)
    kinds = ", ".join(f"{summary.KIND_LABELS[k]}: {counts['kind'][k]}" for k in summary.KINDS)
    return lines + [f"Open findings by kind: {kinds}.", ""]


def coverage_lines(model):
    rows = []
    for row in model["coverage"]:
        rows.append([str(row["input"]), esc(row["producer"]), esc(row["origin"]), esc(row["status"]),
                     esc(row["reason"]), esc(row["version"]), esc(row["rule_pack"]), str(row["findings"])])
    if not rows:
        return ["No scanners or imported reports contributed to this report.", ""]
    lines = table(["Input", "Producer", "Origin", "Status", "Reason", "Version", "Rule pack", "Findings"], rows)
    note = "Coverage is complete." if model["coverage_complete"] else \
        "Coverage is incomplete. Skipped, partial or failed inputs did not contribute every result."
    return lines + [note, ""]


def comparison_lines(model):
    comparison = model["comparison"]
    if not comparison:
        return ["No base report was given, so new and fixed findings are not computed.", ""]
    lines = [f"Base revision: {esc(comparison.get('base_revision') or 'not recorded')}. "
             f"New: {comparison['new']}. Unchanged: {comparison['unchanged']}. Fixed: {len(comparison['fixed'])}.", ""]
    if comparison["fixed"]:
        rows = []
        for fixed in comparison["fixed"]:
            span = f":{fixed['line']}" if fixed.get("line") else ""
            where = (fixed.get("path") or "") + span if fixed.get("path") else \
                summary.package_ref(fixed) or "not located"
            rows.append([summary.SEVERITY_LABELS.get(fixed["severity"], esc(fixed["severity"])),
                         esc(summary.CATEGORY_LABELS.get(fixed["category"], fixed["category"])),
                         esc(f"{fixed['producer']}/{fixed['rule']}"), esc(where), esc(fixed["fingerprint"][:12])])
        lines += ["Fixed since the base report:", ""]
        lines += table(["Severity", "Category", "Rule", "Location", "Fingerprint"], rows)
    return lines


def fix_text(finding):
    if finding.get("fixed_version"):
        return "Upgrade to " + esc(finding["fixed_version"])
    if finding.get("risk_type") == "malicious":
        return "Remove the package"
    return ""


def priority_lines(model):
    top = model["top"]
    if not top:
        return ["No open findings.", ""]
    rows = []
    for number, finding in enumerate(top[:PRIORITY_LIMIT], 1):
        rows.append([str(number), summary.SEVERITY_LABELS[finding["severity"]], esc(summary.title(finding)),
                     esc(summary.location(finding)), esc(", ".join(summary.signal_labels(finding))),
                     fix_text(finding)])
    lines = table(["#", "Severity", "Finding", "Location", "Signals", "Fix"], rows)
    if len(top) > PRIORITY_LIMIT:
        lines += [f"{len(top) - PRIORITY_LIMIT} more open findings are listed in the details below.", ""]
    return lines


def detail_cells(finding):
    parts = []
    if finding.get("cwe"):
        parts.append(", ".join(finding["cwe"]))
    if finding.get("package"):
        parts.append("Package " + (summary.package_ref(finding) or ""))
    if finding.get("fixed_version"):
        parts.append("Fixed in " + finding["fixed_version"])
    if finding.get("license"):
        parts.append("License " + finding["license"])
    parts.extend(summary.signal_labels(finding))
    return esc("; ".join(parts))


def details_lines(report):
    lines = []
    for category in summary.CATEGORIES:
        findings = [f for f in report["findings"] if f["category"] == category]
        if not findings:
            continue
        lines += [f"### {summary.CATEGORY_LABELS[category]} ({len(findings)})", ""]
        rows = []
        for finding in findings:
            rule = link(summary.rule_id(finding), finding.get("help_uri"))
            rows.append([summary.SEVERITY_LABELS[finding["severity"]], rule, esc(summary.title(finding)),
                         esc(summary.location(finding)), esc(finding["message"]), detail_cells(finding),
                         esc(summary.KIND_LABELS[finding["kind"]]), esc(summary.status_label(finding)),
                         esc(finding["fingerprint"][:12])])
        lines += table(["Severity", "Rule", "Finding", "Location", "Guidance", "Details", "Kind", "Status",
                        "Fingerprint"], rows)
    return lines or ["No findings.", ""]


def recommendation_lines(model):
    if not model["recommendations"]:
        return ["No action required.", ""]
    lines = []
    for number, action in enumerate(model["recommendations"], 1):
        lines.append(f"{number}. **{summary.TOPIC_LABELS[action['topic']]}** ({action['count']}): {action['text']}")
    return lines + [""]


def exception_lines(model):
    rows = []
    for row in model["exceptions"]:
        status = summary.EXCEPTION_LABELS.get(row["status"], row["status"])
        if not row["suppressed"]:
            status += " (not applied)"
        rows.append([esc(row["fingerprint"][:12]), esc(row["rule"]), esc(row["location"]), esc(status),
                     esc(row["justification"]), esc(row["reason"]), esc(row["reviewer"]), esc(row["expires"]),
                     esc(row["ticket"])])
    if not rows:
        return ["No exceptions apply to this report.", ""]
    return table(["Fingerprint", "Rule", "Location", "Status", "Justification", "Reason", "Reviewer", "Expires",
                  "Ticket"], rows)


def stale_lines(model):
    policy = model["policy"]
    lines = []
    if policy["expired_exceptions"]:
        lines += ["Expired exceptions no longer suppress their findings:", ""]
        lines += table(["Fingerprint", "Expired"],
                       [[esc(e["fingerprint"]), esc(e["expires"])] for e in policy["expired_exceptions"]])
    if policy["stale_exceptions"]:
        lines += ["Stale exceptions match no finding in this report:", ""]
        lines += [f"- {esc(fingerprint)}" for fingerprint in policy["stale_exceptions"]] + [""]
    return lines or ["No expired or stale exceptions.", ""]


def error_lines(model):
    if not model["errors"]:
        return ["No errors.", ""]
    rows = [[esc(e["reason"]), esc(e.get("producer") or ""), esc("" if e.get("input") is None else e["input"]),
             esc(e.get("path") or "")] for e in model["errors"]]
    return table(["Reason", "Producer", "Input", "Path"], rows)


def inventory_lines(model):
    inventory = model["inventory"]
    if not inventory:
        return ["No software inventory was linked or generated.", ""]
    lines = [f"Components: {inventory['components']} ({esc(inventory['format'])} {esc(inventory['spec_version'])}). "
             f"Direct: {inventory['direct']}. Transitive: {inventory['transitive']}. "
             f"With findings: {inventory['with_findings']}.", ""]
    lines += table(["License", "Components"], [[esc(name), str(count)] for name, count in inventory["licenses"]])
    return lines


def posture_lines(model):
    posture = model["posture"]
    return [f"**Posture: {posture['label']}.** {posture['description']}", ""]


def technical(report, generated_at=None):
    model = summary.build(report, generated_at)
    lines = [f"# CRAB security report: {esc(report['target'])}", ""]
    lines += metadata_lines(model)
    lines += policy_lines(model)
    lines += ["## Summary", ""] + posture_lines(model) + severity_lines(model) + category_lines(model)
    lines += ["## Coverage", ""] + coverage_lines(model)
    lines += ["## Comparison", ""] + comparison_lines(model)
    lines += ["## Prioritized findings", "",
              "Order: known exploited and malicious first, then severity, EPSS and CVSS.", ""]
    lines += priority_lines(model)
    lines += ["## Recommendations", ""] + recommendation_lines(model)
    lines += ["## Findings by category", ""] + details_lines(report)
    lines += ["## Exceptions", ""] + exception_lines(model)
    lines += ["## Expired and stale exceptions", ""] + stale_lines(model)
    lines += ["## Errors", ""] + error_lines(model)
    lines += ["## Inventory and licenses", ""] + inventory_lines(model)
    lines += footer(model)
    return "\n".join(lines)


def executive(report, generated_at=None):
    model = summary.build(report, generated_at)
    meta = model["meta"]
    counts = model["counts"]
    found = model["signals"]
    lines = [f"# Security summary: {esc(report['target'])}", ""]
    context = [f"Revision {esc(meta['revision'] or 'not recorded')}",
               f"branch {esc(meta['branch'] or 'not recorded')}"]
    if meta["generated_at"]:
        context.append(f"generated {esc(meta['generated_at'])}")
    lines += [", ".join(context) + ".", ""]
    lines += policy_lines(model)
    lines += ["## Posture", ""] + posture_lines(model)
    covered = sum(1 for row in model["coverage"] if row["status"] in ("complete", "imported"))
    metrics = [
        ["Open findings", str(counts["total"])],
        ["Critical and high", str(counts["severity"]["critical"] + counts["severity"]["high"])],
        ["Known exploited (KEV)", str(found["kev"])],
        ["Malicious packages", str(found["malicious"])],
        ["Exposed secrets", str(found["secrets"])],
        ["Fix available", str(found["fixable"])],
        ["New since base", str(found["new"]) if model["comparison"] else "not compared"],
        ["Suppressed by exception", str(counts["suppressed"])],
        ["Scanner coverage", f"{covered} of {len(model['coverage'])} inputs complete"],
    ]
    lines += ["## Key metrics", ""] + table(["Metric", "Value"], metrics)
    lines += ["## Top risks", ""]
    top = model["top"][:EXECUTIVE_TOP]
    if top:
        rows = [[str(n), summary.SEVERITY_LABELS[f["severity"]], esc(summary.title(f)),
                 esc(summary.CATEGORY_LABELS[f["category"]]), esc(", ".join(summary.signal_labels(f)))]
                for n, f in enumerate(top, 1)]
        lines += table(["#", "Severity", "Risk", "Area", "Signals"], rows)
    else:
        lines += ["No open findings.", ""]
    lines += ["## Recommendations", ""] + recommendation_lines(model)
    lines += footer(model)
    return "\n".join(lines)


def footer(model):
    meta = model["meta"]
    return ["---", "", f"Generated by {esc(meta['tool'])} {esc(meta['tool_version'])}. "
            "Posture ratings and recommendations are written by CRAB from structured findings.", ""]


def render(report, *, template="technical", generated_at=None):
    builder = executive if template == "executive" else technical
    return builder(report, generated_at)
