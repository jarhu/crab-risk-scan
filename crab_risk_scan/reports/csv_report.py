"""CSV export: one row per finding.

Text cells that a spreadsheet would evaluate as a formula (leading ``=``, ``+``,
``-``, ``@``, tab or carriage return) are prefixed with an apostrophe.
"""
import csv
import io

from . import summary

COLUMNS = ("severity", "category", "kind", "producer", "rule", "title", "path", "line", "end_line",
           "package", "version", "fixed_version", "cwe", "cvss", "epss", "kev", "status",
           "exception_status", "new", "fingerprint")

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def guard(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def row(finding):
    package = finding.get("package") or {}
    return {
        "severity": finding["severity"],
        "category": finding["category"],
        "kind": finding["kind"],
        "producer": finding["producer"],
        "rule": finding["rule"],
        "title": summary.title(finding),
        "path": finding.get("path"),
        "line": finding.get("line"),
        "end_line": finding.get("end_line"),
        "package": package.get("name"),
        "version": package.get("version"),
        "fixed_version": finding.get("fixed_version"),
        "cwe": ";".join(finding.get("cwe") or ()),
        "cvss": (finding.get("cvss") or {}).get("score"),
        "epss": (finding.get("epss") or {}).get("score"),
        "kev": finding.get("kev") is True,
        "status": "suppressed" if finding.get("suppressed") else "open",
        "exception_status": (finding.get("exception") or {}).get("status"),
        "new": finding.get("new") if "new" in finding else None,
        "fingerprint": finding["fingerprint"],
    }


def render(report):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    for finding in report["findings"]:
        writer.writerow({key: guard(value) for key, value in row(finding).items()})
    return buffer.getvalue()
