"""GitLab Code Quality report (Code Climate subset accepted by GitLab).

Only open findings with a checkout path are included, because GitLab anchors
every entry to a file in the merge request diff.
"""
from . import summary

SEVERITIES = {"critical": "blocker", "high": "critical", "medium": "major",
              "unknown": "major", "low": "minor", "info": "info"}


def render(report):
    issues = []
    for finding in summary.open_findings(report):
        path = summary.checkout_path(finding)
        if not path:
            continue
        lines = {"begin": finding.get("line") or 1}
        if finding.get("line") and finding.get("end_line"):
            lines["end"] = finding["end_line"]
        issues.append({
            "description": f"{summary.title(finding)}: {finding['message']}",
            "check_name": summary.rule_id(finding),
            "fingerprint": finding["fingerprint"],
            "severity": SEVERITIES[finding["severity"]],
            "location": {"path": path, "lines": lines},
            "categories": ["Security"],
            "type": "issue",
        })
    return issues
