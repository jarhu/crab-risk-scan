"""DOCX reports: technical and executive templates, plus custom ``.docx`` templates.

python-docx is an optional extra and is imported only when a DOCX is rendered.
Output is deterministic: core properties and ZIP entry times use the
caller-supplied ``generated_at`` or a fixed epoch.
"""
import io
import re
import zipfile
from pathlib import Path

from . import summary

MARKER = "{{CRAB_REPORT}}"
TEMPLATE_LIMIT = 25 * 1024 * 1024
TEMPLATE_EXPANDED_LIMIT = 100 * 1024 * 1024
TEMPLATE_ENTRY_LIMIT = 2000
# Parts that run code or embed foreign objects when the document is opened.
ACTIVE_PARTS = re.compile(r"vbaProject|vbaData|activeX|oleObject|/embeddings/", re.IGNORECASE)
RELATIONSHIP = re.compile(rb"<(?:\w+:)?Relationship\b[^>]*>")
EXTERNAL_TARGET = re.compile(rb"""\bTargetMode\s*=\s*["']External["']""")
HYPERLINK_TYPE = re.compile(rb"""\bType\s*=\s*["'][^"']*/relationships/hyperlink["']""")
DETAIL_LIMIT = 200
EXECUTIVE_TOP = 10
SUMMARY_TOP = 5

_ILLEGAL_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def clean(value):
    if value is None:
        return ""
    return _ILLEGAL_XML.sub(" ", str(value))


def load_docx():
    try:
        import docx
        from docx.oxml.ns import qn
        from docx.shared import Pt
        from docx.text.run import Run
    except ImportError as error:
        raise ValueError("DOCX output needs python-docx. Install it with: "
                         "pip install 'crab-risk-scan[docx]'") from error
    return docx, qn, Pt, Run


class Writer:
    """Appends content to a document using styles only when the document defines them."""

    def __init__(self, document, pt):
        self.doc = document
        self.pt = pt
        self.styles = {style.name for style in document.styles}

    def style(self, *names):
        return next((name for name in names if name in self.styles), None)

    def paragraph(self, text="", style=None, bold=False):
        chosen = self.style(style) if style else None
        paragraph = self.doc.add_paragraph(style=chosen)
        if text:
            run = paragraph.add_run(clean(text))
            run.bold = bold or None
        return paragraph

    def labelled(self, label, text):
        paragraph = self.doc.add_paragraph()
        paragraph.add_run(clean(label) + ": ").bold = True
        paragraph.add_run(clean(text))
        return paragraph

    def heading(self, text, level):
        style = self.style("Title") if level == 0 else self.style(f"Heading {level}")
        if style:
            return self.doc.add_paragraph(clean(text), style=style)
        paragraph = self.doc.add_paragraph()
        run = paragraph.add_run(clean(text))
        run.bold = True
        run.font.size = self.pt(max(11, 24 - 3 * level))
        return paragraph

    def bullet(self, text):
        style = self.style("List Bullet")
        return self.doc.add_paragraph(clean(text) if style else "\u2022 " + clean(text), style=style)

    def numbered(self, number, label, text):
        style = self.style("List Number")
        paragraph = self.doc.add_paragraph(style=style)
        if not style:
            paragraph.add_run(f"{number}. ")
        paragraph.add_run(clean(label) + ": ").bold = True
        paragraph.add_run(clean(text))
        return paragraph

    def table(self, headers, rows):
        table = self.doc.add_table(rows=1, cols=len(headers))
        style = self.style("Light Grid Accent 1", "Table Grid")
        if style:
            table.style = style
        for cell, header in zip(table.rows[0].cells, headers):
            cell.text = ""
            cell.paragraphs[0].add_run(clean(header)).bold = True
        for row in rows:
            cells = table.add_row().cells
            for cell, value in zip(cells, row):
                cell.text = clean(value)
        self.doc.add_paragraph()
        return table

    def fields(self, pairs):
        table = self.doc.add_table(rows=0, cols=2)
        style = self.style("Table Grid")
        if style:
            table.style = style
        for label, value in pairs:
            cells = table.add_row().cells
            cells[0].paragraphs[0].add_run(clean(label)).bold = True
            cells[1].text = clean(value)
        self.doc.add_paragraph()
        return table

    def page_break(self):
        from docx.enum.text import WD_BREAK
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def policy_headline(status):
    return {"passed": "Policy passed.", "failed": "Policy failed.",
            "incomplete": "Scan incomplete. Errors occurred, so the result is not conclusive."}[status]


def key_metrics(model):
    counts = model["counts"]
    found = model["signals"]
    covered = sum(1 for row in model["coverage"] if row["status"] in ("complete", "imported"))
    return [
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


def metadata_pairs(model):
    meta = model["meta"]
    pairs = [("Target", meta["target"])]
    if meta["repository"]:
        pairs.append(("Repository", meta["repository"]))
    pairs += [("Revision", meta["revision"] or "not recorded"), ("Branch", meta["branch"] or "not recorded"),
              ("Tool", f"{meta['tool']} {meta['tool_version']}")]
    if meta["generated_at"]:
        pairs.append(("Generated", meta["generated_at"]))
    return pairs


def write_posture(w, model):
    posture = model["posture"]
    w.labelled("Posture", f"{posture['label']}. {posture['description']}")


def write_policy(w, model, level):
    policy = model["policy"]
    w.heading("Policy", level)
    w.paragraph(policy_headline(policy["status"]), bold=True)
    w.fields([
        ("Source", "policy file" if policy["source"] == "policy-file" else "default policy"),
        ("Severity threshold", policy["minimum_severity"]),
        ("New findings only", "yes" if policy["new_only"] else "no"),
        ("Review signals included", "yes" if policy["include_review"] else "no"),
        ("Actionable findings", str(policy["actionable"])),
        ("Suppressed findings", str(policy["suppressed"])),
        ("Disabled by policy rules", str(policy["disabled_findings"])),
        ("Expired exceptions", str(len(policy["expired_exceptions"]))),
        ("Stale exceptions", str(len(policy["stale_exceptions"]))),
    ])
    if policy["violations"]:
        w.paragraph("Violations:", bold=True)
        for text in policy["violations"]:
            w.bullet(text)


def write_recommendations(w, model):
    if not model["recommendations"]:
        w.paragraph("No action required.")
        return
    for number, action in enumerate(model["recommendations"], 1):
        w.numbered(number, f"{summary.TOPIC_LABELS[action['topic']]} ({action['count']})", action["text"])


def write_top(w, model, limit):
    top = model["top"][:limit]
    if not top:
        w.paragraph("No open findings.")
        return
    w.table(["#", "Severity", "Risk", "Area", "Signals"],
            [[str(n), summary.SEVERITY_LABELS[f["severity"]], summary.title(f),
              summary.CATEGORY_LABELS[f["category"]], ", ".join(summary.signal_labels(f))]
             for n, f in enumerate(top, 1)])


def finding_pairs(finding):
    pairs = [("Rule", summary.rule_id(finding)),
             ("Category", summary.CATEGORY_LABELS[finding["category"]]),
             ("Kind", summary.KIND_LABELS[finding["kind"]]),
             ("Location", summary.location(finding)),
             ("Status", summary.status_label(finding)),
             ("Guidance", finding["message"])]
    if finding.get("cwe"):
        pairs.append(("CWE", ", ".join(finding["cwe"])))
    reference = summary.package_ref(finding)
    if reference:
        pairs.append(("Package", reference))
    if finding.get("fixed_version"):
        pairs.append(("Fixed version", finding["fixed_version"]))
    if finding.get("license"):
        pairs.append(("License", finding["license"]))
    if finding.get("cvss"):
        vector = finding["cvss"].get("vector")
        pairs.append(("CVSS", f"{finding['cvss']['score']:.1f}" + (f" ({vector})" if vector else "")))
    if finding.get("epss"):
        pairs.append(("EPSS", f"{finding['epss']['score']:.4f}"))
    if finding.get("kev") is True:
        pairs.append(("CISA KEV", "listed"))
    if finding.get("new") is True:
        pairs.append(("New since base", "yes"))
    if finding.get("help_uri"):
        pairs.append(("Reference", finding["help_uri"]))
    pairs.append(("Fingerprint", finding["fingerprint"]))
    return pairs


def write_details(w, report, model):
    ranked = model["top"] + [f for f in report["findings"] if f.get("suppressed")]
    detailed = ranked[:DETAIL_LIMIT]
    if not detailed:
        w.paragraph("No findings.")
        return
    for level in summary.SEVERITIES:
        group = [f for f in detailed if f["severity"] == level]
        if not group:
            continue
        w.heading(f"{summary.SEVERITY_LABELS[level]} ({len(group)})", 2)
        for finding in group:
            w.heading(summary.title(finding), 3)
            w.fields(finding_pairs(finding))
    rest = ranked[DETAIL_LIMIT:]
    if rest:
        w.heading("Additional findings", 2)
        w.paragraph(f"{len(rest)} further findings are listed without detail. The JSON report has every field.")
        w.table(["Severity", "Rule", "Location", "Status", "Fingerprint"],
                [[summary.SEVERITY_LABELS[f["severity"]], summary.rule_id(f), summary.location(f),
                  summary.status_label(f), f["fingerprint"][:12]] for f in rest])


def write_exceptions(w, model):
    rows = model["exceptions"]
    if rows:
        w.table(["Rule", "Location", "Status", "Reason", "Reviewer", "Expires", "Ticket"],
                [[r["rule"], r["location"],
                  summary.EXCEPTION_LABELS.get(r["status"], r["status"])
                  + (f" ({r['justification']})" if r["justification"] else "")
                  + ("" if r["suppressed"] else " (not applied)"),
                  r["reason"], r["reviewer"], r["expires"], r["ticket"]] for r in rows])
    else:
        w.paragraph("No exceptions apply to this report.")
    policy = model["policy"]
    if policy["expired_exceptions"]:
        w.paragraph("Expired exceptions no longer suppress their findings:", bold=True)
        for entry in policy["expired_exceptions"]:
            w.bullet(f"{entry['fingerprint']} expired {entry['expires']}")
    if policy["stale_exceptions"]:
        w.paragraph("Stale exceptions match no finding in this report:", bold=True)
        for fingerprint in policy["stale_exceptions"]:
            w.bullet(fingerprint)


def write_scope(w, report, model):
    w.heading("Scope and coverage", 1)
    w.fields(metadata_pairs(model) + [("Files checked by built-in rules", str(report["files_scanned"]))])
    if model["coverage"]:
        w.table(["Input", "Producer", "Origin", "Status", "Reason", "Version", "Findings"],
                [[str(r["input"]), r["producer"], r["origin"], r["status"], r["reason"], r["version"],
                  str(r["findings"])] for r in model["coverage"]])
    w.paragraph("Coverage is complete." if model["coverage_complete"] else
                "Coverage is incomplete. Skipped, partial or failed inputs did not contribute every result.")
    if model["errors"]:
        w.heading("Errors", 2)
        w.table(["Reason", "Producer", "Input", "Path"],
                [[e["reason"], e.get("producer") or "", "" if e.get("input") is None else str(e["input"]),
                  e.get("path") or ""] for e in model["errors"]])
    inventory = model["inventory"]
    w.heading("Inventory and licenses", 2)
    if inventory:
        w.paragraph(f"Components: {inventory['components']}. Direct: {inventory['direct']}. "
                    f"Transitive: {inventory['transitive']}. With findings: {inventory['with_findings']}.")
        w.table(["License", "Components"], [[name, str(count)] for name, count in inventory["licenses"]])
    else:
        w.paragraph("No software inventory was linked or generated.")


def write_severity(w, model):
    counts = model["counts"]
    w.heading("Findings by severity", 1)
    w.table(["Severity", "Open findings"],
            [[summary.SEVERITY_LABELS[level], str(counts["severity"][level])] for level in summary.SEVERITIES]
            + [["Total open", str(counts["total"])], ["Suppressed", str(counts["suppressed"])]])
    w.heading("By category", 2)
    w.table(["Category", *(summary.SEVERITY_LABELS[level] for level in summary.SEVERITIES), "Total"],
            [[summary.CATEGORY_LABELS[c], *(str(counts["matrix"][c][level]) for level in summary.SEVERITIES),
              str(counts["category"][c])] for c in summary.CATEGORIES])
    comparison = model["comparison"]
    w.heading("Comparison", 2)
    if comparison:
        w.paragraph(f"Base revision: {comparison.get('base_revision') or 'not recorded'}. New: {comparison['new']}. "
                    f"Unchanged: {comparison['unchanged']}. Fixed: {len(comparison['fixed'])}.")
        if comparison["fixed"]:
            w.table(["Severity", "Rule", "Location", "Fingerprint"],
                    [[summary.SEVERITY_LABELS.get(f["severity"], f["severity"]), f"{f['producer']}/{f['rule']}",
                      (f.get("path") or "") + (f":{f['line']}" if f.get("line") else "")
                      if f.get("path") else (summary.package_ref(f) or "not located"),
                      f["fingerprint"][:12]] for f in comparison["fixed"]])
    else:
        w.paragraph("No base report was given, so new and fixed findings are not computed.")


def write_methodology(w):
    w.heading("Appendix: methodology", 1)
    w.paragraph("CRAB runs built-in checks and external scanners on a snapshot of the target, imports saved "
                "scanner reports, and normalizes every result into one finding model. Findings carry a "
                "line-independent fingerprint, so exceptions survive unrelated edits.")
    w.paragraph("Severity order: critical, high, medium, low, info, unknown. Policy rules can override a "
                "producer severity; the original value is kept.")
    w.paragraph("Prioritization: findings listed in CISA KEV and malicious packages come first, then severity, "
                "EPSS probability and CVSS score.")
    w.heading("Posture rating", 2)
    w.table(["Rating", "Condition"], [[label, text] for _, label, text in summary.POSTURE_LEVELS])
    w.paragraph("When coverage is incomplete, the rating is a lower bound.")
    w.heading("Exceptions", 2)
    w.paragraph("Accepted: the risk is accepted and the component stays affected. False positive: the finding "
                "is incorrect. Not affected: the code is not exploitable, with a CycloneDX VEX justification. "
                "Expired exceptions stop suppressing their findings.")
    w.heading("Limitations", 2)
    w.paragraph("Results depend on the scanners that ran and their rule packs. Skipped and failed inputs are "
                "listed under coverage. Recommendations are written by CRAB from structured findings and do "
                "not replace a review of the affected code.")


def technical_body(w, report, model):
    w.heading("Executive summary", 1)
    write_posture(w, model)
    w.paragraph(policy_headline(model["policy"]["status"]), bold=True)
    w.table(["Metric", "Value"], key_metrics(model))
    w.heading("Top risks", 2)
    write_top(w, model, SUMMARY_TOP)
    w.heading("Recommendations", 2)
    write_recommendations(w, model)
    write_scope(w, report, model)
    write_policy(w, model, 1)
    write_severity(w, model)
    w.heading("Detailed findings", 1)
    write_details(w, report, model)
    w.heading("Exceptions", 1)
    write_exceptions(w, model)
    write_methodology(w)


def technical(w, report, model):
    w.heading("Security assessment report", 0)
    w.paragraph(report["target"], style="Subtitle")
    w.fields(metadata_pairs(model))
    write_posture(w, model)
    w.page_break()
    technical_body(w, report, model)


def executive(w, report, model):
    w.heading("Security summary", 0)
    w.paragraph(report["target"], style="Subtitle")
    w.fields(metadata_pairs(model))
    w.heading("Posture", 1)
    write_posture(w, model)
    w.heading("Key metrics", 1)
    w.table(["Metric", "Value"], key_metrics(model))
    w.heading("Top risks", 1)
    write_top(w, model, EXECUTIVE_TOP)
    w.heading("Recommendations", 1)
    write_recommendations(w, model)
    write_policy(w, model, 1)


def placeholder_values(report, generated_at):
    date = summary.as_datetime(generated_at).date().isoformat() if generated_at is not None else "not recorded"
    return {
        "{{TARGET}}": clean(report["target"]),
        "{{REVISION}}": clean(report.get("revision") or "not recorded"),
        "{{BRANCH}}": clean(report.get("branch") or "not recorded"),
        "{{DATE}}": date,
        "{{TOOL_VERSION}}": clean(report["tool"]["version"]),
    }


def part_roots(document):
    roots = [document.element.body]
    for section in document.sections:
        for part in (section.header, section.first_page_header, section.even_page_header,
                     section.footer, section.first_page_footer, section.even_page_footer):
            if not part.is_linked_to_previous:
                roots.append(part._element)
    return roots


def replace_placeholders(document, values, qn, run_type):
    runs_path = "./w:r | ./w:hyperlink/w:r | ./w:ins/w:r | ./w:smartTag/w:r | ./w:fldSimple/w:r"
    for root in part_roots(document):
        for paragraph in root.iter(qn("w:p")):
            runs = [run_type(element, None) for element in paragraph.xpath(runs_path)]
            text = "".join(run.text for run in runs)
            if not any(key in text for key in values):
                continue
            for run in runs:
                for key, value in values.items():
                    if key in run.text:
                        run.text = run.text.replace(key, value)
            text = "".join(run.text for run in runs)
            if any(key in text for key in values):
                for key, value in values.items():
                    text = text.replace(key, value)
                runs[0].text = text
                for run in runs[1:]:
                    run.text = ""


def find_marker(document, qn):
    for paragraph in document.element.body.iter(qn("w:p")):
        text = "".join(node.text or "" for node in paragraph.iter(qn("w:t")))
        if text.strip() == MARKER:
            return paragraph
    return None


def check_template(path):
    """Refuse templates that expand too far or pull external content into generated reports.

    External hyperlinks are kept: they need a click. External templates, frames, images and
    other external parts load on open, which turns a report into a beacon or, with a UNC target,
    an NTLM credential leak.
    """
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as error:
        raise ValueError(f"DOCX template could not be opened: {path.name}") from error
    with archive:
        entries = archive.infolist()
        if len(entries) > TEMPLATE_ENTRY_LIMIT or sum(entry.file_size for entry in entries) > TEMPLATE_EXPANDED_LIMIT:
            raise ValueError(f"DOCX template expands beyond {TEMPLATE_EXPANDED_LIMIT // (1024 * 1024)} MiB "
                             f"or {TEMPLATE_ENTRY_LIMIT} parts: {path.name}")
        for entry in entries:
            if ACTIVE_PARTS.search(entry.filename):
                raise ValueError(f"DOCX template contains macros or embedded objects: {path.name}")
            if entry.filename.lower().endswith(".rels"):
                for relationship in RELATIONSHIP.findall(archive.read(entry)):
                    if EXTERNAL_TARGET.search(relationship) and not HYPERLINK_TYPE.search(relationship):
                        raise ValueError(f"DOCX template references external content: {path.name}")


def open_template(docx, template):
    path = Path(template)
    if path.suffix.lower() != ".docx":
        raise ValueError(f"DOCX template must be a .docx file: {path.name}")
    if not path.is_file():
        raise ValueError(f"DOCX template not found: {path.name}")
    if path.stat().st_size > TEMPLATE_LIMIT:
        raise ValueError(f"DOCX template exceeds {TEMPLATE_LIMIT // (1024 * 1024)} MiB: {path.name}")
    check_template(path)
    try:
        return docx.Document(str(path))
    except Exception as error:  # python-docx raises several unrelated types for damaged packages
        raise ValueError(f"DOCX template could not be opened: {path.name}") from error


def add_footer(document, report):
    for section in document.sections:
        footer = section.footer
        paragraph = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
        revision = report.get("revision") or "no revision"
        paragraph.text = clean(f"CRAB {report['tool']['version']} | {report['target']} | {revision}")


def set_properties(document, report, template, generated_at):
    properties = document.core_properties
    when = summary.as_datetime(generated_at).replace(microsecond=0)
    kind = "Executive security summary" if template == "executive" else "Security assessment report"
    properties.title = clean(f"{kind}: {report['target']}")
    properties.subject = clean(report["target"])
    properties.author = "crab-risk-scan"
    properties.last_modified_by = "crab-risk-scan"
    properties.keywords = "security; CRAB"
    properties.category = "Security report"
    properties.comments = ""
    properties.created = when
    properties.modified = when
    properties.last_printed = when
    properties.revision = 1


def deterministic_zip(data, generated_at):
    when = summary.as_datetime(generated_at)
    stamp = (when.year, when.month, when.day, when.hour, when.minute, when.second - when.second % 2)
    if when.year < 1980:
        stamp = (1980, 1, 1, 0, 0, 0)
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, \
            zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            entry = zipfile.ZipInfo(info.filename, date_time=stamp)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            target.writestr(entry, source.read(info.filename))
    return output.getvalue()


def render(report, *, template="technical", generated_at=None):
    docx, qn, pt, run_type = load_docx()
    model = summary.build(report, generated_at)
    custom = template not in (None, "technical", "executive")
    if custom:
        document = open_template(docx, template)
        replace_placeholders(document, placeholder_values(report, generated_at), qn, run_type)
        marker = find_marker(document, qn)
        body = document.element.body
        existing = set(body.iterchildren())
        technical_body(Writer(document, pt), report, model)
        if marker is not None:
            for element in [child for child in body.iterchildren() if child not in existing]:
                marker.addprevious(element)
            if marker.getparent() is body:
                body.remove(marker)
            else:
                for child in list(marker):
                    if child.tag != qn("w:pPr"):
                        marker.remove(child)
    else:
        document = docx.Document()
        writer = Writer(document, pt)
        (executive if template == "executive" else technical)(writer, report, model)
        add_footer(document, report)
    set_properties(document, report, template, generated_at)
    buffer = io.BytesIO()
    document.save(buffer)
    return deterministic_zip(buffer.getvalue(), generated_at)
