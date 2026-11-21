"""Reporting engine: render one CRAB report into every supported export format."""
import json
import tempfile
from pathlib import Path

from . import codequality, csv_report, html, markdown, sarif, vex

FORMATS = ("json", "sarif", "markdown", "html", "csv", "docx", "codequality", "vex")
SBOM_FORMATS = ("cyclonedx-json", "spdx-json")
TEMPLATES = ("technical", "executive")
TEMPLATE_FORMATS = ("markdown", "html", "docx")


def format_for_path(path):
    """Return the export format for an output path, or "sbom:<format>" for inventories."""
    name = Path(path).name.lower()
    if name.endswith(".cdx.json"):
        return "sbom:cyclonedx-json"
    if name.endswith(".spdx.json"):
        return "sbom:spdx-json"
    if name.endswith(".vex.json"):
        return "vex"
    if name.endswith(".codequality.json") or name == "gl-code-quality-report.json":
        return "codequality"
    if name.endswith((".sarif", ".sarif.json")):
        return "sarif"
    if name.endswith(".json"):
        return "json"
    if name.endswith((".md", ".markdown")):
        return "markdown"
    if name.endswith((".html", ".htm")):
        return "html"
    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".docx"):
        return "docx"
    raise ValueError(f"unsupported output format: {Path(path).name}")


def sbom_formats_for(outputs):
    """SBOM formats that the requested outputs need generated."""
    kinds = (format_for_path(path) for path in outputs)
    return sorted({kind.removeprefix("sbom:") for kind in kinds if kind.startswith("sbom:")})


def is_docx_template(template):
    return template is not None and str(template).lower().endswith(".docx")


def check_template(fmt, template):
    """Validate a template choice; returns the normalized template."""
    if template is None or template == "technical":
        return "technical"
    if template == "executive":
        if fmt not in TEMPLATE_FORMATS:
            raise ValueError(f"the executive template applies to markdown, html and docx, not {fmt}")
        return template
    if is_docx_template(template):
        if fmt != "docx":
            raise ValueError(f"a .docx template applies to docx output only, not {fmt}")
        return template
    raise ValueError(f"unknown template: {template} (use technical, executive or a .docx file)")


def _json(document):
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def render(report, fmt, *, template=None, generated_at=None):
    """Render a report as bytes. Output is deterministic when generated_at is None."""
    if fmt not in FORMATS:
        raise ValueError(f"unsupported output format: {fmt}")
    template = check_template(fmt, template)
    if fmt == "json":
        return _json(report)
    if fmt == "sarif":
        return _json(sarif.render(report))
    if fmt == "codequality":
        return _json(codequality.render(report))
    if fmt == "vex":
        return _json(vex.render(report, generated_at))
    if fmt == "csv":
        return csv_report.render(report).encode("utf-8")
    if fmt == "markdown":
        return markdown.render(report, template=template, generated_at=generated_at).encode("utf-8")
    if fmt == "html":
        return html.render(report, template=template, generated_at=generated_at).encode("utf-8")
    from . import docx_report
    return docx_report.render(report, template=template, generated_at=generated_at)


def template_for(fmt, template):
    """Template passed to one output of a multi-output write: machine formats ignore templates."""
    if template is None or fmt not in TEMPLATE_FORMATS:
        return None
    if is_docx_template(template) and fmt != "docx":
        return None
    return template


def write_outputs(report, outputs, *, sboms=None, template=None, generated_at=None):
    """Write each output atomically. The format follows the file name.

    The template applies to the outputs that support it: technical or executive to
    Markdown, HTML and DOCX, a .docx template to DOCX only.
    """
    if template is not None and template not in TEMPLATES and not is_docx_template(template):
        raise ValueError(f"unknown template: {template} (use technical, executive or a .docx file)")
    written = []
    for path in map(Path, outputs):
        kind = format_for_path(path)
        if kind.startswith("sbom:"):
            document = (sboms or {}).get(kind.removeprefix("sbom:"))
            if document is None:
                raise ValueError(f"no {kind.removeprefix('sbom:')} inventory was generated")
            data = _json(document)
        else:
            data = render(report, kind, template=template_for(kind, template), generated_at=generated_at)
        atomic_write(path, data)
        written.append(path)
    return written


def atomic_write(path, data):
    """Write bytes to path through a temporary file in the same directory."""
    path = Path(path)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, dir=path.parent, prefix=".crab-", suffix=".tmp") as stream:
            temp_path = Path(stream.name)
            stream.write(data)
        temp_path.replace(path)
        temp_path = None
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)
