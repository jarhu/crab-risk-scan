"""Collect one snapshot, retain provenance, and account for incomplete inputs."""
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .adapters import ADAPTERS
from .evidence import (CATEGORIES, INVALID, LEVELS, SourceLines, array, assign_fingerprints, http_uri, load_json,
                       mapping, relative_path, token)
from .policy import evaluate
from .triage import link_inventory

INVENTORY_LIMIT = 32 * 1024 * 1024
# CWE for each built-in rule.
BUILTIN_CWE = {"CRAB-PY-001": ["CWE-295"], "CRAB-CTR-001": ["CWE-250"], "CRAB-HTML-001": ["CWE-319"],
               "CRAB-SQL-001": ["CWE-732"]}
STATUSES = {"complete", "partial", "failed", "skipped"}


def manifest(path):
    data = mapping(load_json(path))
    if data["version"] != 1 or set(data) - {"version", "revision", "reports"}:
        raise ValueError("unsupported manifest")
    inputs = []
    for entry in array(data["reports"]):
        name, status = entry["producer"], entry["status"]
        if (name not in ADAPTERS or status not in STATUSES
                or set(entry) - {"producer", "version", "rule_pack", "status", "file", "reason"}):
            raise ValueError("invalid producer metadata")
        meta = {"status": status}
        for key in ("version", "rule_pack"):
            # Every completed input declares its provenance; skipped engines may lack a version.
            meta[key] = None if entry.get(key) is None and status == "skipped" else token(entry[key])
        if "reason" in entry:
            meta["reason"] = token(entry["reason"])
        file = None
        if "file" in entry:
            file = path.parent / relative_path(entry["file"])
            if not file.resolve().is_relative_to(path.parent.resolve()):
                raise ValueError("report outside manifest folder")
        elif status in {"complete", "partial"}:
            raise ValueError("report file required")
        inputs.append((name, None if status == "skipped" else file, meta))
    return token(data["revision"]), inputs


def builtin(local, root, sources):
    findings = []
    for hit in local:
        module = "Burrow" if hit["rule"] == "CRAB-CTR-001" else "Claws"
        entry = {"producer": "crab", "producer_version": __version__, "rule_pack": "pinch-v1", "module": module,
                 "category": CATEGORIES[module], "kind": "review", "rule": hit["rule"],
                 "severity": hit["severity"], "original_severity": hit["severity"], "message": hit["message"],
                 "path": hit["path"], "line": hit["line"]}
        for key in ("end_line", "byte_offset", "end_byte_offset"):
            if hit.get(key) is not None:
                entry[key] = hit[key]
        if hit["rule"] in BUILTIN_CWE:
            entry["cwe"] = list(BUILTIN_CWE[hit["rule"]])
        findings.append(entry)
    return assign_fingerprints(findings, root, sources)


def clean_repository(value):
    """Keep scheme, host and path of an http(s) repository URL; drop credentials, query and fragment."""
    if http_uri(value) is None:
        raise ValueError("invalid repository URL")
    parts = urlsplit(value)
    host = parts.hostname or ""
    if not host:
        raise ValueError("invalid repository URL")
    netloc = ("[" + host + "]" if ":" in host else host) + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def snapshot(revision, branch, repository, errors):
    checks = (("revision", revision, token),
              ("branch", branch, lambda v: v if isinstance(v, str) and 0 < len(v) <= 256
               and not any(ord(c) < 32 or ord(c) == 0x7f for c in v) else token(None)),
              ("repository", repository, clean_repository))
    values = []
    for name, value, check in checks:
        try:
            values.append(None if value is None else check(value))
        except INVALID:
            errors.append({"reason": "invalid_" + name})
            values.append(None)
    return values


def collect(local, *, root, inputs=(), run_manifest=None, revision=None, branch=None, repository=None,
            inventory=None, policy=None, exceptions=None, fail_on=None, new_since=None,
            epss=None, kev=None, today=None):
    """Build a complete schema-3 report from built-in hits, producer reports and policy inputs."""
    root = Path(root)
    errors = [dict(e) for e in local["errors"]]
    revision, branch, repository = snapshot(revision, branch, repository, errors)
    sources = SourceLines(root)
    findings = builtin(local["findings"], root, sources)
    inputs = list(inputs)
    if run_manifest:
        try:
            declared, listed = manifest(Path(run_manifest))
            if revision and revision != declared:
                raise ValueError("snapshot mismatch")
            revision = declared
            inputs.extend((name, file, dict(meta, origin="manifest")) for name, file, meta in listed)
        except INVALID:
            errors.append({"reason": "invalid_run_manifest"})
    imports = []
    for index, (name, path, meta) in enumerate(inputs, 1):
        meta = dict(meta or {})
        version, rule_pack = (identifier(meta.get(k)) for k in ("version", "rule_pack"))
        status = meta.get("status")
        entry = {"input": index, "producer": name, "origin": meta.get("origin", "report"), "status": "failed",
                 "producer_version": version, "rule_pack": rule_pack, "targets": None}
        imports.append(entry)
        if entry["origin"] not in {"engine", "report", "manifest"} or name not in ADAPTERS:
            entry.update(producer=identifier(name) or "unknown", origin="report", reason="invalid_report")
            errors.append({"input": index, "reason": "invalid_report"})
            continue
        if status == "skipped":
            entry.update(status="skipped", reason=identifier(meta.get("reason")) or "not_applicable")
            continue
        if status == "failed" or path is None:
            entry["reason"] = identifier(meta.get("reason")) or "producer_failed"
            errors.append({"input": index, "producer": name, "reason": "producer_failed"})
            continue
        try:
            batch = ADAPTERS[name](load_json(path), root)
            if batch.version and version and batch.version != version:
                raise ValueError("version mismatch")
            version = batch.version or version
            entry.update(producer_version=version, targets=batch.targets,
                         status=status if status in {"complete", "partial"} else "imported")
            if batch.partial or status == "partial":
                entry.update(status="partial", reason="producer_partial")
                errors.append({"input": index, "producer": name, "reason": "producer_partial"})
            for hit in batch.findings:
                hit.setdefault("producer_version", version)
                hit.update(rule_pack=rule_pack, inputs=[index])
            findings.extend(assign_fingerprints(batch.findings, root, sources))
        except INVALID:
            entry["reason"] = "invalid_report"
            errors.append({"input": index, "producer": name, "reason": "invalid_report"})
    findings.sort(key=lambda f: (LEVELS.index(f["severity"]), f["path"] or "", f.get("line") or 0,
                                 f["rule"], f["fingerprint"], f.get("inputs", [0])))
    unique = {}
    for hit in findings:
        kept = unique.setdefault(hit["fingerprint"], hit)
        if kept is not hit and "inputs" in hit:
            kept.setdefault("inputs", []).extend(hit["inputs"])
            if "aliases" in hit:
                kept["aliases"] = sorted(set(kept.get("aliases", []) + hit["aliases"]))
    observations = list(unique.values())
    for hit in observations:
        if "inputs" in hit:
            hit["inputs"] = sorted(set(hit["inputs"]))
    target = root.resolve().name[:256] or "target"
    report = {"schema_version": 3, "tool": {"name": "crab-risk-scan", "version": __version__},
              "target": target, "revision": revision, "branch": branch, "repository": repository,
              "files_scanned": local["files_scanned"], "imports": imports, "findings": observations,
              "groups": [], "errors": errors}
    if inventory is not None:
        try:
            doc = inventory if isinstance(inventory, dict) else load_json(Path(inventory), INVENTORY_LIMIT)
            report["inventory"] = link_inventory(doc, observations)
        except INVALID:
            errors.append({"reason": "invalid_inventory"})
    return evaluate(report, policy=policy, exceptions=exceptions, fail_on=fail_on, new_since=new_since,
                    epss=epss, kev=kev, today=today)


def identifier(value):
    if value is None:
        return None
    return value if isinstance(value, str) and re.fullmatch(r"[\w@.+:/~^!-]{1,256}", value, re.ASCII) else None
