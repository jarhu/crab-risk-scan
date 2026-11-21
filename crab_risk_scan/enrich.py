"""Offline prioritization data: FIRST EPSS scores and the CISA KEV catalog."""
import csv
import gzip
import io
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .evidence import array, load_json, number

CVE = re.compile(r"CVE-\d{4}-\d{4,19}")
EPSS_COMPRESSED_LIMIT = 64 * 1024 * 1024
EPSS_LIMIT = 256 * 1024 * 1024
KEV_LIMIT = 32 * 1024 * 1024


@dataclass
class Epss:
    scores: dict = field(default_factory=dict)      # CVE -> (score, percentile | None)
    date: str | None = None


def read_bounded(path, limit):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("expected regular file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file size limit")
    return raw


def load_epss(path):
    """Parse the FIRST EPSS CSV (optionally gzip-compressed) with bounded decompressed size."""
    raw = read_bounded(path, EPSS_COMPRESSED_LIMIT)
    if raw[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            raw = stream.read(EPSS_LIMIT + 1)
        if len(raw) > EPSS_LIMIT:
            raise ValueError("decompressed size limit")
    lines = raw.decode("utf-8-sig").splitlines()
    result = Epss()
    if lines and lines[0].startswith("#"):
        match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", lines[0])
        if match:
            result.date = match[1]
        lines = lines[1:]
    rows = csv.reader(lines)
    header = [h.strip().lower() for h in next(rows, [])]
    if header[:2] != ["cve", "epss"] or (len(header) > 2 and header[2] != "percentile"):
        raise ValueError("unexpected EPSS header")
    for row in rows:
        if not row:
            continue
        if len(row) != len(header) or not CVE.fullmatch(row[0].strip()):
            raise ValueError("invalid EPSS row")
        score = number(row[1].strip(), 0, 1)
        percentile = number(row[2].strip(), 0, 1) if len(row) > 2 else None
        result.scores[row[0].strip()] = (float(score), None if percentile is None else float(percentile))
    return result


def load_kev(path):
    """Return the CVE IDs listed in a CISA Known Exploited Vulnerabilities JSON catalog."""
    doc = load_json(path, KEV_LIMIT)
    found = set()
    for entry in array(doc["vulnerabilities"]):
        cve = entry["cveID"]
        if not isinstance(cve, str) or not CVE.fullmatch(cve):
            raise ValueError("invalid KEV entry")
        found.add(cve)
    return found


def cve_ids(finding):
    return [v for v in [finding["rule"], *finding.get("aliases", [])] if CVE.fullmatch(v)]


def apply(findings, *, epss=None, kev=None):
    """Annotate findings whose rule or aliases are CVE IDs. None leaves existing data untouched."""
    for hit in findings:
        ids = cve_ids(hit)
        if epss is not None:
            hit.pop("epss", None)
            known = [epss.scores[i] for i in ids if i in epss.scores]
            if known:
                score, percentile = max(known, key=lambda s: (s[0], s[1] or 0))
                hit["epss"] = {"score": score, "percentile": percentile, "date": epss.date}
        if kev is not None:
            hit.pop("kev", None)
            if any(i in kev for i in ids):
                hit["kev"] = True
    return findings
