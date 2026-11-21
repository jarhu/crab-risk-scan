"""Validation shared by the saved-report adapters, fingerprints and package identities."""
import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote, unquote, urlsplit

LEVELS = ("critical", "high", "medium", "low", "info", "unknown")
INVALID = (KeyError, TypeError, AttributeError, ValueError, OSError, RecursionError, IndexError)
CATEGORIES = {"Claws": "sast", "Sniffer": "secrets", "Burrow": "iac", "Shell": "sca", "Exoskeleton": "container"}
SOURCE_LIMIT = 16 * 1024 * 1024


def reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name}")


def load_json(path, limit=16 * 1024 * 1024):
    """Parse a bounded regular JSON file. NaN and Infinity are rejected, as strict JSON requires."""
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("expected regular file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file size limit")
    return json.loads(raw, parse_constant=reject_constant)


def array(value):
    if not isinstance(value, list):
        raise ValueError("expected JSON array")
    return value


def mapping(value):
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[\w@.+:/~^!-]{1,256}", value, re.ASCII):
        raise ValueError("invalid identifier")
    return value


def text(value, limit=256):
    """A bounded single-line string without control characters."""
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or any(ord(c) < 32 or 0x7f <= ord(c) < 0xa0 for c in value)):
        raise ValueError("invalid text")
    return value


def network_path(value):
    """True for UNC and device paths: \\\\server\\share, //server/share, \\\\?\\ and \\\\.\\ prefixes.

    They never name files in a local checkout, and touching one makes Windows open an SMB
    connection that can disclose the account's NTLM credentials to the named host.
    """
    return value.replace("\\", "/").startswith("//") or PureWindowsPath(value).drive.startswith("\\\\")


def root_forms(root):
    """The scanned directory as given and fully resolved.

    Producers report either form: macOS reaches /var through /private/var, and Windows
    temporary folders can appear with 8.3 short names.
    """
    forms = []
    for form in (Path(os.path.abspath(root)), Path(root).resolve()):
        if form not in forms:
            forms.append(form)
    return forms


def relative_path(value, root=None):
    """Validate a repository-relative path. Absolute paths must lie inside `root`.

    The check is lexical: a report-supplied path is never resolved or opened here.
    """
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError("invalid path")
    if network_path(value):
        raise ValueError("network path")
    if ".." in PurePosixPath(value.replace("\\", "/")).parts:
        raise ValueError("parent traversal")
    if root is not None and Path(value).is_absolute():
        for form in root_forms(root):
            try:
                value = Path(value).relative_to(form).as_posix()
                break
            except ValueError:
                continue
        else:
            raise ValueError("path outside the target")
    path = PurePosixPath(value.replace("\\", "/"))
    if not path.parts or path.is_absolute() or PureWindowsPath(value).drive or ":" in str(path):
        raise ValueError("invalid path")
    return path.as_posix()


def positive_integer(value):
    if type(value) is not int or value < 1:
        raise ValueError("invalid position")
    return value


def number(value, low, high):
    """A finite JSON number (or numeric string) inside [low, high]."""
    if isinstance(value, str) and re.fullmatch(r"\d{1,3}(\.\d{1,12})?", value.strip()):
        value = float(value)
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise ValueError("invalid number")
    return value


def http_uri(value):
    """Return value when it is a usable http(s) URL, else None."""
    if (not isinstance(value, str) or len(value) > 2048
            or any(c.isspace() or ord(c) < 32 or ord(c) == 0x7f for c in value)):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc or not value.startswith(parts.scheme + "://"):
        return None
    return value


def cwe_id(value):
    """Normalize 79, "79", "CWE-79" or "CWE-79: description" to "CWE-79"."""
    if type(value) is int:
        value = str(value)
    if not isinstance(value, str):
        return None
    match = re.match(r"\s*(?:external/cwe/)?(?:cwe[-_ ]?)?0*([1-9][0-9]{0,5})(?![0-9])\s*(?::|$)", value, re.I)
    return "CWE-" + match[1] if match else None


def cwe_list(values):
    found = []
    for value in values:
        cwe = cwe_id(value)
        if cwe and cwe not in found:
            found.append(cwe)
    return found


def fingerprint(parts):
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def package_url(ecosystem, name, version):
    kind = {"npm": "npm", "pip": "pypi", "pypi": "pypi", "poetry": "pypi",
            "cargo": "cargo", "crates.io": "cargo", "yarn": "npm", "pnpm": "npm"}.get(ecosystem.lower())
    if kind is None:
        return None
    if kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return "pkg:" + kind + "/" + quote(name, safe="/.-_") + "@" + quote(version, safe=".-_")


# Package URL types whose names compare case-insensitively (purl-spec type definitions).
CASELESS_PURL_TYPES = {"bitbucket", "composer", "github", "golang", "hex", "npm", "nuget", "pypi"}


def purl_key(purl, version=None):
    """Canonical join key: lowercase type, normalized name, no qualifiers or subpath.

    The key is used only for grouping and inventory joins; reports keep the original purl.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    if "/" not in body:
        return None
    kind, rest = body.split("/", 1)
    kind = kind.lower()
    found = None
    if "@" in rest.rsplit("/", 1)[-1]:
        rest, found = rest.rsplit("@", 1)
        found = unquote(found)
    segments = [unquote(s) for s in rest.strip("/").split("/") if s]
    if not segments or not kind:
        return None
    if kind in CASELESS_PURL_TYPES:
        segments = [s.lower() for s in segments]
    if kind == "pypi":
        segments[-1] = re.sub(r"[-_.]+", "-", segments[-1])
    found = found or version
    return "pkg:" + kind + "/" + "/".join(segments) + ("@" + found if found else "")


class SourceLines:
    """Read flagged lines of the target to build line-independent content hashes.

    Files are read once, bounded in size, and only when they resolve inside the target.
    Only hashes leave this class; source text is never returned to callers.
    """

    def __init__(self, root):
        self.root = Path(root).resolve() if root is not None else None
        self.cache = {}

    def lines(self, path):
        if path not in self.cache:
            self.cache[path] = self.read(path)
        return self.cache[path]

    def read(self, path):
        if self.root is None or path is None:
            return None
        try:
            file = self.root / path
            if not file.resolve().is_relative_to(self.root) or not stat.S_ISREG(file.lstat().st_mode):
                return None
            with file.open("rb") as stream:
                raw = stream.read(SOURCE_LIMIT + 1)
        except (OSError, ValueError):
            return None
        if len(raw) > SOURCE_LIMIT:
            return None
        return re.split(r"\r?\n", raw.decode("utf-8", "replace").removeprefix("\ufeff"))

    def content_hash(self, path, start, end):
        lines = self.lines(path)
        if lines is None or start is None or end is None or end < start or end > len(lines):
            return None
        selected = "\n".join(" ".join(line.split()) for line in lines[start - 1:end])
        return hashlib.sha256(selected.encode("utf-8")).hexdigest()


# Hard-coded password rules whose flagged lines hold a credential, like secret detector matches.
CREDENTIAL_RULES = frozenset({("bandit", "B105"), ("bandit", "B106"), ("bandit", "B107")})
# A credential fingerprint carries 16 bits of the flagged lines' hash: a changed value yields a new
# fingerprint (so an exception for a placeholder never covers a real key), while 16 bits are far too
# few to confirm a guessed secret.
CREDENTIAL_TAG = 4


def credential(hit):
    return hit.get("category") == "secrets" or (hit["producer"], hit["rule"]) in CREDENTIAL_RULES


def assign_fingerprints(findings, root, sources=None):
    """Fingerprint source findings of one input batch.

    Source: [producer, rule, path, content_hash, occurrence, identity].
    Credentials (secrets, hard-coded passwords): [producer, rule, path, change_tag, occurrence], where
    the change tag is the first 16 bits of the content hash, or null when the file is unreadable.
    Findings that already carry a fingerprint (dependency, container) keep it.
    """
    sources = sources or SourceLines(root)
    pending = [(i, f) for i, f in enumerate(findings) if "fingerprint" not in f]

    def position(item):
        i, f = item
        return (f.get("line") or 0, f.get("column") or 0, f.get("byte_offset") or 0,
                f.get("end_line") or 0, f.get("end_column") or 0, f.get("end_byte_offset") or 0, i)

    counts = {}
    for _, hit in sorted(pending, key=position):
        identity = hit.pop("_identity", None)
        digest = sources.content_hash(hit["path"], hit.get("line"), hit.get("end_line") or hit.get("line"))
        if credential(hit):
            anchor = (hit["producer"], hit["rule"], hit["path"], digest[:CREDENTIAL_TAG] if digest else None)
        else:
            anchor = (hit["producer"], hit["rule"], hit["path"], digest, json.dumps(identity))
        occurrence = counts.get(anchor, 0)
        counts[anchor] = occurrence + 1
        parts = [*anchor, occurrence] if credential(hit) else [*anchor[:4], occurrence, identity]
        hit["fingerprint"] = fingerprint(parts)
    return findings
