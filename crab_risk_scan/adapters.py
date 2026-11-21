"""Read untrusted scanner JSON. Only explicitly selected fields leave an adapter."""
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .evidence import (CATEGORIES, LEVELS, array, cwe_id, cwe_list, fingerprint, http_uri, mapping, number,
                       package_url, positive_integer, relative_path, token)

SECRET_CWE = ["CWE-798"]
# Gitleaks rule IDs rated critical: private keys and cloud or provider credentials.
CRITICAL_SECRETS = {"private-key", "pkcs12-file", "npm-access-token", "pypi-upload-token",
                    "rubygems-api-token", "nuget-api-key", "dockerhub-pat", "jfrog-api-key",
                    "jfrog-identity-token", "openshift-user-token", "kubernetes-secret-yaml"}
CRITICAL_SECRET_PREFIXES = ("aws-", "azure-", "gcp-", "alibaba-", "digitalocean-", "linode-", "scalingo-",
                            "cloudflare-", "heroku-", "flyio-", "github-", "gitlab-", "bitbucket-",
                            "hashicorp-", "vault-", "doppler-")
MEDIUM_SECRETS = {"generic-api-key"}
MALICIOUS_MESSAGE = "Remove this package. It is listed as malicious."
SARIF_RESULT_LIMIT = 100_000


@dataclass
class ImportResult:
    findings: list = field(default_factory=list)
    version: str | None = None
    partial: bool = False
    targets: int | None = None


def secret_severity(rule):
    if rule in CRITICAL_SECRETS or rule.startswith(CRITICAL_SECRET_PREFIXES):
        return "critical"
    return "medium" if rule in MEDIUM_SECRETS else "high"


def normalize_level(original):
    normalized = {"error": "high", "warning": "medium", "moderate": "medium", "note": "info",
                  "information": "info", "style": "info"}.get(original.lower(), original.lower())
    return normalized if normalized in LEVELS else "unknown"


def source(producer, module, rule, path, start, end, severity, *, columns=None, identity=None):
    """A source-location finding. Fingerprints are assigned per input batch by the collector."""
    rule, original = token(rule), token(severity)
    result = {"producer": producer, "module": module, "category": CATEGORIES[module], "kind": "vulnerability",
              "rule": rule, "path": path, "line": None, "original_severity": original,
              "severity": normalize_level(original),
              "message": f"Review {producer} rule {rule} at the reported location."}
    if start is not None:
        start, end = positive_integer(start), positive_integer(end)
        if end < start:
            raise ValueError("invalid span")
        result.update(line=start, end_line=end)
        if columns:
            left, right = map(positive_integer, columns)
            if start == end and right < left:
                raise ValueError("invalid columns")
            result.update(column=left, end_column=right)
    if identity is not None:
        result["_identity"] = identity
    return result


def bandit(doc, root):
    result = ImportResult(partial=bool(array(doc["errors"])))
    for row in array(doc["results"]):
        line = positive_integer(row["line_number"])
        span = array(row.get("line_range", []))
        end = max(map(positive_integer, span), default=line)
        hit = source("bandit", "Claws", row["test_id"], relative_path(row["filename"], root),
                     line, end, row["issue_severity"])
        hit["confidence"] = token(row["issue_confidence"])
        # Bandit AST offsets count bytes. Do not export them as SARIF character columns.
        if "col_offset" in row:
            col = row["col_offset"]
            if type(col) is not int or col < 0:
                raise ValueError("invalid offset")
            hit["byte_offset"] = col
            if type(row.get("end_col_offset")) is int and row["end_col_offset"] >= 0:
                hit["end_byte_offset"] = row["end_col_offset"]
        issue_cwe = row.get("issue_cwe")
        if isinstance(issue_cwe, dict) and cwe_id(issue_cwe.get("id")):
            hit["cwe"] = [cwe_id(issue_cwe["id"])]
        if http_uri(row.get("more_info")):
            hit["help_uri"] = row["more_info"]
        result.findings.append(hit)
    return result


def first_reference(metadata):
    for key in ("references", "source", "shortlink"):
        values = metadata.get(key)
        for value in values if isinstance(values, list) else [values]:
            if http_uri(value):
                return value
    return None


def opengrep(doc, root):
    result = ImportResult(version=token(doc["version"]), partial=bool(array(doc["errors"])))
    for row in array(doc["results"]):
        start, end = row["start"], row["end"]
        hit = source("opengrep", "Claws", row["check_id"], relative_path(row["path"], root),
                     start["line"], end["line"], row["extra"]["severity"],
                     columns=(start["col"], end["col"]))
        if hit["rule"].rsplit(".", 1)[-1].startswith("crab-"):
            hit["kind"] = "review"
        metadata = row["extra"].get("metadata") or {}
        if isinstance(metadata, dict):
            values = metadata.get("cwe")
            cwes = cwe_list(values if isinstance(values, list) else [values])
            if cwes:
                hit["cwe"] = cwes
            reference = first_reference(metadata)
            if reference:
                hit["help_uri"] = reference
        result.findings.append(hit)
    return result


def gitleaks(doc, root):
    result = ImportResult()
    for row in array(doc):
        # Do not ingest Match, Secret, Fingerprint, commit messages or author metadata.
        rule = token(row["RuleID"])
        cols = (row["StartColumn"], positive_integer(row["EndColumn"]) + 1) if row.get("StartColumn") else None
        hit = source("gitleaks", "Sniffer", rule, relative_path(row["File"], root),
                     row["StartLine"], row["EndLine"], "unknown", columns=cols)
        hit.update(severity=secret_severity(rule), cwe=list(SECRET_CWE),
                   message="Review the credential detector match and rotate any exposed credential.")
        result.findings.append(hit)
    return result


def checkov(doc, root):
    result = ImportResult()
    for block in doc if isinstance(doc, list) else [doc]:
        checks = block["results"]
        result.partial |= bool(array(checks.get("parsing_errors", [])))
        count = block.get("summary", {}).get("parsing_errors", 0)
        if type(count) is not int or count < 0:
            raise ValueError("invalid parser error count")
        result.partial |= count > 0
        framework = token(block["check_type"])
        for row in array(checks["failed_checks"]):
            path = checkov_path(row, root)
            start, end = array(row["file_line_range"])
            if framework == "secrets":
                # Checkov names a secret finding by the SHA-1 of the secret value. That hash would let
                # report readers verify guesses, so the resource is dropped like Gitleaks secrets.
                hit = source("checkov", "Sniffer", row["check_id"], path, start, end,
                             row.get("severity") or "unknown")
                hit.update(framework=framework, cwe=list(SECRET_CWE),
                           message="Review the credential detector match and rotate any exposed credential.")
                if not row.get("severity"):
                    hit["severity"] = "high"
                result.findings.append(hit)
                continue
            resource = row["resource"]
            if not isinstance(resource, str) or not re.fullmatch(r"""[\w.:/@+\[\]"'=-]{1,512}""", resource):
                raise ValueError("invalid resource address")
            hit = source("checkov", "Burrow", row["check_id"], path,
                         start, end, row.get("severity") or "unknown", identity=resource)
            hit.update(resource=resource, framework=framework)
            if http_uri(row.get("guideline")):
                hit["help_uri"] = row["guideline"]
            result.findings.append(hit)
    return result


def checkov_path(row, root):
    # Graph checks on Windows report file_path relative to the file's own folder, so an
    # absolute file_abs_path inside the target wins. Reports from another host fall back.
    absolute = row.get("file_abs_path")
    if isinstance(absolute, str) and root is not None and Path(absolute).is_absolute():
        try:
            return relative_path(absolute, root)
        except ValueError:
            pass
    # file_path is relative to the scan root behind a virtual leading separator ("/" on
    # POSIX, "\" on Windows); repo_file_path depends on the producer's working directory.
    path = row.get("file_path") or row["repo_file_path"]
    if isinstance(path, str) and path[:1] in ("/", "\\"):
        path = path[1:]
    return relative_path(path)


def shellcheck(doc, root):
    result = ImportResult()
    for row in array(doc):
        code = positive_integer(row["code"])
        if code in {1009, 1072, 1073, 1089}:
            result.partial = True
        if code not in {2086, 2046, 2068, 2294}:
            continue
        hit = source("shellcheck", "Claws", f"SC{code}", relative_path(row["file"], root), row["line"],
                     row["endLine"], row["level"], columns=(row["column"], row["endColumn"]))
        hit["help_uri"] = f"https://www.shellcheck.net/wiki/SC{code}"
        result.findings.append(hit)
    return result


def psscriptanalyzer(doc, root):
    result = ImportResult()
    for row in array(doc):
        if row["Severity"] == "ParseError":
            result.partial = True
            continue
        extent = row["Extent"]
        hit = source("psscriptanalyzer", "Claws", row["RuleName"], relative_path(row["ScriptPath"], root),
                     extent["StartLineNumber"], extent["EndLineNumber"], row["Severity"],
                     columns=(extent["StartColumnNumber"], extent["EndColumnNumber"]))
        # Built-in rules are documented under their name without the PS prefix.
        match = re.fullmatch(r"PS([A-Za-z]{1,128})", hit["rule"])
        if match:
            hit["help_uri"] = ("https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/rules/"
                               + match[1].lower())
        result.findings.append(hit)
    return result


def dependency(producer, advisory, name, version, ecosystem, target, location, level, digest=None):
    advisory, name, version, ecosystem, level = map(token, (advisory, name, version, ecosystem, level))
    key = [producer, ecosystem, target, location, advisory, name, version]
    if digest:
        key.append(digest)
    module = "Exoskeleton" if digest else "Shell"
    result = {"producer": producer, "module": module, "category": CATEGORIES[module], "kind": "vulnerability",
              "rule": advisory, "path": location, "line": None, "fingerprint": fingerprint(key),
              "original_severity": level, "severity": normalize_level(level),
              "package": {"ecosystem": ecosystem, "name": name, "version": version},
              "manifest": target, "message": "Review the installed dependency against this advisory.",
              "risk_type": "vulnerability"}
    if digest:
        result["image_digest"] = digest
    return result


def fixed_version(value):
    if not isinstance(value, str):
        return None
    first = value.split(",", 1)[0].strip()
    return first if re.fullmatch(r"[\w@.+:/~^!-]{1,256}", first, re.ASCII) else None


def cvss_from_trivy(data):
    if not isinstance(data, dict):
        return None
    vendors = sorted((v for v in data if isinstance(v, str)), key=lambda v: (v != "nvd", v))
    for vendor in vendors:
        scores = data[vendor]
        if not isinstance(scores, dict):
            continue
        for version in ("V3", "V40", "V2"):
            try:
                score = number(scores.get(version + "Score"), 0, 10)
            except ValueError:
                continue
            vector = scores.get(version + "Vector")
            if not isinstance(vector, str) or not re.fullmatch(r"[A-Za-z0-9.:/_+()-]{1,256}", vector):
                vector = None
            source_name = vendor if re.fullmatch(r"[\w@.+:/~^!-]{1,256}", vendor, re.ASCII) else None
            return {"score": score, "vector": vector, "source": source_name}
    return None


def trivy(doc, root, *, image=False):
    expected = "container_image" if image else "filesystem"
    if doc["SchemaVersion"] != 2 or doc["ArtifactType"] != expected:
        raise ValueError("unsupported Trivy document")
    digest = None
    if image:
        # RepoDigests identify image manifests, unlike the local image configuration ID.
        digests = {s.rsplit("@", 1)[-1] for s in array(doc["Metadata"]["RepoDigests"])}
        if len(digests) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", next(iter(digests))):
            raise ValueError("missing or ambiguous manifest digest")
        digest = digests.pop()
    version = doc.get("Trivy", {}).get("Version")
    results = array(doc.get("Results", []))
    result = ImportResult(version=token(version) if version else None, targets=len(results))
    for group in results:
        if group["Class"] not in ({"os-pkgs", "lang-pkgs"} if image else {"lang-pkgs"}):
            raise ValueError("expected vulnerability-only report")
        target = relative_path(group["Target"], root) if not image or group["Class"] == "lang-pkgs" else None
        vulnerabilities = group.get("Vulnerabilities")
        for row in array([] if vulnerabilities is None else vulnerabilities):
            location = relative_path(row["PkgPath"], root) if row.get("PkgPath") else target
            hit = dependency("trivy", row["VulnerabilityID"], row["PkgName"], row["InstalledVersion"],
                             group["Type"], target, location, row["Severity"], digest)
            hit["package"]["purl"] = purl_for(row.get("PkgIdentifier", {}).get("PURL"), hit["package"])
            fixed = fixed_version(row.get("FixedVersion"))
            if fixed:
                hit["fixed_version"] = fixed
            cwes = cwe_list(array(row.get("CweIDs") or []))
            if cwes:
                hit["cwe"] = cwes
            cvss = cvss_from_trivy(row.get("CVSS"))
            if cvss:
                hit["cvss"] = cvss
            if http_uri(row.get("PrimaryURL")):
                hit["help_uri"] = row["PrimaryURL"]
            result.findings.append(hit)
    return result


def purl_for(value, package):
    if value is None:
        return package_url(package["ecosystem"], package["name"], package["version"])
    if not isinstance(value, str) or not re.fullmatch(r"pkg:[a-z0-9.+-]+/[^\s\x00-\x1f]{1,1024}", value):
        raise ValueError("invalid package URL")
    return value


def osv_fixed(advisory, pkg):
    for affected in advisory.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        target = affected.get("package") or {}
        if (not isinstance(target, dict) or target.get("name") != pkg["name"]
                or str(target.get("ecosystem", "")).lower() != str(pkg["ecosystem"]).lower()):
            continue
        for span in affected.get("ranges") or []:
            for event in (span.get("events") or []) if isinstance(span, dict) else []:
                if isinstance(event, dict) and "fixed" in event:
                    return fixed_version(event["fixed"])
    return None


def osv(doc, root):
    groups = array(doc["results"])
    result = ImportResult(targets=len(groups))
    for group in groups:
        if group["source"]["type"] != "lockfile":
            raise ValueError("expected OSV lockfile")
        path = relative_path(group["source"]["path"], root)
        for row in array(group["packages"]):
            pkg = row["package"]
            for advisory in array(row.get("vulnerabilities", [])):
                specific = advisory.get("database_specific") or {}
                level = specific.get("severity") or "unknown"
                hit = dependency("osv", advisory["id"], pkg["name"], pkg["version"], pkg["ecosystem"],
                                 path, path, level)
                hit["package"]["purl"] = purl_for(pkg.get("purl"), hit["package"])
                hit["aliases"] = sorted({token(a) for a in array(advisory.get("aliases") or [])})
                if hit["rule"].startswith("MAL-"):
                    hit.update(risk_type="malicious", severity="critical", message=MALICIOUS_MESSAGE)
                cwes = cwe_list(array(specific.get("cwe_ids") or []))
                if cwes:
                    hit["cwe"] = cwes
                fixed = osv_fixed(advisory, pkg)
                if fixed:
                    hit["fixed_version"] = fixed
                result.findings.append(hit)
    return result


# Generic SARIF 2.1.0 import.

SARIF_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
SECRET_TAGS = {"secret", "secrets", "credential", "credentials"}
IAC_TAGS = {"iac", "infrastructure-as-code", "terraform", "kubernetes", "cloudformation", "dockerfile", "helm",
            "arm", "bicep", "ansible"}
CWE_TAG = re.compile(r"(?:external/cwe/)?cwe-0*([1-9][0-9]{0,5})", re.I)


def sarif_producer(driver):
    name = driver.get("name")
    if isinstance(name, str):
        name = re.sub(r"[^a-z0-9._-]+", "-", name.strip().lower()).strip("-.")[:64]
        if name and name != "crab":
            return name
    return "sarif"


def sarif_version(driver):
    for key in ("version", "semanticVersion"):
        value = driver.get(key)
        if isinstance(value, str) and re.fullmatch(r"[\w@.+:/~^!-]{1,256}", value, re.ASCII):
            return value
    return None


def severity_score(properties):
    if not isinstance(properties, dict) or "security-severity" not in properties:
        return None
    try:
        return number(properties["security-severity"], 0, 10)
    except ValueError:
        return None


def tags_of(*sources):
    tags = []
    for item in sources:
        properties = item.get("properties") if isinstance(item, dict) else None
        values = properties.get("tags") if isinstance(properties, dict) else None
        tags.extend(t for t in values or [] if isinstance(t, str) and len(t) <= 256)
    return tags


def cwe_from_relationships(entries):
    found = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        target = entry.get("target", entry)
        component = target.get("toolComponent") if isinstance(target, dict) else None
        if not isinstance(component, dict) or str(component.get("name", "")).upper() != "CWE":
            continue
        cwe = cwe_id(target.get("id"))
        if cwe:
            found.append(cwe)
    return found


class SarifRun:
    def __init__(self, run, root):
        self.run = mapping(run)
        self.target = root
        tool = mapping(self.run["tool"])
        self.driver = mapping(tool["driver"])
        self.extensions = [e for e in tool.get("extensions") or [] if isinstance(e, dict)]
        self.rules = [r for r in self.driver.get("rules") or [] if isinstance(r, dict)]
        self.by_id = {}
        for component in [self.driver, *self.extensions]:
            for rule in component.get("rules") or []:
                if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                    self.by_id.setdefault(rule["id"], rule)
        self.bases = self.run.get("originalUriBaseIds") or {}
        self.artifacts = self.run.get("artifacts") or []

    def rule_for(self, result):
        reference = result.get("rule") if isinstance(result.get("rule"), dict) else {}
        index = result.get("ruleIndex", reference.get("index"))
        component = reference.get("toolComponent")
        rules = self.rules
        if isinstance(component, dict) and type(component.get("index")) is int:
            if not 0 <= component["index"] < len(self.extensions):
                raise ValueError("invalid tool component")
            rules = [r for r in self.extensions[component["index"]].get("rules") or [] if isinstance(r, dict)]
        descriptor = None
        if type(index) is int and index >= 0:
            if index >= len(rules):
                raise ValueError("invalid rule index")
            descriptor = rules[index]
        rule_id = result.get("ruleId") or reference.get("id") or (descriptor or {}).get("id")
        if descriptor is None and isinstance(rule_id, str):
            descriptor = self.by_id.get(rule_id) or self.by_id.get(rule_id.split("/", 1)[0])
        return rule_id, descriptor or {}

    def base_path(self, name, depth=0):
        base = self.bases.get(name) if isinstance(self.bases, dict) else None
        if depth > 8 or not isinstance(base, dict):
            return None
        uri = base.get("uri")
        if not isinstance(uri, str):
            return None
        parent = self.base_path(base["uriBaseId"], depth + 1) if base.get("uriBaseId") else None
        return self.join(parent, uri)

    def join(self, parent, uri):
        """Return an absolute file path or a PurePosix relative string, or None for foreign schemes."""
        if re.match(r"[A-Za-z]:[\\/]", uri):
            return Path(uri)
        parts = urlsplit(uri)
        if parts.scheme == "file":
            if parts.netloc not in ("", "localhost"):
                return None
            return Path(unquote(parts.path).removeprefix("/") if re.match(r"/[A-Za-z]:", parts.path)
                        else unquote(parts.path))
        if parts.scheme or parts.netloc:
            return None
        relative = unquote(parts.path)
        if relative.startswith("/"):
            return Path(relative)
        if parent is None:
            return relative
        if isinstance(parent, Path):
            return parent / relative
        return parent.rstrip("/") + "/" + relative if parent else relative

    def location(self, result):
        for location in result.get("locations") or []:
            physical = location.get("physicalLocation") if isinstance(location, dict) else None
            if isinstance(physical, dict):
                break
        else:
            return None, None
        artifact = physical.get("artifactLocation")
        if not isinstance(artifact, dict):
            return None, None
        if "uri" not in artifact and type(artifact.get("index")) is int:
            if not 0 <= artifact["index"] < len(self.artifacts):
                raise ValueError("invalid artifact index")
            artifact = (self.artifacts[artifact["index"]] or {}).get("location") or {}
        uri = artifact.get("uri")
        if not isinstance(uri, str) or not uri or len(uri) > 4096:
            return None, None
        parent = None
        if artifact.get("uriBaseId"):
            parent = self.base_path(artifact["uriBaseId"])
        path = self.join(parent, uri)
        if path is None:
            return None, None
        if isinstance(path, Path):
            if not path.is_absolute() or self.target is None:
                return None, None
            try:
                path = relative_path(str(path), self.target)
            except ValueError:
                return None, None
        path = relative_path(path.removeprefix("./"))
        region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
        return path, region


def sarif(doc, root):
    if doc["version"] != "2.1.0":
        raise ValueError("unsupported SARIF version")
    runs = array(doc["runs"])
    result = ImportResult()
    versions = set()
    total = 0
    for raw in runs:
        run = SarifRun(raw, root)
        producer, version = sarif_producer(run.driver), sarif_version(run.driver)
        versions.add(version)
        for invocation in run.run.get("invocations") or []:
            if isinstance(invocation, dict) and invocation.get("executionSuccessful") is False:
                result.partial = True
        for item in array(run.run.get("results") or []):
            total += 1
            if total > SARIF_RESULT_LIMIT:
                raise ValueError("SARIF result limit")
            item = mapping(item)
            if item.get("kind", "fail") in {"pass", "notApplicable"}:
                continue
            rule_id, rule = run.rule_for(item)
            if not isinstance(rule_id, str) or not re.fullmatch(r"[\w@.+:/~^!-]{1,256}", rule_id, re.ASCII):
                result.partial = True
                continue
            path, region = run.location(item)
            if path is None:
                continue
            tags = {t.lower() for t in tags_of(item, rule)}
            module = "Sniffer" if tags & SECRET_TAGS else "Burrow" if tags & IAC_TAGS else "Claws"
            score = severity_score(item.get("properties"))
            if score is None:
                score = severity_score(rule.get("properties"))
            configuration = rule.get("defaultConfiguration")
            level = item.get("level")
            if level not in SARIF_LEVELS:
                level = configuration.get("level") if isinstance(configuration, dict) else None
            if level not in SARIF_LEVELS:
                level = "none" if item.get("kind", "fail") != "fail" else "warning"
            if score is not None:
                severity = ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4
                            else "low" if score > 0 else "info")
                original = format(score, "g")
            else:
                severity, original = SARIF_LEVELS[level], level
            start = region.get("startLine")
            if start is not None:
                end = region.get("endLine", start)
                columns = None
                if "startColumn" in region:
                    columns = (region["startColumn"], region.get("endColumn", region["startColumn"]))
                hit = source(producer, module, rule_id, path, start, end, original, columns=columns)
            else:
                hit = source(producer, module, rule_id, path, None, None, original)
            hit["severity"] = severity
            cwes = []
            for tag in tags_of(item, rule):
                match = CWE_TAG.fullmatch(tag)
                if match and "CWE-" + match[1] not in cwes:
                    cwes.append("CWE-" + match[1])
            for cwe in cwe_from_relationships(rule.get("relationships")) + cwe_from_relationships(item.get("taxa")):
                if cwe not in cwes:
                    cwes.append(cwe)
            if cwes:
                hit["cwe"] = cwes
            if http_uri(rule.get("helpUri")):
                hit["help_uri"] = rule["helpUri"]
            hit["producer_version"] = version
            result.findings.append(hit)
    if len(versions) == 1:
        result.version = versions.pop()
    return result


ADAPTERS = {"bandit": bandit, "opengrep": opengrep, "gitleaks": gitleaks, "checkov": checkov,
            "shellcheck": shellcheck, "psscriptanalyzer": psscriptanalyzer, "trivy": trivy,
            "trivy-image": lambda doc, root: trivy(doc, root, image=True), "osv": osv, "sarif": sarif}
