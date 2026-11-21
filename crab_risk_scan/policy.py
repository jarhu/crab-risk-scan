"""Policy v1, exceptions v2, comparison with a base report and gate evaluation."""
import copy
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from . import __version__, enrich
from .evidence import CATEGORIES, INVALID, LEVELS, fingerprint, load_json, purl_key, text, token
from .triage import groups, relink

POLICY_LIMIT = 1024 * 1024
EXCEPTIONS_LIMIT = 16 * 1024 * 1024
BASE_LIMIT = 64 * 1024 * 1024
STATUSES = ("accepted", "false_positive", "not_affected")
JUSTIFICATIONS = ("code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
                  "requires_environment", "protected_by_compiler", "protected_at_runtime",
                  "protected_at_perimeter", "protected_by_mitigating_control")
GATES = ("secrets", "malicious", "kev", "epss", "licenses", "max")
RULE_KEY = re.compile(r"[\w@.+:~^!-]{1,256}/[\w@.+:/~^!-]{1,256}", re.ASCII)
FINGERPRINT = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
LICENSE_RULE = "CRAB-LIC-001"
DENIED_MESSAGE = "This dependency's license is denied by the project policy."
NOT_ALLOWED_MESSAGE = "This dependency's license is not on the project allow list."
FINDING_ORDER = ("fingerprint", "producer", "producer_version", "rule_pack", "module", "category", "kind", "rule",
                 "severity", "original_severity", "message", "path", "line", "end_line", "column", "end_column",
                 "cwe", "help_uri", "confidence", "resource", "framework", "byte_offset", "end_byte_offset",
                 "package", "manifest", "image_digest", "aliases", "risk_type", "fixed_version", "cvss", "epss",
                 "kev", "license", "inputs", "inventory_components", "new", "suppressed", "exception")
REPORT_ORDER = ("schema_version", "tool", "target", "revision", "branch", "repository", "files_scanned",
                "imports", "findings", "groups", "inventory", "comparison", "policy", "errors")
V1_MESSAGE = ("exceptions file version 1 (the 0.2 baseline) is not supported: fingerprints changed with "
              "report schema 3. Regenerate the reviewed entries as an exceptions version 2 file.")


class PolicyError(ValueError):
    """A rejected policy-related input. The message is a fixed string without file content."""

    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


@dataclass
class Policy:
    source: str = "default"
    fail_on: str = "unknown"
    new_only: bool = False
    include_review: bool = True
    gates: dict = field(default_factory=lambda: {"secrets": True, "malicious": True, "kev": True, "epss": None,
                                                 "licenses": True, "max": {}})
    disabled: frozenset = frozenset()
    severity: dict = field(default_factory=dict)
    deny: frozenset = frozenset()
    allow: frozenset = frozenset()
    license_severity: str = "high"


def require(condition, reason, message):
    if not condition:
        raise PolicyError(reason, message)


def only_keys(value, allowed, reason, where):
    require(isinstance(value, dict), reason, f"{where} must be a JSON object")
    unknown = sorted(set(value) - set(allowed))
    require(not unknown, reason, f"{where} has unsupported keys: {', '.join(k[:64] for k in unknown)}"
            if all(isinstance(k, str) and re.fullmatch(r"[\w.-]{1,64}", k) for k in unknown)
            else f"{where} has unsupported keys")


def boolean(value, reason, where):
    require(type(value) is bool, reason, f"{where} must be true or false")
    return value


def string_list(value, reason, where):
    require(isinstance(value, list), reason, f"{where} must be an array of strings")
    for item in value:
        require(isinstance(item, str) and 0 < len(item) <= 256 and item.strip() == item
                and not any(ord(c) < 32 for c in item), reason, f"{where} must contain short strings")
    return value


def read_document(value, limit):
    if isinstance(value, dict):
        return value
    return load_json(Path(value), limit)


def parse_policy(doc):
    reason = "invalid_policy"
    only_keys(doc, ("version", "fail_on", "new_only", "include_review", "gates", "rules", "licenses"),
              reason, "policy")
    require(type(doc.get("version")) is int and doc["version"] == 1, reason, "policy version must be 1")
    result = Policy(source="policy-file")
    if "fail_on" in doc:
        require(doc["fail_on"] in (*LEVELS, "none"), reason, "fail_on must be a severity or none")
        result.fail_on = doc["fail_on"]
    if "new_only" in doc:
        result.new_only = boolean(doc["new_only"], reason, "new_only")
    if "include_review" in doc:
        result.include_review = boolean(doc["include_review"], reason, "include_review")
    gates = doc.get("gates", {})
    only_keys(gates, GATES, reason, "gates")
    for name in ("secrets", "malicious", "kev", "licenses"):
        if name in gates:
            result.gates[name] = boolean(gates[name], reason, "gates." + name)
    if "epss" in gates:
        value = gates["epss"]
        require(value is None or value is False or (type(value) in (int, float) and 0 <= value <= 1),
                reason, "gates.epss must be a probability between 0 and 1, false or null")
        result.gates["epss"] = None if value is None or value is False else float(value)
    if "max" in gates:
        only_keys(gates["max"], LEVELS, reason, "gates.max")
        for level, limit in gates["max"].items():
            require(type(limit) is int and limit >= 0, reason, "gates.max limits must be non-negative integers")
        result.gates["max"] = dict(gates["max"])
    rules = doc.get("rules", {})
    only_keys(rules, ("disabled", "severity"), reason, "rules")
    disabled = string_list(rules.get("disabled", []), reason, "rules.disabled")
    require(all(RULE_KEY.fullmatch(k) for k in disabled), reason, "rules.disabled entries use producer/rule")
    result.disabled = frozenset(disabled)
    overrides = rules.get("severity", {})
    require(isinstance(overrides, dict), reason, "rules.severity must be an object")
    for key, level in overrides.items():
        require(RULE_KEY.fullmatch(key), reason, "rules.severity keys use producer/rule")
        require(level in LEVELS, reason, "rules.severity values must be severities")
    result.severity = dict(overrides)
    licenses = doc.get("licenses", {})
    only_keys(licenses, ("deny", "allow", "severity"), reason, "licenses")
    result.deny = frozenset(v.lower() for v in string_list(licenses.get("deny", []), reason, "licenses.deny"))
    result.allow = frozenset(v.lower() for v in string_list(licenses.get("allow", []), reason, "licenses.allow"))
    if "severity" in licenses:
        require(licenses["severity"] in LEVELS, reason, "licenses.severity must be a severity")
        result.license_severity = licenses["severity"]
    return result


def load_policy(value):
    try:
        return parse_policy(read_document(value, POLICY_LIMIT))
    except PolicyError:
        raise
    except INVALID:
        raise PolicyError("invalid_policy", "the policy file could not be read as JSON") from None


def valid_date(value):
    if not isinstance(value, str) or not DATE.fullmatch(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def parse_exceptions(doc):
    reason = "invalid_exceptions"
    require(isinstance(doc, dict), reason, "exceptions file must be a JSON object")
    require(not (doc.get("version") == 1 or "suppressions" in doc), reason, V1_MESSAGE)
    only_keys(doc, ("version", "exceptions"), reason, "exceptions file")
    require(type(doc.get("version")) is int and doc["version"] == 2, reason, "exceptions version must be 2")
    entries = doc.get("exceptions")
    require(isinstance(entries, list), reason, "exceptions must be an array")
    result = {}
    for entry in entries:
        only_keys(entry, ("fingerprint", "status", "reason", "reviewer", "expires", "ticket", "justification"),
                  reason, "exception")
        key = entry.get("fingerprint")
        require(isinstance(key, str) and FINGERPRINT.fullmatch(key), reason,
                "exception fingerprints are 64 lowercase hexadecimal characters")
        require(key not in result, reason, "exception fingerprints must be unique")
        require(entry.get("status") in STATUSES, reason, "exception status must be accepted, false_positive "
                "or not_affected")
        for name, limit in (("reason", 2000), ("reviewer", 256)):
            value = entry.get(name)
            require(isinstance(value, str) and value.strip() and len(value) <= limit, reason,
                    f"exception {name} is required")
        item = {"status": entry["status"], "reason": entry["reason"], "reviewer": entry["reviewer"]}
        if entry.get("expires") is not None:
            require(valid_date(entry["expires"]), reason, "exception expires must be a YYYY-MM-DD date")
            item["expires"] = entry["expires"]
        if entry.get("ticket") is not None:
            ticket = entry["ticket"]
            require(isinstance(ticket, str) and ticket.strip() and len(ticket) <= 256, reason,
                    "exception ticket must be a short string")
            item["ticket"] = ticket
        justification = entry.get("justification")
        if entry["status"] == "not_affected":
            require(justification in JUSTIFICATIONS, reason, "not_affected exceptions require a VEX justification")
            item["justification"] = justification
        else:
            require(justification is None, reason, "justification applies only to not_affected exceptions")
        result[key] = item
    return result


def load_exceptions(value):
    try:
        return parse_exceptions(read_document(value, EXCEPTIONS_LIMIT))
    except PolicyError:
        raise
    except INVALID:
        raise PolicyError("invalid_exceptions", "the exceptions file could not be read as JSON") from None


def nullable(value, check):
    return None if value is None else check(value)


def fixed_entry(hit):
    entry = {"fingerprint": hit["fingerprint"], "producer": token(hit["producer"]), "rule": token(hit["rule"]),
             "severity": hit["severity"], "category": hit["category"],
             "path": nullable(hit.get("path"), lambda p: text(p, 4096)), "line": hit.get("line")}
    if (not FINGERPRINT.fullmatch(entry["fingerprint"]) or entry["severity"] not in LEVELS
            or entry["category"] not in CATEGORIES.values()
            or not (entry["line"] is None or (type(entry["line"]) is int and entry["line"] >= 1))):
        raise ValueError("invalid base finding")
    if hit.get("package") is not None:
        pkg = hit["package"]
        purl = pkg.get("purl")
        if purl is not None and (not isinstance(purl, str) or len(purl) > 1100):
            raise ValueError("invalid base package")
        entry["package"] = {"ecosystem": token(pkg["ecosystem"]), "name": token(pkg["name"]),
                            "version": token(pkg["version"]), "purl": purl}
    return entry


def load_base(value):
    """Return (base_revision, {fingerprint: fixed entry}) from a schema-3 base report."""
    try:
        doc = read_document(value, BASE_LIMIT)
        if doc["schema_version"] != 3 or not isinstance(doc["findings"], list):
            raise ValueError("expected schema 3")
        revision = nullable(doc.get("revision"), token)
        entries = {}
        for hit in doc["findings"]:
            entry = fixed_entry(hit)
            entries.setdefault(entry["fingerprint"], entry)
        return revision, entries
    except INVALID:
        raise PolicyError("invalid_comparison_base",
                          "the --new-since base must be a schema 3 CRAB JSON report") from None


# SPDX license expressions: OR offers a choice, AND requires every operand.

def license_acceptable(value, deny, allow):
    def atomic(identifier):
        lowered = identifier.lower()
        base = lowered.split(" with ", 1)[0]
        if lowered in deny or base in deny:
            return False
        return not allow or lowered in allow or base in allow

    if not re.search(r"[()]|\s(AND|OR|WITH)\s", value):
        return atomic(value.strip())
    tokens = re.findall(r"\(|\)|[^\s()]+", value)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        position += 1
        return tokens[position - 1]

    def expression():
        result = term()
        while peek() == "OR":
            take()
            result = term() or result
        return result

    def term():
        result = factor()
        while peek() == "AND":
            take()
            result = factor() and result
        return result

    def factor():
        current = peek()
        if current == "(":
            take()
            result = expression()
            if take() != ")":
                raise ValueError("unbalanced expression")
            return result
        if current in (None, ")", "AND", "OR", "WITH"):
            raise ValueError("invalid expression")
        identifier = take()
        if peek() == "WITH":
            take()
            if peek() in (None, "(", ")", "AND", "OR", "WITH"):
                raise ValueError("invalid expression")
            identifier += " with " + take()
        return atomic(identifier)

    try:
        result = expression()
        if position != len(tokens):
            raise ValueError("trailing tokens")
        return result
    except (ValueError, IndexError):
        return atomic(value.strip())


def license_findings(inventory, rules):
    if not inventory or not (rules.deny or rules.allow):
        return []
    found = {}
    for position, component in enumerate(inventory["components"]):
        for license_ in component["licenses"]:
            if license_acceptable(license_, rules.deny, rules.allow):
                continue
            denied = not license_acceptable(license_, rules.deny, frozenset())
            purl, name, version = component["purl"], component["name"], component["version"]
            key = fingerprint(["crab-license", purl or f"{name}@{version}", license_])
            if key in found:
                found[key]["inventory_components"].append(position)
                continue
            hit = {"fingerprint": key, "producer": "crab", "producer_version": __version__, "rule_pack": "policy",
                   "module": "Shell", "category": "sca", "kind": "vulnerability", "rule": LICENSE_RULE,
                   "severity": rules.license_severity, "original_severity": rules.license_severity,
                   "message": DENIED_MESSAGE if denied else NOT_ALLOWED_MESSAGE, "path": None, "line": None}
            package = license_package(component)
            if package:
                hit["package"] = package
            hit.update(manifest=None, risk_type="license", license=license_[:256],
                       inventory_components=[position])
            found[key] = hit
    return list(found.values())


def license_package(component):
    purl, name, version = component["purl"], component["name"], component["version"]
    ecosystem = None
    key = purl_key(purl)
    if key:
        ecosystem = key[4:].split("/", 1)[0]
    try:
        return {"ecosystem": token(ecosystem or "generic"), "name": token(name), "version": token(version),
                "purl": purl}
    except ValueError:
        return None


def sort_key(hit):
    return (LEVELS.index(hit["severity"]), hit["path"] or "", hit.get("line") or 0, hit["rule"],
            hit["fingerprint"])


def ordered(item, order):
    return {k: item[k] for k in order if k in item} | {k: v for k, v in item.items() if k not in order}


def warn(exc):
    print(f"crab-risk-scan: {exc}", file=sys.stderr)


def evaluate(report, *, policy=None, exceptions=None, fail_on=None, new_since=None, epss=None, kev=None,
             today=None):
    """Apply enrichment, rule profile, license findings, exceptions, comparison and gates in place."""
    errors = report["errors"]
    today = today or date.today()
    previous = report.get("policy") or {}
    rules = Policy()
    loaded = {}
    for name, value, loader in (("policy", policy, load_policy), ("exceptions", exceptions, load_exceptions),
                                ("base", new_since, load_base)):
        if value is None:
            continue
        try:
            loaded[name] = loader(value)
        except PolicyError as exc:
            warn(exc)
            errors.append({"reason": exc.reason})
    for name, value, loader in (("epss", epss, enrich.load_epss), ("kev", kev, enrich.load_kev)):
        if value is None:
            continue
        try:
            loaded[name] = loader(value)
        except INVALID:
            warn(f"the {name.upper()} file could not be read")
            errors.append({"reason": "invalid_" + name})
    rules = loaded.get("policy", rules)
    if fail_on is not None:
        if fail_on in (*LEVELS, "none"):
            rules.fail_on = fail_on
        else:
            errors.append({"reason": "invalid_policy"})
    findings = report["findings"]
    enrich.apply(findings, epss=loaded.get("epss"), kev=loaded.get("kev"))

    # 1. Rule profile.
    kept = [f for f in findings if f"{f['producer']}/{f['rule']}" not in rules.disabled]
    disabled = len(findings) - len(kept) + previous.get("disabled_findings", 0)
    for hit in kept:
        override = rules.severity.get(f"{hit['producer']}/{hit['rule']}")
        if override:
            hit["severity"] = override

    # 2. License findings from the inventory.
    earlier = {f["fingerprint"]: f.get("new") for f in kept if f.get("risk_type") == "license"}
    kept = [f for f in kept if f.get("risk_type") != "license"]
    for hit in license_findings(report.get("inventory"), rules):
        if earlier.get(hit["fingerprint"]) is not None and "base" not in loaded:
            hit["new"] = earlier[hit["fingerprint"]]
        elif "comparison" in report and "base" not in loaded:
            hit["new"] = True
        kept.append(hit)
    kept.sort(key=sort_key)
    if report.get("inventory"):
        relink(report["inventory"], kept)

    # 3. Exceptions. Without a new file, keep the exceptions already attached to the report.
    if "exceptions" in loaded:
        entries, carried_expired, carried_stale = loaded["exceptions"], [], []
    elif exceptions is not None:
        entries, carried_expired, carried_stale = {}, [], []
    else:
        entries = {f["fingerprint"]: f["exception"] for f in kept if "exception" in f}
        carried_expired = list(previous.get("expired_exceptions", []))
        carried_stale = list(previous.get("stale_exceptions", []))
    expired = {e["fingerprint"]: e["expires"] for e in carried_expired}
    for key, entry in entries.items():
        if entry.get("expires") and date.fromisoformat(entry["expires"]) <= today:
            expired[key] = entry["expires"]
    matched = set()
    for hit in kept:
        hit.pop("exception", None)
        entry = entries.get(hit["fingerprint"])
        hit["suppressed"] = bool(entry) and hit["fingerprint"] not in expired
        if entry:
            matched.add(hit["fingerprint"])
            if hit["suppressed"]:
                hit["exception"] = dict(entry)
    stale = sorted(set(carried_stale) | (set(entries) - matched))

    # 4. Comparison with a base report.
    if "base" in loaded:
        base_revision, base = loaded["base"]
        current = {f["fingerprint"] for f in kept}
        for hit in kept:
            hit["new"] = hit["fingerprint"] not in base
        fixed = sorted((e for k, e in base.items() if k not in current), key=sort_key)
        report["comparison"] = {"base_revision": base_revision, "new": sum(f["new"] for f in kept),
                                "unchanged": sum(not f["new"] for f in kept), "fixed": fixed}
    elif "comparison" in report:
        report["comparison"]["new"] = sum(bool(f.get("new")) for f in kept)
        report["comparison"]["unchanged"] = sum(not f.get("new") for f in kept)

    # 5. Gates.
    considered = [f for f in kept if not f["suppressed"]
                  and (rules.include_review or f["kind"] != "review")
                  and not (rules.new_only and "comparison" in report and not f.get("new"))]
    threshold = None if rules.fail_on == "none" else LEVELS.index(rules.fail_on)
    actionable = sum(threshold is not None and LEVELS.index(f["severity"]) <= threshold for f in considered)
    violations = []
    if actionable:
        violations.append({"gate": "severity", "count": actionable})
    gates = rules.gates
    checks = (("secrets", gates["secrets"], lambda f: f["category"] == "secrets"),
              ("malicious", gates["malicious"], lambda f: f.get("risk_type") == "malicious"),
              ("kev", gates["kev"], lambda f: f.get("kev") is True),
              ("epss", gates["epss"] is not None,
               lambda f: "epss" in f and f["epss"]["score"] >= gates["epss"]),
              ("licenses", gates["licenses"], lambda f: f.get("risk_type") == "license"))
    for name, enabled, matches in checks:
        count = sum(1 for f in considered if matches(f)) if enabled else 0
        if count:
            violations.append({"gate": name, "count": count})
    for level in LEVELS:
        if level in gates["max"]:
            count = sum(f["severity"] == level for f in considered)
            if count > gates["max"][level]:
                violations.append({"gate": "max:" + level, "count": count, "limit": gates["max"][level]})
    report["findings"] = [ordered(f, FINDING_ORDER) for f in kept]
    report["groups"] = groups(report["findings"], report["revision"])
    report["policy"] = {"passed": not violations, "source": rules.source, "minimum_severity": rules.fail_on,
                        "new_only": rules.new_only, "include_review": rules.include_review,
                        "actionable": actionable, "suppressed": sum(f["suppressed"] for f in kept),
                        "disabled_findings": disabled, "violations": violations,
                        "expired_exceptions": [{"fingerprint": k, "expires": v} for k, v in sorted(expired.items())],
                        "stale_exceptions": stale}
    reordered = ordered(report, REPORT_ORDER)
    report.clear()
    report.update(reordered)
    return report


def reevaluate(report, *, policy=None, exceptions=None, fail_on=None, new_since=None, epss=None, kev=None,
               today=None):
    """Return a copy of a schema-3 report with enrichment, suppression, comparison and policy recomputed."""
    if not isinstance(report, dict) or report.get("schema_version") != 3:
        raise ValueError("expected a schema 3 CRAB report")
    result = copy.deepcopy(report)
    return evaluate(result, policy=policy, exceptions=exceptions, fail_on=fail_on, new_since=new_since,
                    epss=epss, kev=kev, today=today)


def exit_status(report):
    if report["errors"]:
        return 2
    return 0 if report["policy"]["passed"] else 1
