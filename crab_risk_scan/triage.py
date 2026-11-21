"""Conservative correlation and inventory joins."""
from collections import defaultdict

from .evidence import LEVELS, array, fingerprint, purl_key, text

SOURCE_EQUIVALENTS = {("crab", "CRAB-PY-001"): "python-unverified-tls",
                      ("bandit", "B323"): "python-unverified-tls"}
COMPONENT_LIMIT = 200_000


def groups(findings, revision):
    parents = list(range(len(findings)))
    by_key = {}

    def root(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    for i, hit in enumerate(findings):
        pkg = hit.get("package", {})
        keys = []
        key = purl_key(pkg.get("purl"), pkg.get("version")) if hit.get("risk_type") != "license" else None
        if key:
            location = (hit.get("image_digest"), hit.get("manifest"))
            base = ("package", key, pkg["version"], location)
            keys = [base + (a,) for a in [hit["rule"], *hit.get("aliases", [])]]
        else:
            equivalence = SOURCE_EQUIVALENTS.get((hit["producer"], hit["rule"]))
            if equivalence and "byte_offset" in hit and "end_byte_offset" in hit:
                keys = [(equivalence, hit["path"], hit["line"], hit["byte_offset"],
                         hit["end_line"], hit["end_byte_offset"])]
        for key in keys:
            previous = by_key.setdefault(key, i)
            parents[root(i)] = root(previous)
    members = defaultdict(list)
    for i, hit in enumerate(findings):
        members[root(i)].append(hit)
    output = []
    for hits in members.values():
        ids = sorted(h["fingerprint"] for h in hits)
        entry = {"id": fingerprint(["map-v1", revision, ids]), "observations": ids,
                 "revision": revision, "mapping_version": 1,
                 "severity": min((h["severity"] for h in hits), key=LEVELS.index)}
        digests = {h.get("image_digest") for h in hits}
        if len(digests) == 1 and None not in digests:
            entry["image_digest"] = digests.pop()
        output.append(entry)
    return output


def licenses_of(item):
    found = []
    for entry in array(item.get("licenses") or []):
        if not isinstance(entry, dict):
            raise ValueError("invalid license entry")
        values = []
        if "expression" in entry:
            values.append(entry["expression"])
        if "license" in entry:
            license_ = entry["license"]
            if not isinstance(license_, dict):
                raise ValueError("invalid license entry")
            values.append(license_["id"] if "id" in license_ else license_["name"])
        for value in values:
            value = text(value)
            if value not in found:
                found.append(value)
    return found


def link_inventory(doc, findings):
    """Summarize a CycloneDX document: components, licenses and direct dependencies."""
    if doc["bomFormat"] != "CycloneDX" or not isinstance(doc["specVersion"], str) or len(doc["specVersion"]) > 32:
        raise ValueError("expected CycloneDX")
    metadata = doc.get("metadata") or {}
    root_ref = (metadata.get("component") or {}).get("bom-ref") if isinstance(metadata, dict) else None
    graph = doc.get("dependencies")
    direct_refs = None
    if isinstance(root_ref, str) and graph is not None:
        direct_refs = set()
        for node in array(graph):
            if not isinstance(node, dict) or not isinstance(node.get("ref"), str):
                raise ValueError("invalid dependency node")
            if node["ref"] == root_ref:
                direct_refs.update(r for r in array(node.get("dependsOn") or []) if isinstance(r, str))
    components = []
    pending = list(reversed(array(doc.get("components", []))))
    while pending:
        item = pending.pop()
        if not isinstance(item, dict):
            raise ValueError("invalid component")
        name = item["name"]
        version, purl, ref = item.get("version"), item.get("purl"), item.get("bom-ref")
        if (not isinstance(name, str) or len(name) > 1024
                or any(v is not None and not isinstance(v, str) for v in (version, purl, ref))
                or (version and len(version) > 256) or (purl and len(purl) > 1100)):
            raise ValueError("invalid component")
        direct = None
        if direct_refs is not None and ref:
            direct = ref in direct_refs
        components.append({"name": name, "version": version, "purl": purl, "licenses": licenses_of(item),
                           "direct": direct, "observations": []})
        if len(components) > COMPONENT_LIMIT:
            raise ValueError("component limit")
        pending.extend(reversed(array(item.get("components", []))))
    inventory = {"format": "cyclonedx", "spec_version": doc["specVersion"], "components": components}
    relink(inventory, findings)
    return inventory


def relink(inventory, findings):
    """Recompute finding-to-component links using canonical package URLs."""
    index = defaultdict(list)
    for position, component in enumerate(inventory["components"]):
        component["observations"] = []
        key = purl_key(component["purl"], component["version"])
        if key and component["version"]:
            index[key].append(position)
    for hit in findings:
        if "package" not in hit:
            continue
        if hit.get("risk_type") == "license":
            linked = hit.get("inventory_components", [])
        elif hit.get("image_digest"):
            linked = []
        else:
            pkg = hit["package"]
            linked = list(index.get(purl_key(pkg.get("purl"), pkg["version"]), []))
        hit["inventory_components"] = linked
        for position in linked:
            inventory["components"][position]["observations"].append(hit["fingerprint"])
    for component in inventory["components"]:
        component["observations"] = sorted(set(component["observations"]))
