"""Self-contained HTML report with inline CSS and JavaScript.

Report data is embedded as JSON inside a non-executable
``<script type="application/json">`` block with ``<``, ``>`` and ``&`` escaped
as ``\\u003c``, ``\\u003e`` and ``\\u0026``. The inline script builds the page with
DOM APIs and ``textContent`` only. A Content-Security-Policy meta tag allows
exactly the inline script and stylesheet by SHA-256 hash and nothing else.
"""
import base64
import hashlib
import html
import json

from . import summary

EXECUTIVE_TOP = 10
PRIORITY_LIMIT = 25

STYLE = """
:root{--bg:#f6f7f9;--fg:#1d2330;--muted:#5b6475;--card:#fff;--line:#d9dde5;--accent:#2457c5;
--critical:#8b1a1a;--high:#c0392b;--medium:#c27c0e;--low:#2f7d32;--info:#2b6cb0;--unknown:#6b7280;
--ok:#2f7d32;--bad:#b42318;--warn:#b26a00;color-scheme:light}
:root[data-theme=dark]{--bg:#12151c;--fg:#e6e9ef;--muted:#9aa3b2;--card:#1b2029;--line:#2e3542;--accent:#7aa2ff;
--critical:#ff6b6b;--high:#ff8a65;--medium:#ffc857;--low:#7bd88f;--info:#7cc4ff;--unknown:#a0a7b4;
--ok:#7bd88f;--bad:#ff6b6b;--warn:#ffc857;color-scheme:dark}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#12151c;--fg:#e6e9ef;--muted:#9aa3b2;
--card:#1b2029;--line:#2e3542;--accent:#7aa2ff;--critical:#ff6b6b;--high:#ff8a65;--medium:#ffc857;--low:#7bd88f;
--info:#7cc4ff;--unknown:#a0a7b4;--ok:#7bd88f;--bad:#ff6b6b;--warn:#ffc857;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px}
header.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
h1{font-size:24px;margin:0 0 8px}h2{font-size:18px;margin:0 0 12px}h3{font-size:15px;margin:16px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 20px;margin:16px 0}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;margin:0}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;word-break:break-all}
.toolbar button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;
padding:6px 12px;cursor:pointer;margin-left:6px}
.banner{border-radius:8px;padding:12px 16px;margin:16px 0;border:1px solid var(--line);border-left-width:6px}
.banner-passed{border-left-color:var(--ok)}.banner-failed{border-left-color:var(--bad)}
.banner-incomplete{border-left-color:var(--warn)}.banner ul{margin:6px 0 0;padding-left:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}
.sevcard{border:1px solid var(--line);border-top:4px solid var(--unknown);border-radius:8px;padding:10px 12px}
.sevcard .n{font-size:26px;font-weight:700}.sevcard .l{color:var(--muted)}
.sevcard.sev-critical{border-top-color:var(--critical)}.sevcard.sev-high{border-top-color:var(--high)}
.sevcard.sev-medium{border-top-color:var(--medium)}.sevcard.sev-low{border-top-color:var(--low)}
.sevcard.sev-info{border-top-color:var(--info)}
.bars{display:grid;grid-template-columns:max-content 1fr max-content;gap:6px 12px;align-items:center}
.track{background:var(--bg);border:1px solid var(--line);border-radius:4px;height:14px;overflow:hidden}
.fill{background:var(--accent);height:100%;width:0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{color:var(--muted);font-weight:600}th.sortable{cursor:pointer;user-select:none}
th.sortable:after{content:" \\2195";opacity:.4}th.asc:after{content:" \\2191";opacity:1}
th.desc:after{content:" \\2193";opacity:1}
.sev{display:inline-block;border-radius:10px;padding:0 8px;font-size:12px;font-weight:600;color:#fff;
background:var(--unknown)}
.sev.sev-critical{background:var(--critical)}.sev.sev-high{background:var(--high)}
.sev.sev-medium{background:var(--medium);color:#1d2330}.sev.sev-low{background:var(--low)}
.sev.sev-info{background:var(--info)}
.tag{display:inline-block;border:1px solid var(--line);border-radius:10px;padding:0 6px;margin:0 4px 2px 0;
font-size:12px}
.tag-hot{border-color:var(--bad);color:var(--bad);font-weight:600}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.controls input,.controls select{background:var(--card);color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:6px 8px}
.controls input{flex:1 1 240px}
details summary{cursor:pointer}details ul{margin:6px 0;padding-left:18px}
.posture{font-size:20px;font-weight:700}
.posture-critical{color:var(--critical)}.posture-high{color:var(--high)}.posture-moderate{color:var(--medium)}
.posture-low{color:var(--low)}.posture-minimal{color:var(--ok)}
ol.recs li{margin-bottom:6px}
footer{color:var(--muted);font-size:12px;margin:24px 0}
@media print{body{background:#fff;color:#000}main{max-width:none;padding:0}
.toolbar,.controls,noscript{display:none}.card{border:1px solid #999;break-inside:avoid-page}
th.sortable:after{content:""}a{color:#000}}
"""

SCRIPT = r"""
(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("crab-data").textContent);
  var root = document.getElementById("app");
  var L = data.labels;

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }
  function add(parent, child) { parent.appendChild(child); return child; }
  function toNode(value) {
    if (value instanceof Node) { return value; }
    return document.createTextNode(value === null || value === undefined ? "" : String(value));
  }
  function section(title) {
    var node = add(root, el("section", "card"));
    add(node, el("h2", null, title));
    return node;
  }
  function para(parent, text, cls) { return add(parent, el("p", cls || null, text)); }
  function table(headers, rows) {
    var tbl = el("table");
    var head = add(add(tbl, el("thead")), el("tr"));
    headers.forEach(function (h) { add(head, el("th", null, h)); });
    var body = add(tbl, el("tbody"));
    rows.forEach(function (row) {
      var tr = add(body, el("tr"));
      row.forEach(function (value) { add(add(tr, el("td")), toNode(value)); });
    });
    return tbl;
  }
  function link(text, uri) {
    if (typeof uri === "string" && /^https?:\/\//i.test(uri)) {
      var a = el("a", null, text);
      a.href = uri;
      a.rel = "noopener noreferrer";
      a.target = "_blank";
      return a;
    }
    return document.createTextNode(text);
  }
  function badge(level) { return el("span", "sev sev-" + level, L.severity[level] || level); }
  function tags(list) {
    var span = el("span");
    list.forEach(function (t) {
      add(span, el("span", (t === "KEV" || t === "Malicious") ? "tag tag-hot" : "tag", t));
    });
    return span;
  }

  function header() {
    var top = add(root, el("header", "top"));
    var left = add(top, el("div"));
    add(left, el("h1", null, (data.variant === "executive" ? "Security summary: " : "CRAB security report: ") +
      data.meta.target));
    var dl = add(left, el("dl", "meta"));
    data.metaRows.forEach(function (row) {
      add(dl, el("dt", null, row[0]));
      var dd = add(dl, el("dd"));
      add(dd, row[2] ? link(row[1], row[1]) : toNode(row[1]));
    });
    var bar = add(top, el("div", "toolbar"));
    var theme = add(bar, el("button", null, "Toggle theme"));
    theme.type = "button";
    theme.addEventListener("click", function () {
      var html = document.documentElement;
      var dark = html.getAttribute("data-theme") === "dark" ||
        (!html.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
      html.setAttribute("data-theme", dark ? "light" : "dark");
    });
    var printer = add(bar, el("button", null, "Print"));
    printer.type = "button";
    printer.addEventListener("click", function () { window.print(); });
  }

  function banner() {
    var p = data.policy;
    var box = add(root, el("div", "banner banner-" + p.status));
    add(box, el("strong", null, p.headline));
    add(box, document.createTextNode(" Threshold: " + p.minimum_severity + ". Actionable findings: " +
      p.actionable + ". Suppressed: " + p.suppressed + "."));
    if (p.violations.length) {
      var ul = add(box, el("ul"));
      p.violations.forEach(function (v) { add(ul, el("li", null, v)); });
    }
  }

  function posture(parent) {
    add(parent, el("div", "posture posture-" + data.posture.rating, "Posture: " + data.posture.label));
    para(parent, data.posture.description);
  }

  function severityCards(parent) {
    var cards = add(parent, el("div", "cards"));
    L.severities.forEach(function (level) {
      var c = add(cards, el("div", "sevcard sev-" + level));
      add(c, el("div", "n", data.counts.severity[level]));
      add(c, el("div", "l", L.severity[level]));
    });
    para(parent, "Open findings: " + data.counts.total + ". Suppressed: " + data.counts.suppressed +
      ". Vulnerabilities: " + data.counts.kind.vulnerability + ". Review signals: " + data.counts.kind.review + ".",
      "muted");
  }

  function categoryBars(parent) {
    add(parent, el("h3", null, "Open findings by category"));
    var bars = add(parent, el("div", "bars"));
    var max = 1;
    L.categories.forEach(function (c) { max = Math.max(max, data.counts.category[c]); });
    L.categories.forEach(function (c) {
      add(bars, el("div", null, L.category[c]));
      var track = add(bars, el("div", "track"));
      var fill = add(track, el("div", "fill"));
      fill.style.width = (100 * data.counts.category[c] / max).toFixed(1) + "%";
      add(bars, el("div", null, data.counts.category[c]));
    });
  }

  function metrics(parent) {
    var cards = add(parent, el("div", "cards"));
    data.metrics.forEach(function (m) {
      var c = add(cards, el("div", "sevcard"));
      add(c, el("div", "n", m[1]));
      add(c, el("div", "l", m[0]));
    });
  }

  function recommendations(parent) {
    if (!data.recommendations.length) { para(parent, "No action required."); return; }
    var ol = add(parent, el("ol", "recs"));
    data.recommendations.forEach(function (r) {
      var li = add(ol, el("li"));
      add(li, el("strong", null, r.label + " (" + r.count + "): "));
      add(li, document.createTextNode(r.text));
    });
  }

  function topRisks(parent, limit) {
    var rows = data.top.slice(0, limit).map(function (index, n) {
      var f = data.findings[index];
      return [String(n + 1), badge(f.severity), f.title, f.categoryLabel, tags(f.signals)];
    });
    if (!rows.length) { para(parent, "No open findings."); return; }
    add(parent, table(["#", "Severity", "Risk", "Area", "Signals"], rows));
  }

  function coverage() {
    var s = section("Coverage");
    var rows = data.coverage.map(function (r) {
      return [String(r.input), r.producer, r.origin, r.status, r.reason, r.version, r.rule_pack, String(r.findings)];
    });
    if (rows.length) {
      add(s, table(["Input", "Producer", "Origin", "Status", "Reason", "Version", "Rule pack", "Findings"], rows));
    }
    para(s, data.coverage_complete ? "Coverage is complete." :
      "Coverage is incomplete. Skipped, partial or failed inputs did not contribute every result.", "muted");
  }

  function findingDetails(f) {
    var details = el("details");
    add(details, el("summary", null, f.title));
    var ul = add(details, el("ul"));
    var rule = add(ul, el("li"));
    add(rule, document.createTextNode("Rule: "));
    add(rule, link(f.rule, f.help));
    add(ul, el("li", null, "Guidance: " + f.message));
    add(ul, el("li", null, "Kind: " + f.kindLabel));
    f.details.forEach(function (d) { add(ul, el("li", null, d)); });
    add(ul, el("li", "mono", "Fingerprint: " + f.fingerprint));
    return details;
  }

  function findings() {
    var s = section("Findings");
    var controls = add(s, el("div", "controls"));
    var search = add(controls, el("input"));
    search.type = "search";
    search.placeholder = "Search rule, path, package or fingerprint";
    search.setAttribute("aria-label", "Search findings");
    function select(label, options) {
      var sel = add(controls, el("select"));
      sel.setAttribute("aria-label", label);
      options.forEach(function (o) { var opt = add(sel, el("option", null, o[1])); opt.value = o[0]; });
      return sel;
    }
    var sev = select("Severity", [["", "All severities"]].concat(L.severities.map(function (l) {
      return [l, L.severity[l]]; })));
    var cat = select("Category", [["", "All categories"]].concat(L.categories.map(function (c) {
      return [c, L.category[c]]; })));
    var kind = select("Kind", [["", "All kinds"], ["vulnerability", "Vulnerabilities"], ["review", "Review signals"]]);
    var status = select("Status", [["open", "Open"], ["", "Open and suppressed"], ["suppressed", "Suppressed"]]);
    var shown = para(s, "", "muted");
    var tbl = add(s, el("table"));
    var head = add(add(tbl, el("thead")), el("tr"));
    var columns = [["severity", "Severity"], ["title", "Finding"], ["location", "Location"],
      ["category", "Category"], ["risk", "Signals"], ["status", "Status"]];
    var sortKey = "risk", sortDir = 1;
    var ths = columns.map(function (c) {
      var th = add(head, el("th", "sortable", c[1]));
      th.addEventListener("click", function () {
        if (sortKey === c[0]) { sortDir = -sortDir; } else { sortKey = c[0]; sortDir = 1; }
        draw();
      });
      return th;
    });
    var body = add(tbl, el("tbody"));
    function value(f, key) {
      if (key === "severity") { return f.severityRank; }
      if (key === "risk") { return f.riskRank; }
      if (key === "category") { return f.categoryLabel; }
      return f[key];
    }
    function draw() {
      var q = search.value.trim().toLowerCase();
      var rows = data.findings.filter(function (f) {
        if (sev.value && f.severity !== sev.value) { return false; }
        if (cat.value && f.category !== cat.value) { return false; }
        if (kind.value && f.kind !== kind.value) { return false; }
        if (status.value === "open" && f.suppressed) { return false; }
        if (status.value === "suppressed" && !f.suppressed) { return false; }
        return !q || f.search.indexOf(q) !== -1;
      });
      rows.sort(function (a, b) {
        var x = value(a, sortKey), y = value(b, sortKey);
        if (x < y) { return -sortDir; }
        if (x > y) { return sortDir; }
        return a.riskRank - b.riskRank;
      });
      ths.forEach(function (th, i) {
        th.className = "sortable" + (columns[i][0] === sortKey ? (sortDir > 0 ? " asc" : " desc") : "");
      });
      while (body.firstChild) { body.removeChild(body.firstChild); }
      rows.forEach(function (f) {
        var tr = add(body, el("tr"));
        add(add(tr, el("td")), badge(f.severity));
        add(add(tr, el("td")), findingDetails(f));
        add(tr, el("td", "mono", f.location));
        add(tr, el("td", null, f.categoryLabel));
        add(add(tr, el("td")), tags(f.signals));
        add(tr, el("td", null, f.status));
      });
      shown.textContent = "Showing " + rows.length + " of " + data.findings.length + " findings.";
    }
    [search, sev, cat, kind, status].forEach(function (c) {
      c.addEventListener(c === search ? "input" : "change", draw);
    });
    draw();
  }

  function exceptions() {
    var s = section("Exceptions");
    if (data.exceptions.length) {
      add(s, table(["Fingerprint", "Rule", "Location", "Status", "Justification", "Reason", "Reviewer", "Expires",
        "Ticket"], data.exceptions.map(function (e) {
        return [el("span", "mono", e.fingerprint.slice(0, 12)), e.rule, e.location, e.statusLabel, e.justification,
          e.reason, e.reviewer, e.expires, e.ticket];
      })));
    } else {
      para(s, "No exceptions apply to this report.");
    }
    add(s, el("h3", null, "Expired and stale exceptions"));
    var p = data.policy;
    if (p.expired_exceptions.length) {
      add(s, table(["Expired fingerprint", "Expired"], p.expired_exceptions.map(function (e) {
        return [el("span", "mono", e.fingerprint), e.expires];
      })));
    }
    if (p.stale_exceptions.length) {
      add(s, table(["Stale fingerprint (matches no finding)"], p.stale_exceptions.map(function (fp) {
        return [el("span", "mono", fp)];
      })));
    }
    if (!p.expired_exceptions.length && !p.stale_exceptions.length) {
      para(s, "No expired or stale exceptions.");
    }
  }

  function comparison() {
    var s = section("Comparison");
    var c = data.comparison;
    if (!c) { para(s, "No base report was given, so new and fixed findings are not computed."); return; }
    para(s, "Base revision: " + (c.base_revision || "not recorded") + ". New: " + c.new + ". Unchanged: " +
      c.unchanged + ". Fixed: " + c.fixed.length + ".");
    if (c.fixed.length) {
      add(s, table(["Severity", "Category", "Rule", "Location", "Fingerprint"], c.fixed.map(function (f) {
        return [badge(f.severity), f.categoryLabel, f.rule, f.location, el("span", "mono", f.fingerprint.slice(0, 12))];
      })));
    }
  }

  function errors() {
    var s = section("Errors");
    if (!data.errors.length) { para(s, "No errors."); return; }
    add(s, table(["Reason", "Producer", "Input", "Path"], data.errors.map(function (e) {
      return [e.reason, e.producer || "", e.input === undefined || e.input === null ? "" : String(e.input),
        e.path || ""];
    })));
  }

  function inventory() {
    var s = section("Inventory and licenses");
    var inv = data.inventory;
    if (!inv) { para(s, "No software inventory was linked or generated."); return; }
    para(s, "Components: " + inv.components + " (" + inv.format + " " + inv.spec_version + "). Direct: " +
      inv.direct + ". Transitive: " + inv.transitive + ". With findings: " + inv.with_findings + ".");
    add(s, table(["License", "Components"], inv.licenses.map(function (l) { return [l[0], String(l[1])]; })));
  }

  header();
  banner();
  if (data.variant === "executive") {
    var p = section("Posture");
    posture(p);
    metrics(section("Key metrics"));
    topRisks(section("Top risks"), data.executiveTop);
    recommendations(section("Recommendations"));
  } else {
    var sum = section("Summary");
    posture(sum);
    severityCards(sum);
    categoryBars(sum);
    coverage();
    comparison();
    var pr = section("Prioritized findings");
    para(pr, "Order: known exploited and malicious first, then severity, EPSS and CVSS.", "muted");
    topRisks(pr, data.priorityLimit);
    recommendations(section("Recommendations"));
    findings();
    exceptions();
    errors();
    inventory();
  }
  add(root, el("footer", null, "Generated by " + data.meta.tool + " " + data.meta.tool_version +
    ". Posture ratings and recommendations are written by CRAB from structured findings."));
  window.addEventListener("beforeprint", function () {
    Array.prototype.forEach.call(document.querySelectorAll("details"), function (d) { d.open = true; });
  });
}());
"""


def csp_hash(text):
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def embed_json(value):
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def finding_view(finding, risk_rank):
    details = []
    if finding.get("cwe"):
        details.append("CWE: " + ", ".join(finding["cwe"]))
    reference = summary.package_ref(finding)
    if reference:
        details.append("Package: " + reference)
    if finding.get("fixed_version"):
        details.append("Fixed version: " + finding["fixed_version"])
    if finding.get("license"):
        details.append("License: " + finding["license"])
    if finding.get("cvss"):
        vector = finding["cvss"].get("vector")
        details.append(f"CVSS: {finding['cvss']['score']:.1f}" + (f" ({vector})" if vector else ""))
    if finding.get("epss"):
        epss = finding["epss"]
        text = f"EPSS: {epss['score']:.4f}"
        if epss.get("percentile") is not None:
            text += f", percentile {epss['percentile']:.4f}"
        details.append(text)
    if finding.get("image_digest"):
        details.append("Image digest: " + finding["image_digest"])
    if finding.get("original_severity") and finding["original_severity"] != finding["severity"]:
        details.append("Producer severity: " + finding["original_severity"])
    exception = finding.get("exception")
    if exception:
        status = summary.EXCEPTION_LABELS.get(exception.get("status"), exception.get("status") or "")
        details.append("Exception: " + status + (f" ({exception['reason']})" if exception.get("reason") else ""))
    view = {
        "severity": finding["severity"],
        "severityRank": summary.SEVERITY_RANK[finding["severity"]],
        "riskRank": risk_rank,
        "category": finding["category"],
        "categoryLabel": summary.CATEGORY_LABELS[finding["category"]],
        "kind": finding["kind"],
        "kindLabel": summary.KIND_LABELS[finding["kind"]],
        "rule": summary.rule_id(finding),
        "title": summary.title(finding),
        "location": summary.location(finding),
        "message": finding["message"],
        "details": details,
        "signals": summary.signal_labels(finding),
        "status": summary.status_label(finding),
        "suppressed": bool(finding.get("suppressed")),
        "fingerprint": finding["fingerprint"],
        "help": finding.get("help_uri"),
    }
    view["search"] = " ".join([view["rule"], view["title"], view["location"], view["message"],
                               view["fingerprint"], *details]).lower()
    return view


def payload(report, variant, generated_at):
    model = summary.build(report, generated_at)
    order = {id(finding): rank for rank, finding in enumerate(model["top"])}
    findings = report["findings"]
    open_count = len(model["top"])
    ranks = []
    extra = open_count
    for finding in findings:
        if id(finding) in order:
            ranks.append(order[id(finding)])
        else:
            ranks.append(extra)
            extra += 1
    views = [finding_view(finding, rank) for finding, rank in zip(findings, ranks)]
    top = sorted((index for index, finding in enumerate(findings) if id(finding) in order), key=lambda i: ranks[i])
    meta = model["meta"]
    meta_rows = [["Target", meta["target"], False]]
    if meta["repository"]:
        meta_rows.append(["Repository", meta["repository"], True])
    meta_rows += [["Revision", meta["revision"] or "not recorded", False],
                  ["Branch", meta["branch"] or "not recorded", False],
                  ["Tool", f"{meta['tool']} {meta['tool_version']}", False],
                  ["Files checked by built-in rules", str(meta["files_scanned"]), False]]
    if meta["generated_at"]:
        meta_rows.append(["Generated", meta["generated_at"], False])
    policy = dict(model["policy"])
    policy["headline"] = {"passed": "Policy passed.", "failed": "Policy failed.",
                          "incomplete": "Scan incomplete. Errors occurred, so the result is not conclusive."}[
        policy["status"]]
    comparison = model["comparison"]
    if comparison:
        comparison = {
            "base_revision": comparison.get("base_revision"),
            "new": comparison["new"],
            "unchanged": comparison["unchanged"],
            "fixed": [{"severity": f["severity"],
                       "categoryLabel": summary.CATEGORY_LABELS.get(f["category"], f["category"]),
                       "rule": f"{f['producer']}/{f['rule']}",
                       "location": ((f.get("path") or "") + (f":{f['line']}" if f.get("line") else ""))
                       if f.get("path") else (summary.package_ref(f) or "not located"),
                       "fingerprint": f["fingerprint"]} for f in comparison["fixed"]],
        }
    counts = model["counts"]
    found = model["signals"]
    covered = sum(1 for row in model["coverage"] if row["status"] in ("complete", "imported"))
    metrics = [
        ["Open findings", str(counts["total"])],
        ["Critical and high", str(counts["severity"]["critical"] + counts["severity"]["high"])],
        ["Known exploited (KEV)", str(found["kev"])],
        ["Malicious packages", str(found["malicious"])],
        ["Exposed secrets", str(found["secrets"])],
        ["Fix available", str(found["fixable"])],
        ["New since base", str(found["new"]) if model["comparison"] else "not compared"],
        ["Suppressed by exception", str(counts["suppressed"])],
        ["Scanner coverage", f"{covered} of {len(model['coverage'])} complete"],
    ]
    return {
        "variant": variant,
        "meta": meta,
        "metaRows": meta_rows,
        "policy": policy,
        "posture": model["posture"],
        "counts": {key: counts[key] for key in ("severity", "category", "kind", "total", "suppressed")},
        "metrics": metrics,
        "coverage": model["coverage"],
        "coverage_complete": model["coverage_complete"],
        "comparison": comparison,
        "recommendations": [{"label": summary.TOPIC_LABELS[r["topic"]], "count": r["count"], "text": r["text"]}
                            for r in model["recommendations"]],
        "exceptions": [{**row, "statusLabel": summary.EXCEPTION_LABELS.get(row["status"], row["status"])
                        + ("" if row["suppressed"] else " (not applied)")} for row in model["exceptions"]],
        "errors": model["errors"],
        "inventory": model["inventory"],
        "findings": views,
        "top": top,
        "executiveTop": EXECUTIVE_TOP,
        "priorityLimit": PRIORITY_LIMIT,
        "labels": {"severities": list(summary.SEVERITIES), "categories": list(summary.CATEGORIES),
                   "severity": summary.SEVERITY_LABELS, "category": summary.CATEGORY_LABELS},
    }


def render(report, *, template="technical", generated_at=None):
    variant = "executive" if template == "executive" else "technical"
    data = embed_json(payload(report, variant, generated_at))
    policy = (f"default-src 'none'; script-src '{csp_hash(SCRIPT)}'; style-src '{csp_hash(STYLE)}'; "
              "img-src 'none'; base-uri 'none'; form-action 'none'")
    heading = "Security summary" if variant == "executive" else "CRAB security report"
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{policy}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{html.escape(heading + ': ' + report['target'])}</title>\n"
        f"<style>{STYLE}</style>\n</head>\n<body>\n<main id=\"app\">\n"
        "<noscript><p>This report renders its content with JavaScript. Enable scripts for this file, "
        "or open the Markdown or JSON report instead.</p></noscript>\n</main>\n"
        f'<script type="application/json" id="crab-data">{data}</script>\n'
        f"<script>{SCRIPT}</script>\n</body>\n</html>\n"
    )
