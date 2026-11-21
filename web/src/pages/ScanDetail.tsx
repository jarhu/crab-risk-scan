import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import type { ReportFormat, ScanDetail as Scan } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CategoryBars, SeverityCards } from "../components/charts";
import { DownloadButton, Empty, ErrorMessage, ExternalLink, Loading, SeverityBadge, StatusBadge } from "../components/ui";
import { formatDate, shortId } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const DOWNLOADS: { format: ReportFormat; label: string; template?: "technical" | "executive" }[] = [
  { format: "json", label: "JSON" },
  { format: "sarif", label: "SARIF" },
  { format: "markdown", label: "Markdown" },
  { format: "html", label: "HTML" },
  { format: "csv", label: "CSV" },
  { format: "codequality", label: "GitLab Code Quality" },
  { format: "vex", label: "CycloneDX VEX" },
  { format: "docx", label: "DOCX technical", template: "technical" },
  { format: "docx", label: "DOCX executive", template: "executive" },
];

function Coverage({ scan }: { scan: Scan }) {
  if (!scan.imports.length) return <Empty>No engines or imports were recorded.</Empty>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">#</th>
          <th scope="col">Producer</th>
          <th scope="col">Origin</th>
          <th scope="col">Status</th>
          <th scope="col">Reason</th>
          <th scope="col">Version</th>
          <th scope="col">Rule pack</th>
          <th scope="col" className="num">
            Targets
          </th>
        </tr>
      </thead>
      <tbody>
        {scan.imports.map((item) => (
          <tr key={item.input}>
            <td>{item.input}</td>
            <td>{item.producer}</td>
            <td>{item.origin}</td>
            <td>
              <StatusBadge status={item.status} />
            </td>
            <td>{item.reason ?? "—"}</td>
            <td className="mono">{item.producer_version ?? "—"}</td>
            <td className="mono">{item.rule_pack ?? "—"}</td>
            <td className="num">{item.targets ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Policy({ scan }: { scan: Scan }) {
  const policy = scan.policy;
  return (
    <div>
      <p>
        <StatusBadge status={policy.passed ? "passed" : "failed"} /> Threshold <strong>{policy.minimum_severity ?? "—"}</strong>, policy source{" "}
        {policy.source ?? "—"}
        {policy.new_only ? ", new findings only" : ""}
        {policy.include_review === false ? ", review signals excluded" : ""}.
      </p>
      <p className="muted">
        {policy.actionable ?? 0} actionable, {policy.suppressed ?? 0} suppressed, {policy.disabled_findings ?? 0} disabled by policy.
      </p>
      {policy.violations.length ? (
        <table className="table compact">
          <thead>
            <tr>
              <th scope="col">Gate</th>
              <th scope="col" className="num">
                Count
              </th>
              <th scope="col" className="num">
                Limit
              </th>
            </tr>
          </thead>
          <tbody>
            {policy.violations.map((violation) => (
              <tr key={violation.gate}>
                <td>{violation.gate}</td>
                <td className="num">{violation.count}</td>
                <td className="num">{violation.limit ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No policy violations.</p>
      )}
      {policy.expired_exceptions?.length ? (
        <>
          <h3>Expired exceptions</h3>
          <ul className="plain">
            {policy.expired_exceptions.map((item) => (
              <li key={item.fingerprint}>
                <span className="mono">{shortId(item.fingerprint, 16)}</span> expired {item.expires}
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {policy.stale_exceptions?.length ? (
        <>
          <h3>Stale exceptions</h3>
          <p className="muted">These exceptions matched no finding in this scan.</p>
          <ul className="plain">
            {policy.stale_exceptions.map((fingerprint) => (
              <li key={fingerprint} className="mono">
                {shortId(fingerprint, 16)}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}

function CompareWith({ scan }: { scan: Scan }) {
  const { api } = useAuth();
  const navigate = useNavigate();
  const { data } = useAsync(() => api.scans(scan.project, { page_size: 100 }), [scan.project]);
  const others = (data?.items ?? []).filter((item) => String(item.id) !== String(scan.id));
  const [base, setBase] = useState("");
  if (!others.length) return null;
  return (
    <form
      className="inline-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (base) navigate(`/scans/${encodeURIComponent(String(scan.id))}/compare?base=${encodeURIComponent(base)}`);
      }}
    >
      <label className="inline-field">
        <span>Compare with</span>
        <select value={base} onChange={(e) => setBase(e.target.value)} required>
          <option value="">Select a scan</option>
          {others.map((item) => (
            <option key={item.id} value={String(item.id)}>
              #{item.id} {shortId(item.revision)} {formatDate(item.created_at)}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" className="btn" disabled={!base}>
        Compare
      </button>
    </form>
  );
}

export default function ScanDetail() {
  const { id = "" } = useParams();
  const { api } = useAuth();
  const { data: scan, error, loading } = useAsync(() => api.scan(id), [id]);
  if (error) return <ErrorMessage error={error} />;
  if (loading && !scan) return <Loading />;
  if (!scan) return null;
  const projectPath = `/projects/${encodeURIComponent(scan.project)}`;
  return (
    <div>
      <div className="page-header">
        <p className="breadcrumb">
          <Link to="/projects">Projects</Link> / <Link to={projectPath}>{scan.project}</Link> / <Link to={`${projectPath}/scans`}>Scans</Link>
        </p>
        <h1>
          Scan #{scan.id} <StatusBadge status={scan.status} />
        </h1>
      </div>
      <dl className="facts">
        <div>
          <dt>Target</dt>
          <dd>{scan.target}</dd>
        </div>
        <div>
          <dt>Revision</dt>
          <dd className="mono">{scan.revision ?? "—"}</dd>
        </div>
        <div>
          <dt>Branch</dt>
          <dd>{scan.branch ?? "—"}</dd>
        </div>
        <div>
          <dt>Repository</dt>
          <dd>{scan.repository ? <ExternalLink href={scan.repository} /> : "—"}</dd>
        </div>
        <div>
          <dt>Source</dt>
          <dd>{scan.source ?? "—"}</dd>
        </div>
        <div>
          <dt>Tool</dt>
          <dd>
            {scan.tool?.name} {scan.tool?.version}
          </dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{formatDate(scan.created_at)}</dd>
        </div>
      </dl>
      <div className="actions">
        <Link className="btn btn-primary" to={`/scans/${encodeURIComponent(String(scan.id))}/findings`}>
          View findings ({scan.total})
        </Link>
        <CompareWith scan={scan} />
      </div>
      <section aria-labelledby="ssev-title">
        <h2 id="ssev-title">Open findings</h2>
        <SeverityCards counts={scan.counts} />
        <p className="muted">
          {scan.suppressed} suppressed{scan.new !== null && scan.new !== undefined ? `, ${scan.new} new` : ""}.
        </p>
      </section>
      <div className="grid two">
        <section className="card" aria-labelledby="scat-title">
          <h2 id="scat-title">By category</h2>
          <CategoryBars categories={scan.categories} />
        </section>
        <section className="card" aria-labelledby="spol-title">
          <h2 id="spol-title">Policy</h2>
          <Policy scan={scan} />
        </section>
      </div>
      <section className="card" aria-labelledby="cov-title">
        <h2 id="cov-title">Coverage</h2>
        <Coverage scan={scan} />
      </section>
      {scan.errors.length ? (
        <section className="card" aria-labelledby="err-title">
          <h2 id="err-title">Errors</h2>
          <p className="muted">Errors make the scan incomplete. Coverage is not guaranteed for the affected inputs.</p>
          <table className="table compact">
            <thead>
              <tr>
                <th scope="col">Reason</th>
                <th scope="col">Producer</th>
                <th scope="col">Input</th>
                <th scope="col">Path</th>
              </tr>
            </thead>
            <tbody>
              {scan.errors.map((item, index) => (
                <tr key={index}>
                  <td>{item.reason}</td>
                  <td>{item.producer ?? "—"}</td>
                  <td>{item.input ?? "—"}</td>
                  <td className="mono">{item.path ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
      {scan.comparison ? (
        <section className="card" aria-labelledby="cmp-title">
          <h2 id="cmp-title">Embedded comparison</h2>
          <p>
            Against base revision <span className="mono">{scan.comparison.base_revision ?? "—"}</span>: {scan.comparison.new} new,{" "}
            {scan.comparison.unchanged} unchanged, {scan.comparison.fixed.length} fixed.
          </p>
          {scan.comparison.fixed.length ? (
            <table className="table compact">
              <thead>
                <tr>
                  <th scope="col">Severity</th>
                  <th scope="col">Rule</th>
                  <th scope="col">Location</th>
                </tr>
              </thead>
              <tbody>
                {scan.comparison.fixed.map((item) => (
                  <tr key={item.fingerprint}>
                    <td>
                      <SeverityBadge severity={item.severity} />
                    </td>
                    <td className="mono">
                      {item.producer}/{item.rule}
                    </td>
                    <td className="mono">{item.path ? `${item.path}${item.line ? `:${item.line}` : ""}` : (item.package?.name ?? "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
        </section>
      ) : null}
      <section className="card" aria-labelledby="dl-title">
        <h2 id="dl-title">Reports</h2>
        <p className="muted">Reports are rendered on download with the project's current exceptions applied.</p>
        <div className="download-grid">
          {DOWNLOADS.map((item) => (
            <DownloadButton key={item.label} label={item.label} fetcher={() => api.report(scan.id, item.format, item.template)} />
          ))}
          {scan.has_sbom ? <DownloadButton label="SBOM (CycloneDX)" fetcher={() => api.sbom(scan.id)} /> : null}
        </div>
      </section>
    </div>
  );
}
