import { Link } from "react-router";
import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { CategoryBars, PolicySummary, SeverityCards, TopPackages, TopRules, TrendChart } from "../components/charts";
import { useProject } from "../components/Layout";
import { ScanTable } from "../components/scans";
import { Empty, ErrorMessage, ExternalLink, Loading, StatusBadge } from "../components/ui";
import { formatDate, shortId } from "../lib/format";
import { useAsync } from "../lib/useAsync";

export default function ProjectOverview() {
  const { project } = useProject();
  const { api } = useAuth();
  const [days, setDays] = useState(30);
  const { data, error, loading } = useAsync(() => api.projectDashboard(project.key, days), [project.key, days]);
  const latest = data?.latest_scan ?? project.latest_scan ?? null;
  return (
    <div>
      <dl className="facts">
        <div>
          <dt>Repository</dt>
          <dd>{project.repository_url ? <ExternalLink href={project.repository_url} /> : "—"}</dd>
        </div>
        <div>
          <dt>Default branch</dt>
          <dd>{project.default_branch ?? "—"}</dd>
        </div>
        <div>
          <dt>Latest scan</dt>
          <dd>
            {latest ? (
              <>
                <Link to={`/scans/${encodeURIComponent(String(latest.id))}`}>#{latest.id}</Link> <StatusBadge status={latest.status} />{" "}
                <span className="mono">{shortId(latest.revision)}</span> {formatDate(latest.created_at)}
              </>
            ) : (
              "No scans yet"
            )}
          </dd>
        </div>
      </dl>
      <ErrorMessage error={error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        <>
          <section aria-labelledby="psev-title">
            <h2 id="psev-title">Open findings</h2>
            <SeverityCards counts={data.counts} />
          </section>
          <div className="grid two">
            <section className="card" aria-labelledby="pcat-title">
              <h2 id="pcat-title">By category</h2>
              <CategoryBars categories={data.categories} />
            </section>
            <section className="card" aria-labelledby="ppol-title">
              <h2 id="ppol-title">Policy status</h2>
              {latest ? (
                <p>
                  Latest scan: <StatusBadge status={latest.status} />
                  {latest.policy.violations.length ? (
                    <span className="muted"> ({latest.policy.violations.map((v) => `${v.gate} ${v.count}`).join(", ")})</span>
                  ) : null}
                </p>
              ) : null}
              <PolicySummary policy={data.policy} />
            </section>
          </div>
          <section className="card" aria-labelledby="ptrend-title">
            <div className="row">
              <h2 id="ptrend-title">Trend</h2>
              <label className="inline-field">
                <span>Window</span>
                <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
                  <option value={7}>7 days</option>
                  <option value={30}>30 days</option>
                  <option value={90}>90 days</option>
                  <option value={365}>365 days</option>
                </select>
              </label>
            </div>
            <TrendChart trend={data.trend} />
          </section>
          <div className="grid two">
            <section className="card" aria-labelledby="prules-title">
              <h2 id="prules-title">Top rules</h2>
              <TopRules rules={data.top_rules} />
            </section>
            <section className="card" aria-labelledby="ppkg-title">
              <h2 id="ppkg-title">Top packages</h2>
              <TopPackages packages={data.top_packages} />
            </section>
          </div>
          <section className="card" aria-labelledby="precent-title">
            <h2 id="precent-title">Recent scans</h2>
            {data.recent_scans?.length ? <ScanTable scans={data.recent_scans} /> : <Empty>No scans yet.</Empty>}
            <p>
              <Link to="scans">Full scan history</Link>
            </p>
          </section>
        </>
      ) : null}
    </div>
  );
}
