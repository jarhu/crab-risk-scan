import { Link } from "react-router";
import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { CategoryBars, PolicySummary, SeverityCards, TopPackages, TopRules, TrendChart } from "../components/charts";
import { SeverityInline } from "../components/scans";
import { Empty, ErrorMessage, Loading, StatusBadge } from "../components/ui";
import { formatDate } from "../lib/format";
import { useAsync } from "../lib/useAsync";

export default function Dashboard() {
  const { api } = useAuth();
  const [days, setDays] = useState(30);
  const { data, error, loading } = useAsync(() => api.dashboard(days), [days]);
  return (
    <div>
      <div className="page-header row">
        <h1>Organization dashboard</h1>
        <label className="inline-field">
          <span>Trend window</span>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
            <option value={365}>365 days</option>
          </select>
        </label>
      </div>
      <ErrorMessage error={error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        <>
          <p className="muted">
            {data.projects} projects, {data.scans} scans. Figures cover each project's latest scan.
          </p>
          <section aria-labelledby="sev-title">
            <h2 id="sev-title">Open findings</h2>
            <SeverityCards counts={data.counts} />
          </section>
          <div className="grid two">
            <section className="card" aria-labelledby="cat-title">
              <h2 id="cat-title">By category</h2>
              <CategoryBars categories={data.categories} />
            </section>
            <section className="card" aria-labelledby="policy-title">
              <h2 id="policy-title">Policy</h2>
              <PolicySummary policy={data.policy} />
            </section>
          </div>
          <section className="card" aria-labelledby="trend-title">
            <h2 id="trend-title">Trend</h2>
            <TrendChart trend={data.trend} />
          </section>
          <div className="grid two">
            <section className="card" aria-labelledby="rules-title">
              <h2 id="rules-title">Top rules</h2>
              <TopRules rules={data.top_rules} />
            </section>
            <section className="card" aria-labelledby="pkg-title">
              <h2 id="pkg-title">Top packages</h2>
              <TopPackages packages={data.top_packages} />
            </section>
          </div>
          <section className="card" aria-labelledby="projects-title">
            <h2 id="projects-title">Projects</h2>
            {data.projects_summary.length === 0 ? (
              <Empty>
                No projects yet. <Link to="/projects">Create a project</Link>.
              </Empty>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Project</th>
                    <th scope="col">Policy</th>
                    <th scope="col">Open findings</th>
                    <th scope="col">Latest scan</th>
                  </tr>
                </thead>
                <tbody>
                  {data.projects_summary.map((project) => (
                    <tr key={project.key}>
                      <td>
                        <Link to={`/projects/${encodeURIComponent(project.key)}`}>{project.name}</Link>
                      </td>
                      <td>{project.latest_scan ? <StatusBadge status={project.latest_scan.status} /> : <span className="muted">no scans</span>}</td>
                      <td>{project.latest_scan ? <SeverityInline counts={project.latest_scan.counts} /> : "—"}</td>
                      <td>
                        {project.latest_scan ? (
                          <Link to={`/scans/${encodeURIComponent(String(project.latest_scan.id))}`}>{formatDate(project.latest_scan.created_at)}</Link>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      ) : null}
    </div>
  );
}
