import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";
import { useAuth } from "../auth/AuthContext";
import { SeverityInline } from "../components/scans";
import { Can, Empty, ErrorMessage, ExternalLink, Loading, Pagination, StatusBadge, useAction } from "../components/ui";
import { formatDate } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const PAGE_SIZE = 50;

function CreateProject() {
  const { api } = useAuth();
  const navigate = useNavigate();
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [repository, setRepository] = useState("");
  const [branch, setBranch] = useState("");
  const [scanPath, setScanPath] = useState("");
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const created = await run(() =>
      api.createProject({
        key: key.trim(),
        name: name.trim(),
        repository_url: repository.trim() || null,
        default_branch: branch.trim() || null,
        scan_path: scanPath.trim() || null,
      }),
    );
    if (created) navigate(`/projects/${encodeURIComponent(created.key)}`);
  }

  return (
    <form className="card form-grid" onSubmit={submit} aria-labelledby="create-title">
      <h2 id="create-title">Create project</h2>
      <ErrorMessage error={error} />
      <label className="field">
        <span>Key</span>
        <input required maxLength={64} value={key} onChange={(e) => setKey(e.target.value)} />
      </label>
      <label className="field">
        <span>Name</span>
        <input required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label className="field">
        <span>Repository URL</span>
        <input type="url" placeholder="https://" value={repository} onChange={(e) => setRepository(e.target.value)} />
      </label>
      <label className="field">
        <span>Default branch</span>
        <input value={branch} onChange={(e) => setBranch(e.target.value)} />
      </label>
      <label className="field">
        <span>Scan path</span>
        <input maxLength={4096} placeholder="Absolute path inside a server scan root" value={scanPath} onChange={(e) => setScanPath(e.target.value)} />
      </label>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Create project
        </button>
      </div>
    </form>
  );
}

export default function Projects() {
  const { api, isAdmin } = useAuth();
  const [page, setPage] = useState(1);
  const { data, error, loading } = useAsync(() => api.projects({ page, page_size: PAGE_SIZE }), [page]);
  return (
    <div>
      <div className="page-header">
        <h1>Projects</h1>
      </div>
      <Can allowed={isAdmin}>
        <CreateProject />
      </Can>
      <ErrorMessage error={error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        data.items.length === 0 ? (
          <Empty>{isAdmin ? "No projects yet." : "You are not a member of any project yet. Ask an administrator for access."}</Empty>
        ) : (
          <>
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Project</th>
                  <th scope="col">Key</th>
                  <th scope="col">Repository</th>
                  <th scope="col">Your role</th>
                  <th scope="col">Policy</th>
                  <th scope="col">Open findings</th>
                  <th scope="col">Latest scan</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((project) => (
                  <tr key={project.key}>
                    <td>
                      <Link to={`/projects/${encodeURIComponent(project.key)}`}>{project.name}</Link>
                    </td>
                    <td className="mono">{project.key}</td>
                    <td>{project.repository_url ? <ExternalLink href={project.repository_url} /> : "—"}</td>
                    <td>{project.role ?? "—"}</td>
                    <td>{project.latest_scan ? <StatusBadge status={project.latest_scan.status} /> : <span className="muted">no scans</span>}</td>
                    <td>{project.latest_scan ? <SeverityInline counts={project.latest_scan.counts} /> : "—"}</td>
                    <td>{project.latest_scan ? formatDate(project.latest_scan.created_at) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />
          </>
        )
      ) : null}
    </div>
  );
}
