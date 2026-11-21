import { useState, type FormEvent } from "react";
import type { CreatedToken, TokenScope } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { TokenSecret } from "../components/TokenSecret";
import { Empty, ErrorMessage, Loading, Pagination, confirmAction, useAction } from "../components/ui";
import { formatDate } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const PAGE_SIZE = 50;
const SCOPES: { scope: TokenScope; label: string }[] = [
  { scope: "worker", label: "worker (claim and run jobs)" },
  { scope: "scan:upload", label: "scan:upload (CI uploads)" },
  { scope: "read", label: "read" },
];

export default function AdminTokens() {
  const { api } = useAuth();
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useAsync(() => api.tokens({ page, page_size: PAGE_SIZE }), [page]);
  const projects = useAsync(() => api.allProjects(), []);
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<TokenScope[]>(["worker"]);
  const [project, setProject] = useState("");
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const action = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const token = await action.run(() => api.createToken({ name: name.trim(), scopes, ...(project ? { project } : {}) }));
    if (token) {
      setCreated(token);
      setName("");
      reload();
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Service tokens</h1>
      </div>
      <p className="muted">
        Workers authenticate with a token that has the worker scope; pass it to <code>crab-risk-scan worker</code>. Tokens bound to a project only act on that project.
      </p>
      {created ? <TokenSecret token={created} onDismiss={() => setCreated(null)} /> : null}
      <form className="card form-grid" onSubmit={submit} aria-labelledby="new-token">
        <h2 id="new-token">Create token</h2>
        <ErrorMessage error={action.error} />
        <label className="field">
          <span>Name</span>
          <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <fieldset className="field checks">
          <legend>Scopes</legend>
          {SCOPES.map(({ scope, label }) => (
            <label key={scope}>
              <input
                type="checkbox"
                checked={scopes.includes(scope)}
                onChange={(e) => setScopes((current) => (e.target.checked ? [...current, scope] : current.filter((s) => s !== scope)))}
              />{" "}
              {label}
            </label>
          ))}
        </fieldset>
        <label className="field">
          <span>Project (optional)</span>
          <select value={project} onChange={(e) => setProject(e.target.value)}>
            <option value="">All projects</option>
            {(projects.data ?? []).map((item) => (
              <option key={item.key} value={item.key}>
                {item.name} ({item.key})
              </option>
            ))}
          </select>
        </label>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={action.busy || scopes.length === 0}>
            Create token
          </button>
        </div>
      </form>
      <ErrorMessage error={error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        data.items.length === 0 ? (
          <Empty>No tokens.</Empty>
        ) : (
          <>
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Prefix</th>
                  <th scope="col">Scopes</th>
                  <th scope="col">Project</th>
                  <th scope="col">Created by</th>
                  <th scope="col">Created</th>
                  <th scope="col">Last used</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((token) => (
                  <tr key={token.id}>
                    <td>{token.name}</td>
                    <td className="mono">{token.prefix ?? "—"}</td>
                    <td>{token.scopes.join(", ")}</td>
                    <td>{token.project ?? "all"}</td>
                    <td>{token.created_by ?? "—"}</td>
                    <td>{formatDate(token.created_at)}</td>
                    <td>{formatDate(token.last_used_at)}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={action.busy}
                        onClick={async () => {
                          if (!confirmAction(`Revoke token ${token.name}?`)) return;
                          const done = await action.run(async () => {
                            await api.deleteToken(token.id);
                            return true;
                          });
                          if (done) reload();
                        }}
                      >
                        Revoke
                      </button>
                    </td>
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
