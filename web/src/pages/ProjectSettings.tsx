import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import type { CreatedToken, ProjectRole, TokenScope } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useProject } from "../components/Layout";
import { TokenSecret } from "../components/TokenSecret";
import { Can, Empty, ErrorMessage, Loading, Notice, confirmAction, useAction } from "../components/ui";
import { formatDate } from "../lib/format";
import { useAsync } from "../lib/useAsync";

export function Details() {
  const { project, canMaintain, reloadProject } = useProject();
  const { api, isAdmin } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState(project.name);
  const [repository, setRepository] = useState(project.repository_url ?? "");
  const [branch, setBranch] = useState(project.default_branch ?? "");
  const [scanPath, setScanPath] = useState(project.scan_path ?? "");
  const [notice, setNotice] = useState("");
  const save = useAction();
  const remove = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const saved = await save.run(() =>
      api.updateProject(project.key, {
        name: name.trim(),
        repository_url: repository.trim() || null,
        default_branch: branch.trim() || null,
        // Only admins may change the scan path; the server answers 403 to anyone else sending it.
        ...(isAdmin ? { scan_path: scanPath.trim() || null } : {}),
      }),
    );
    if (saved) {
      setNotice("Project saved.");
      reloadProject();
    }
  }

  return (
    <section className="card" aria-labelledby="details-title">
      <h3 id="details-title">Details</h3>
      {notice ? <Notice>{notice}</Notice> : null}
      <ErrorMessage error={save.error ?? remove.error} />
      <form className="form-grid" onSubmit={submit}>
        <label className="field">
          <span>Key</span>
          <input value={project.key} readOnly disabled />
        </label>
        <label className="field">
          <span>Name</span>
          <input required maxLength={200} value={name} disabled={!canMaintain} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          <span>Repository URL</span>
          <input type="url" placeholder="https://" value={repository} disabled={!canMaintain} onChange={(e) => setRepository(e.target.value)} />
        </label>
        <label className="field">
          <span>Default branch</span>
          <input value={branch} disabled={!canMaintain} onChange={(e) => setBranch(e.target.value)} />
        </label>
        <label className="field">
          <span>Scan path</span>
          <input
            maxLength={4096}
            placeholder={isAdmin ? "Absolute path inside a server scan root" : "Not set"}
            value={scanPath}
            disabled={!isAdmin}
            onChange={(e) => setScanPath(e.target.value)}
          />
          <small className="muted">Path jobs and schedules created by non-admins must stay inside this directory. Only administrators can change it.</small>
        </label>
        <Can allowed={canMaintain}>
          <div className="form-actions">
            <button type="submit" className="btn btn-primary" disabled={save.busy}>
              Save details
            </button>
          </div>
        </Can>
      </form>
      <Can allowed={isAdmin}>
        <div className="danger-zone">
          <h4>Delete project</h4>
          <p className="muted">Deletes the project with its scans, exceptions, jobs, schedules and tokens.</p>
          <button
            type="button"
            className="btn btn-danger"
            disabled={remove.busy}
            onClick={async () => {
              if (!confirmAction(`Delete project ${project.key} and all of its data?`)) return;
              const done = await remove.run(async () => {
                await api.deleteProject(project.key);
                return true;
              });
              if (done) navigate("/projects", { replace: true });
            }}
          >
            Delete project
          </button>
        </div>
      </Can>
    </section>
  );
}

function Members() {
  const { project, canMaintain } = useProject();
  const { api, isAdmin, user } = useAuth();
  const { data, error, loading, reload } = useAsync(() => api.members(project.key), [project.key]);
  const users = useAsync(() => (isAdmin ? api.allUsers() : Promise.resolve([])), [isAdmin]);
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState<ProjectRole>("viewer");
  const action = useAction();

  async function mutate(work: () => Promise<unknown>) {
    const done = await action.run(async () => {
      await work();
      return true;
    });
    if (done) reload();
    return done;
  }

  const memberIds = new Set((data?.items ?? []).map((m) => String(m.user_id)));
  const candidates = (users.data ?? []).filter((u) => !memberIds.has(String(u.id)) && u.role !== "admin");

  return (
    <section className="card" aria-labelledby="members-title">
      <h3 id="members-title">Members</h3>
      <p className="muted">Maintainers triage, run jobs, manage schedules, settings and project tokens. Viewers read. Administrators have full access everywhere.</p>
      <ErrorMessage error={error ?? action.error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        data.items.length === 0 ? (
          <Empty>No members.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">User</th>
                <th scope="col">Role</th>
                {canMaintain ? <th scope="col">Actions</th> : null}
              </tr>
            </thead>
            <tbody>
              {data.items.map((member) => (
                <tr key={member.user_id}>
                  <td>
                    {member.username}
                    {String(member.user_id) === String(user?.id) ? <span className="muted"> (you)</span> : null}
                  </td>
                  <td>
                    {canMaintain ? (
                      <select
                        aria-label={`Role for ${member.username}`}
                        value={member.role}
                        disabled={action.busy}
                        onChange={(e) => mutate(() => api.setMember(project.key, member.user_id, e.target.value === "maintainer" ? "maintainer" : "viewer"))}
                      >
                        <option value="viewer">viewer</option>
                        <option value="maintainer">maintainer</option>
                      </select>
                    ) : (
                      member.role
                    )}
                  </td>
                  <Can allowed={canMaintain}>
                    <td>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={action.busy}
                        onClick={() => {
                          if (confirmAction(`Remove ${member.username} from ${project.key}?`)) void mutate(() => api.removeMember(project.key, member.user_id));
                        }}
                      >
                        Remove
                      </button>
                    </td>
                  </Can>
                </tr>
              ))}
            </tbody>
          </table>
        )
      ) : null}
      <Can allowed={canMaintain}>
        <form
          className="inline-form"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!userId.trim()) return;
            if (await mutate(() => api.setMember(project.key, userId.trim(), role))) setUserId("");
          }}
        >
          {isAdmin ? (
            <label className="inline-field">
              <span>User</span>
              <select required value={userId} onChange={(e) => setUserId(e.target.value)}>
                <option value="">Select a user</option>
                {candidates.map((candidate) => (
                  <option key={candidate.id} value={String(candidate.id)}>
                    {candidate.username}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <label className="inline-field">
              <span>User ID</span>
              <input required inputMode="numeric" maxLength={40} value={userId} onChange={(e) => setUserId(e.target.value)} />
            </label>
          )}
          <label className="inline-field">
            <span>Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value === "maintainer" ? "maintainer" : "viewer")}>
              <option value="viewer">viewer</option>
              <option value="maintainer">maintainer</option>
            </select>
          </label>
          <button type="submit" className="btn btn-primary" disabled={action.busy}>
            Add member
          </button>
        </form>
      </Can>
    </section>
  );
}

const PROJECT_SCOPES: { scope: TokenScope; label: string }[] = [
  { scope: "scan:upload", label: "Upload scans (CI runner)" },
  { scope: "read", label: "Read" },
];

function ProjectTokens() {
  const { project, canMaintain } = useProject();
  const { api } = useAuth();
  const { data, error, loading, reload } = useAsync(
    () => (canMaintain ? api.tokens({ project: project.key, page_size: 500 }) : Promise.resolve({ items: [], total: 0 })),
    [project.key, canMaintain],
  );
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<TokenScope[]>(["scan:upload"]);
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const action = useAction();
  if (!canMaintain) return null;
  const tokens = (data?.items ?? []).filter((token) => token.project === project.key);

  return (
    <section className="card" aria-labelledby="ptokens-title">
      <h3 id="ptokens-title">Project tokens</h3>
      <p className="muted">
        Use a scan:upload token as <code>CRAB_TOKEN</code> for <code>crab-risk-scan ci --server URL --project {project.key}</code>.
      </p>
      {created ? <TokenSecret token={created} onDismiss={() => setCreated(null)} /> : null}
      <ErrorMessage error={error ?? action.error} />
      <form
        className="inline-form"
        onSubmit={async (event) => {
          event.preventDefault();
          const token = await action.run(() => api.createToken({ name: name.trim(), scopes, project: project.key }));
          if (token) {
            setCreated(token);
            setName("");
            reload();
          }
        }}
      >
        <label className="inline-field">
          <span>Name</span>
          <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <fieldset className="inline-field checks">
          <legend>Scopes</legend>
          {PROJECT_SCOPES.map(({ scope, label }) => (
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
        <button type="submit" className="btn btn-primary" disabled={action.busy || scopes.length === 0}>
          Create token
        </button>
      </form>
      {loading && !data ? <Loading /> : null}
      {data ? (
        tokens.length === 0 ? (
          <Empty>No project tokens.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Prefix</th>
                <th scope="col">Scopes</th>
                <th scope="col">Created by</th>
                <th scope="col">Created</th>
                <th scope="col">Last used</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <tr key={token.id}>
                  <td>{token.name}</td>
                  <td className="mono">{token.prefix ?? "—"}</td>
                  <td>{token.scopes.join(", ")}</td>
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
        )
      ) : null}
    </section>
  );
}

export default function ProjectSettings() {
  return (
    <div>
      <h2>Settings</h2>
      <Details />
      <Members />
      <ProjectTokens />
    </div>
  );
}
