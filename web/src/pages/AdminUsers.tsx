import { useState, type FormEvent } from "react";
import type { GlobalRole, User } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Drawer, Empty, ErrorMessage, Loading, Notice, Pagination, StatusBadge, confirmAction, useAction } from "../components/ui";
import { formatDate } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const PAGE_SIZE = 50;

function UserForm({ user, onSubmit, onCancel }: { user?: User; onSubmit: (body: { username: string; password?: string; role: GlobalRole; active: boolean }) => Promise<unknown>; onCancel?: () => void }) {
  const [username, setUsername] = useState(user?.username ?? "");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<GlobalRole>(user?.role ?? "member");
  const [active, setActive] = useState(user?.active ?? true);
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const body: { username: string; password?: string; role: GlobalRole; active: boolean } = { username: username.trim(), role, active };
    if (password) body.password = password;
    const done = await run(async () => {
      await onSubmit(body);
      return true;
    });
    if (done && !user) {
      setUsername("");
      setPassword("");
      setRole("member");
      setActive(true);
    }
  }

  return (
    <form className="form-grid" onSubmit={submit}>
      <ErrorMessage error={error} />
      <label className="field">
        <span>Username</span>
        <input required maxLength={100} autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
      </label>
      <label className="field">
        <span>{user ? "New password (leave empty to keep)" : "Password"}</span>
        <input type="password" required={!user} minLength={8} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <label className="field">
        <span>Role</span>
        <select value={role} onChange={(e) => setRole(e.target.value === "admin" ? "admin" : "member")}>
          <option value="member">member</option>
          <option value="admin">admin</option>
        </select>
      </label>
      <label className="field checkbox">
        <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} /> Active
      </label>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {user ? "Save user" : "Create user"}
        </button>
        {onCancel ? (
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        ) : null}
      </div>
    </form>
  );
}

export default function AdminUsers() {
  const { api, user: me } = useAuth();
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useAsync(() => api.users({ page, page_size: PAGE_SIZE }), [page]);
  const [editing, setEditing] = useState<User | null>(null);
  const [notice, setNotice] = useState("");
  const removal = useAction();

  return (
    <div>
      <div className="page-header">
        <h1>Users</h1>
      </div>
      <section className="card" aria-labelledby="new-user">
        <h2 id="new-user">Create user</h2>
        <UserForm
          onSubmit={async (body) => {
            await api.createUser({ ...body, password: body.password ?? "" });
            setNotice(`User ${body.username} created.`);
            reload();
          }}
        />
      </section>
      {notice ? <Notice>{notice}</Notice> : null}
      <ErrorMessage error={error ?? removal.error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        data.items.length === 0 ? (
          <Empty>No users.</Empty>
        ) : (
          <>
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Username</th>
                  <th scope="col">Role</th>
                  <th scope="col">State</th>
                  <th scope="col">Created</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((user) => (
                  <tr key={user.id}>
                    <td>{user.username}</td>
                    <td>{user.role}</td>
                    <td>
                      <StatusBadge status={user.active ? "active" : "inactive"} />
                    </td>
                    <td>{formatDate(user.created_at)}</td>
                    <td className="row-actions">
                      <button type="button" className="btn" onClick={() => setEditing(user)}>
                        Edit
                      </button>
                      {String(user.id) !== String(me?.id) ? (
                        <button
                          type="button"
                          className="btn btn-danger"
                          disabled={removal.busy}
                          onClick={async () => {
                            if (!confirmAction(`Delete user ${user.username}?`)) return;
                            const done = await removal.run(async () => {
                              await api.deleteUser(user.id);
                              return true;
                            });
                            if (done) {
                              setNotice(`User ${user.username} deleted.`);
                              reload();
                            }
                          }}
                        >
                          Delete
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />
          </>
        )
      ) : null}
      {editing ? (
        <Drawer title={`Edit ${editing.username}`} onClose={() => setEditing(null)}>
          <UserForm
            user={editing}
            onCancel={() => setEditing(null)}
            onSubmit={async (body) => {
              await api.updateUser(editing.id, body);
              setEditing(null);
              setNotice(`User ${body.username} saved.`);
              reload();
            }}
          />
        </Drawer>
      ) : null}
    </div>
  );
}
