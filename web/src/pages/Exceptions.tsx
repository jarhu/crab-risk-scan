import { useState } from "react";
import type { ProjectException } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useProject } from "../components/Layout";
import { TriageForm } from "../components/TriageForm";
import { Can, DownloadButton, Drawer, Empty, ErrorMessage, Loading, Notice, Pagination, StatusBadge, confirmAction, useAction } from "../components/ui";
import { formatDate, shortId } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const PAGE_SIZE = 50;

export default function Exceptions() {
  const { project, canMaintain } = useProject();
  const { api } = useAuth();
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useAsync(() => api.exceptions(project.key, { page, page_size: PAGE_SIZE }), [project.key, page]);
  const [editing, setEditing] = useState<ProjectException | null>(null);
  const [notice, setNotice] = useState("");
  const removal = useAction();
  const today = new Date().toISOString().slice(0, 10);

  return (
    <div>
      <div className="row">
        <h2>Exceptions</h2>
        <DownloadButton label="Export exceptions file" fetcher={() => api.exportExceptions(project.key)} />
      </div>
      <p className="muted">
        The export is an exceptions v2 file for <code>crab-risk-scan scan --exceptions</code> in CI. Create exceptions from a finding's triage form.
      </p>
      {notice ? <Notice>{notice}</Notice> : null}
      <ErrorMessage error={error ?? removal.error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        data.items.length === 0 ? (
          <Empty>No exceptions.</Empty>
        ) : (
          <>
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Fingerprint</th>
                  <th scope="col">Status</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Reviewer</th>
                  <th scope="col">Expires</th>
                  <th scope="col">Ticket</th>
                  <th scope="col">Updated</th>
                  {canMaintain ? <th scope="col">Actions</th> : null}
                </tr>
              </thead>
              <tbody>
                {data.items.map((item) => (
                  <tr key={item.fingerprint}>
                    <td className="mono" title={item.fingerprint}>
                      {shortId(item.fingerprint, 16)}
                    </td>
                    <td>
                      <StatusBadge status={item.status} />
                      {item.justification ? <div className="small muted">{item.justification.replace(/_/g, " ")}</div> : null}
                    </td>
                    <td>{item.reason}</td>
                    <td>{item.reviewer}</td>
                    <td>{item.expires ? <span className={item.expires <= today ? "expired" : ""}>{item.expires}{item.expires <= today ? " (expired)" : ""}</span> : "—"}</td>
                    <td>{item.ticket ?? "—"}</td>
                    <td>{formatDate(item.updated_at)}</td>
                    <Can allowed={canMaintain}>
                      <td className="row-actions">
                        <button type="button" className="btn" onClick={() => setEditing(item)}>
                          Edit
                        </button>
                        <button
                          type="button"
                          className="btn btn-danger"
                          disabled={removal.busy}
                          onClick={async () => {
                            if (!confirmAction("Delete this exception?")) return;
                            const done = await removal.run(async () => {
                              await api.deleteException(project.key, item.fingerprint);
                              return true;
                            });
                            if (done) {
                              setNotice("Exception deleted.");
                              reload();
                            }
                          }}
                        >
                          Delete
                        </button>
                      </td>
                    </Can>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />
          </>
        )
      ) : null}
      {editing ? (
        <Drawer title="Edit exception" onClose={() => setEditing(null)}>
          <p className="mono small">{editing.fingerprint}</p>
          <TriageForm
            initial={editing}
            onCancel={() => setEditing(null)}
            onSubmit={async (payload) => {
              await api.putException(project.key, editing.fingerprint, payload);
              setEditing(null);
              setNotice("Exception saved.");
              reload();
            }}
          />
        </Drawer>
      ) : null}
    </div>
  );
}
