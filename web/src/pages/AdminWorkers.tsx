import { useState } from "react";
import type { JobStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { JobsTable } from "../components/JobsTable";
import { Empty, ErrorMessage, Loading, Pagination, StatusBadge, confirmAction, useAction } from "../components/ui";
import { formatDate } from "../lib/format";
import { useAsync, useInterval } from "../lib/useAsync";

const PAGE_SIZE = 50;
const POLL_MS = 5000;
const STATUSES: (JobStatus | "")[] = ["", "queued", "running", "succeeded", "failed", "cancelled"];

export default function AdminWorkers() {
  const { api } = useAuth();
  const [status, setStatus] = useState<JobStatus | "">("");
  const [project, setProject] = useState("");
  const [page, setPage] = useState(1);
  const [auto, setAuto] = useState(true);
  const workers = useAsync(() => api.workers(), []);
  const jobs = useAsync(() => api.jobs({ status, project: project.trim() }, { page, page_size: PAGE_SIZE }), [status, project, page]);
  const cancel = useAction();
  useInterval(
    () => {
      workers.reload();
      jobs.reload();
    },
    POLL_MS,
    auto,
  );

  return (
    <div>
      <div className="page-header row">
        <h1>Workers and job queue</h1>
        <label className="field checkbox">
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Refresh automatically
        </label>
      </div>
      <section className="card" aria-labelledby="workers-title">
        <h2 id="workers-title">Workers</h2>
        <ErrorMessage error={workers.error} />
        {workers.loading && !workers.data ? <Loading /> : null}
        {workers.data ? (
          workers.data.length === 0 ? (
            <Empty>
              No workers have connected. Start one with <code>crab-risk-scan worker</code>.
            </Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">State</th>
                  <th scope="col">Git sources</th>
                  <th scope="col">Current job</th>
                  <th scope="col">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {workers.data.map((worker) => (
                  <tr key={worker.name}>
                    <td>{worker.name}</td>
                    <td>
                      <StatusBadge status={worker.active ? "active" : "inactive"} />
                    </td>
                    <td>{worker.capabilities?.git ? "allowed" : "no"}</td>
                    <td>{worker.current_job !== null && worker.current_job !== undefined ? `#${worker.current_job}` : "—"}</td>
                    <td>{formatDate(worker.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : null}
      </section>
      <section className="card" aria-labelledby="queue-title">
        <h2 id="queue-title">Job queue</h2>
        <div className="filters">
          <label className="field">
            <span>Status</span>
            <select
              value={status}
              onChange={(e) => {
                setStatus(STATUSES.find((s) => s === e.target.value) ?? "");
                setPage(1);
              }}
            >
              {STATUSES.map((item) => (
                <option key={item} value={item}>
                  {item || "Any"}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Project key</span>
            <input
              maxLength={64}
              value={project}
              onChange={(e) => {
                setProject(e.target.value);
                setPage(1);
              }}
            />
          </label>
        </div>
        <ErrorMessage error={jobs.error ?? cancel.error} />
        {jobs.loading && !jobs.data ? <Loading /> : null}
        {jobs.data ? (
          <>
            <JobsTable
              jobs={jobs.data.items}
              showProject
              canCancel={() => true}
              busy={cancel.busy}
              onCancel={async (job) => {
                if (!confirmAction(`Cancel job #${job.id}?`)) return;
                if (await cancel.run(() => api.cancelJob(job.id))) jobs.reload();
              }}
            />
            <Pagination page={page} pageSize={PAGE_SIZE} total={jobs.data.total} onPage={setPage} />
          </>
        ) : null}
      </section>
    </div>
  );
}
