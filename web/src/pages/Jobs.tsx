import { useState, type FormEvent } from "react";
import { useAuth } from "../auth/AuthContext";
import { EMPTY_JOB, JobFields, jobInputFrom, type JobValues } from "../components/JobFields";
import { isActiveJob, JobsTable } from "../components/JobsTable";
import { useProject } from "../components/Layout";
import { Can, ErrorMessage, Loading, Notice, Pagination, confirmAction, useAction } from "../components/ui";
import { useAsync, useInterval } from "../lib/useAsync";

const PAGE_SIZE = 50;
const POLL_MS = 3000;

function RunScan({ onQueued }: { onQueued: (id: string | number) => void }) {
  const { project } = useProject();
  const { api } = useAuth();
  const [values, setValues] = useState<JobValues>(EMPTY_JOB);
  const { busy, error, run } = useAction();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const job = await run(() => api.createJob(project.key, jobInputFrom(values)));
    if (job) onQueued(job.id);
  }

  return (
    <form className="card form-grid" onSubmit={submit} aria-labelledby="run-title">
      <h3 id="run-title">Run a scan</h3>
      <ErrorMessage error={error} />
      <JobFields values={values} onChange={setValues} />
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Queue scan
        </button>
      </div>
    </form>
  );
}

export default function Jobs() {
  const { project, canMaintain } = useProject();
  const { api } = useAuth();
  const [page, setPage] = useState(1);
  const [notice, setNotice] = useState("");
  const { data, error, loading, reload } = useAsync(() => api.projectJobs(project.key, { page, page_size: PAGE_SIZE }), [project.key, page]);
  const cancel = useAction();
  const polling = (data?.items ?? []).some(isActiveJob);
  useInterval(reload, POLL_MS, polling);

  return (
    <div>
      <h2>Jobs</h2>
      <Can allowed={canMaintain}>
        <RunScan
          onQueued={(id) => {
            setNotice(`Job #${id} queued. Status refreshes automatically.`);
            setPage(1);
            reload();
          }}
        />
      </Can>
      {notice ? <Notice>{notice}</Notice> : null}
      <ErrorMessage error={error ?? cancel.error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        <>
          <p className="muted" aria-live="polite">
            {polling ? "Refreshing every few seconds while jobs are queued or running." : "No active jobs."}
          </p>
          <JobsTable
            jobs={data.items}
            canCancel={() => canMaintain}
            busy={cancel.busy}
            onCancel={async (job) => {
              if (!confirmAction(`Cancel job #${job.id}?`)) return;
              if (await cancel.run(() => api.cancelJob(job.id))) reload();
            }}
          />
          <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />
        </>
      ) : null}
    </div>
  );
}
