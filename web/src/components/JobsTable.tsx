import { Link } from "react-router";
import type { Job } from "../api/types";
import { formatDate, sourceLabel } from "../lib/format";
import { Empty, StatusBadge } from "./ui";

export function isActiveJob(job: Job): boolean {
  return job.status === "queued" || job.status === "running";
}

export interface JobsTableProps {
  jobs: Job[];
  showProject?: boolean;
  canCancel: (job: Job) => boolean;
  onCancel: (job: Job) => void;
  busy?: boolean;
}

export function JobsTable({ jobs, showProject = false, canCancel, onCancel, busy = false }: JobsTableProps) {
  if (jobs.length === 0) return <Empty>No jobs.</Empty>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">Job</th>
          {showProject ? <th scope="col">Project</th> : null}
          <th scope="col">Status</th>
          <th scope="col">Source</th>
          <th scope="col">Worker</th>
          <th scope="col" className="num">
            Attempts
          </th>
          <th scope="col">Created</th>
          <th scope="col">Finished</th>
          <th scope="col">Result</th>
          <th scope="col">Actions</th>
        </tr>
      </thead>
      <tbody>
        {jobs.map((job) => (
          <tr key={job.id}>
            <td>
              #{job.id}
              {job.schedule_id ? <div className="small muted">schedule {job.schedule_id}</div> : null}
            </td>
            {showProject ? (
              <td>
                <Link to={`/projects/${encodeURIComponent(job.project)}/jobs`}>{job.project}</Link>
              </td>
            ) : null}
            <td>
              <StatusBadge status={job.status} />
            </td>
            <td className="mono small">{sourceLabel(job.source)}</td>
            <td>{job.worker ?? "—"}</td>
            <td className="num">{job.attempts}</td>
            <td>{formatDate(job.created_at)}</td>
            <td>{formatDate(job.finished_at)}</td>
            <td>
              {job.scan_id !== null && job.scan_id !== undefined ? (
                <Link to={`/scans/${encodeURIComponent(String(job.scan_id))}`}>Scan #{job.scan_id}</Link>
              ) : job.error ? (
                <span className="field-error">{job.error}</span>
              ) : (
                "—"
              )}
            </td>
            <td>
              {isActiveJob(job) && canCancel(job) ? (
                <button type="button" className="btn btn-danger" disabled={busy} onClick={() => onCancel(job)}>
                  Cancel
                </button>
              ) : null}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
