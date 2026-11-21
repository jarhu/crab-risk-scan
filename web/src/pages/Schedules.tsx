import { useState, type FormEvent } from "react";
import type { Schedule, ScheduleInput } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { EMPTY_JOB, JobFields, jobInputFrom, jobValuesFrom, type JobValues } from "../components/JobFields";
import { useProject } from "../components/Layout";
import { Can, Drawer, Empty, ErrorMessage, Loading, Notice, StatusBadge, confirmAction, useAction } from "../components/ui";
import { formatDate, sourceLabel } from "../lib/format";
import { useAsync } from "../lib/useAsync";

interface ScheduleValues {
  cron: string;
  enabled: boolean;
  job: JobValues;
}

const CRON_PATTERN = "^\\S+\\s+\\S+\\s+\\S+\\s+\\S+\\s+\\S+$";

function scheduleInput(values: ScheduleValues): ScheduleInput {
  return { cron: values.cron.trim().replace(/\s+/g, " "), enabled: values.enabled, ...jobInputFrom(values.job) };
}

function ScheduleForm({ initial, submitLabel, onSubmit, onCancel }: { initial: ScheduleValues; submitLabel: string; onSubmit: (input: ScheduleInput) => Promise<unknown>; onCancel?: () => void }) {
  const [values, setValues] = useState<ScheduleValues>(initial);
  const { busy, error, run } = useAction();
  async function submit(event: FormEvent) {
    event.preventDefault();
    await run(() => onSubmit(scheduleInput(values)));
  }
  return (
    <form className="form-grid" onSubmit={submit}>
      <ErrorMessage error={error} />
      <label className="field">
        <span>Cron (UTC: minute hour day-of-month month day-of-week)</span>
        <input
          required
          className="mono"
          pattern={CRON_PATTERN}
          title="Five space-separated fields, for example 0 3 * * 1"
          placeholder="0 3 * * *"
          maxLength={120}
          value={values.cron}
          onChange={(e) => setValues({ ...values, cron: e.target.value })}
        />
      </label>
      <label className="field checkbox">
        <input type="checkbox" checked={values.enabled} onChange={(e) => setValues({ ...values, enabled: e.target.checked })} /> Enabled
      </label>
      <JobFields values={values.job} onChange={(job) => setValues({ ...values, job })} />
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {submitLabel}
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

export default function Schedules() {
  const { project, canMaintain } = useProject();
  const { api } = useAuth();
  const { data, error, loading, reload } = useAsync(() => api.schedules(project.key), [project.key]);
  const [editing, setEditing] = useState<Schedule | null>(null);
  const [creating, setCreating] = useState(0);
  const [notice, setNotice] = useState("");
  const action = useAction();

  async function mutate(message: string, work: () => Promise<unknown>) {
    const done = await action.run(async () => {
      await work();
      return true;
    });
    if (done) {
      setNotice(message);
      reload();
    }
  }

  return (
    <div>
      <h2>Schedules</h2>
      <p className="muted">Schedules queue a scan job at each cron time. Times are UTC.</p>
      <Can allowed={canMaintain}>
        <section className="card" aria-labelledby="new-schedule">
          <h3 id="new-schedule">New schedule</h3>
          <ScheduleForm
            key={creating}
            initial={{ cron: "", enabled: true, job: EMPTY_JOB }}
            submitLabel="Create schedule"
            onSubmit={async (input) => {
              await api.createSchedule(project.key, input);
              setCreating((n) => n + 1);
              setNotice("Schedule created.");
              reload();
            }}
          />
        </section>
      </Can>
      {notice ? <Notice>{notice}</Notice> : null}
      <ErrorMessage error={error ?? action.error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        data.items.length === 0 ? (
          <Empty>No schedules.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Cron</th>
                <th scope="col">Source</th>
                <th scope="col">Options</th>
                <th scope="col">State</th>
                <th scope="col">Next run</th>
                <th scope="col">Last run</th>
                {canMaintain ? <th scope="col">Actions</th> : null}
              </tr>
            </thead>
            <tbody>
              {data.items.map((schedule) => (
                <tr key={schedule.id}>
                  <td className="mono">{schedule.cron}</td>
                  <td className="mono small">{sourceLabel(schedule.source)}</td>
                  <td className="small">
                    engines {schedule.options?.engines ?? "auto"}
                    {schedule.options?.sbom ? ", SBOM" : ""}
                    {schedule.options?.fail_on ? `, fail on ${schedule.options.fail_on}` : ""}
                  </td>
                  <td>
                    <StatusBadge status={schedule.enabled ? "enabled" : "disabled"} />
                  </td>
                  <td>{schedule.enabled ? formatDate(schedule.next_run_at) : "—"}</td>
                  <td>{formatDate(schedule.last_run_at)}</td>
                  <Can allowed={canMaintain}>
                    <td className="row-actions">
                      <button type="button" className="btn" onClick={() => setEditing(schedule)}>
                        Edit
                      </button>
                      <button
                        type="button"
                        className="btn"
                        disabled={action.busy}
                        onClick={() => mutate(schedule.enabled ? "Schedule disabled." : "Schedule enabled.", () => api.updateSchedule(schedule.id, { enabled: !schedule.enabled }))}
                      >
                        {schedule.enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={action.busy}
                        onClick={() => {
                          if (confirmAction("Delete this schedule?")) void mutate("Schedule deleted.", () => api.deleteSchedule(schedule.id));
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
        )
      ) : null}
      {editing ? (
        <Drawer title="Edit schedule" onClose={() => setEditing(null)}>
          <ScheduleForm
            initial={{ cron: editing.cron, enabled: editing.enabled, job: jobValuesFrom(editing.source, editing.options ?? {}) }}
            submitLabel="Save schedule"
            onCancel={() => setEditing(null)}
            onSubmit={async (input) => {
              await api.updateSchedule(editing.id, input);
              setEditing(null);
              setNotice("Schedule saved.");
              reload();
            }}
          />
        </Drawer>
      ) : null}
    </div>
  );
}
