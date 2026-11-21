import { useState, type FormEvent } from "react";
import { EXCEPTION_STATUSES, JUSTIFICATIONS, type ExceptionInput, type ExceptionStatus, type FindingException, type Justification } from "../api/types";
import { ErrorMessage } from "./ui";

export interface TriageValues {
  status: ExceptionStatus;
  justification: Justification | "";
  reason: string;
  expires: string;
  ticket: string;
}

const STATUS_LABELS: Record<ExceptionStatus, string> = {
  accepted: "Accepted risk",
  false_positive: "False positive",
  not_affected: "Not affected",
};

export function initialTriage(exception?: Partial<FindingException> | null): TriageValues {
  return {
    status: exception?.status ?? "accepted",
    justification: exception?.justification ?? "",
    reason: exception?.reason ?? "",
    expires: exception?.expires ?? "",
    ticket: exception?.ticket ?? "",
  };
}

/** Build the `PUT /exceptions/{fingerprint}` body; optional fields are omitted when empty. */
export function buildExceptionPayload(values: TriageValues): ExceptionInput {
  const payload: ExceptionInput = { status: values.status, reason: values.reason.trim() };
  if (values.status === "not_affected" && values.justification) payload.justification = values.justification;
  if (values.expires) payload.expires = values.expires;
  if (values.ticket.trim()) payload.ticket = values.ticket.trim();
  return payload;
}

export function validateTriage(values: TriageValues): string | null {
  if (!values.reason.trim()) return "A reason is required.";
  if (values.status === "not_affected" && !values.justification) return "Not affected requires a justification.";
  if (values.expires && !/^\d{4}-\d{2}-\d{2}$/.test(values.expires)) return "Expiry must be a date (YYYY-MM-DD).";
  return null;
}

export interface TriageFormProps {
  initial?: Partial<FindingException> | null;
  submitLabel?: string;
  onSubmit: (payload: ExceptionInput) => Promise<unknown>;
  onCancel?: () => void;
}

export function TriageForm({ initial, submitLabel = "Save exception", onSubmit, onCancel }: TriageFormProps) {
  const [values, setValues] = useState<TriageValues>(() => initialTriage(initial));
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  function update<K extends keyof TriageValues>(key: K, value: TriageValues[K]) {
    setValues((current) => ({ ...current, [key]: value }));
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const problem = validateTriage(values);
    if (problem) {
      setError(new Error(problem));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onSubmit(buildExceptionPayload(values));
    } catch (reason) {
      setError(reason);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form-grid triage" onSubmit={submit} aria-label="Triage">
      <ErrorMessage error={error} />
      <label className="field">
        <span>Status</span>
        <select value={values.status} onChange={(e) => update("status", EXCEPTION_STATUSES.find((s) => s === e.target.value) ?? "accepted")}>
          {EXCEPTION_STATUSES.map((status) => (
            <option key={status} value={status}>
              {STATUS_LABELS[status]}
            </option>
          ))}
        </select>
      </label>
      {values.status === "not_affected" ? (
        <label className="field">
          <span>Justification</span>
          <select required value={values.justification} onChange={(e) => update("justification", JUSTIFICATIONS.find((j) => j === e.target.value) ?? "")}>
            <option value="">Select a justification</option>
            {JUSTIFICATIONS.map((item) => (
              <option key={item} value={item}>
                {item.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </label>
      ) : null}
      <label className="field wide">
        <span>Reason</span>
        <textarea required maxLength={500} rows={3} value={values.reason} onChange={(e) => update("reason", e.target.value)} />
      </label>
      <label className="field">
        <span>Expires</span>
        <input type="date" value={values.expires} onChange={(e) => update("expires", e.target.value)} />
      </label>
      <label className="field">
        <span>Ticket</span>
        <input maxLength={100} value={values.ticket} onChange={(e) => update("ticket", e.target.value)} />
      </label>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Saving…" : submitLabel}
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
