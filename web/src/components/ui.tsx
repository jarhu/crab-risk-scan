import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { ApiError, saveDownload, type Download } from "../api/client";
import { safeHref } from "../lib/safe";

export function errorText(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return `You do not have permission for this action. ${error.detail}`.trim();
    if (error.status === 404) return `Not found. ${error.detail}`.trim();
    return error.detail;
  }
  if (error instanceof Error) return error.message;
  return "Something went wrong";
}

export function ErrorMessage({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="alert alert-error" role="alert">
      {errorText(error)}
    </div>
  );
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <div className="alert alert-info" role="status">
      {children}
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <p className="muted" role="status" aria-live="polite">
      {label}…
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

/** Show `children` only when `allowed`; the server still enforces permissions. */
export function Can({ allowed, children }: { allowed: boolean; children: ReactNode }) {
  return allowed ? <>{children}</> : null;
}

/** An external link that renders only http(s) URLs; anything else is shown as plain text. */
export function ExternalLink({ href, children }: { href: string | null | undefined; children?: ReactNode }) {
  const safe = safeHref(href);
  const label = children ?? href ?? "";
  if (!safe) return <span>{label}</span>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer nofollow">
      {label}
    </a>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge badge-${status.replace(/[^a-z_]/g, "")}`}>{status.replace(/_/g, " ")}</span>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`sev sev-${severity.replace(/[^a-z]/g, "")}`}>{severity}</span>;
}

export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize && page === 1) return null;
  return (
    <nav className="pagination" aria-label="Pagination">
      <button type="button" className="btn" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        Previous
      </button>
      <span>
        Page {page} of {pages} ({total} items)
      </span>
      <button type="button" className="btn" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        Next
      </button>
    </nav>
  );
}

export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        ref={panel}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="drawer-header">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="btn" onClick={onClose} aria-label="Close">
            Close
          </button>
        </header>
        <div className="drawer-body">{children}</div>
      </div>
    </div>
  );
}

/** A button that fetches a file through the API and saves it. */
export function DownloadButton({ label, fetcher, className = "btn" }: { label: string; fetcher: () => Promise<Download>; className?: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <span className="download">
      <button
        type="button"
        className={className}
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            saveDownload(await fetcher());
          } catch (reason) {
            setError(reason);
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Preparing…" : label}
      </button>
      {error ? (
        <span className="field-error" role="alert">
          {errorText(error)}
        </span>
      ) : null}
    </span>
  );
}

/** Run an action with busy and error state, for forms and row buttons. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function run<T>(action: () => Promise<T>): Promise<T | undefined> {
    setBusy(true);
    setError(null);
    try {
      return await action();
    } catch (reason) {
      setError(reason);
      return undefined;
    } finally {
      setBusy(false);
    }
  }
  return { busy, error, run, setError };
}

export function confirmAction(message: string): boolean {
  return typeof window.confirm === "function" ? window.confirm(message) : true;
}
