import { Link } from "react-router";
import { SEVERITIES, type ScanSummary } from "../api/types";
import { formatDate, shortId } from "../lib/format";
import { Empty, StatusBadge } from "./ui";

export function SeverityInline({ counts }: { counts: ScanSummary["counts"] | undefined }) {
  return (
    <span className="sev-inline">
      {SEVERITIES.filter((level) => (counts?.[level] ?? 0) > 0).map((level) => (
        <span key={level} className={`sev sev-${level}`} title={level}>
          {level[0]?.toUpperCase()}
          {counts?.[level]}
        </span>
      ))}
      {SEVERITIES.every((level) => !counts?.[level]) ? <span className="muted">none</span> : null}
    </span>
  );
}

export interface ScanTableProps {
  scans: ScanSummary[];
  showProject?: boolean;
  selected?: (string | number)[];
  onToggle?: (id: string | number) => void;
}

export function ScanTable({ scans, showProject = false, selected, onToggle }: ScanTableProps) {
  if (scans.length === 0) return <Empty>No scans yet.</Empty>;
  return (
    <table className="table">
      <thead>
        <tr>
          {onToggle ? <th scope="col">Compare</th> : null}
          <th scope="col">Scan</th>
          {showProject ? <th scope="col">Project</th> : null}
          <th scope="col">Revision</th>
          <th scope="col">Branch</th>
          <th scope="col">Policy</th>
          <th scope="col">Open findings</th>
          <th scope="col" className="num">
            New
          </th>
          <th scope="col" className="num">
            Suppressed
          </th>
          <th scope="col">Source</th>
          <th scope="col">Created</th>
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.id}>
            {onToggle ? (
              <td>
                <input
                  type="checkbox"
                  aria-label={`Select scan ${scan.id}`}
                  checked={selected?.includes(scan.id) ?? false}
                  onChange={() => onToggle(scan.id)}
                />
              </td>
            ) : null}
            <td>
              <Link to={`/scans/${encodeURIComponent(String(scan.id))}`}>#{scan.id}</Link>
            </td>
            {showProject ? (
              <td>
                <Link to={`/projects/${encodeURIComponent(scan.project)}`}>{scan.project}</Link>
              </td>
            ) : null}
            <td className="mono">{shortId(scan.revision)}</td>
            <td>{scan.branch ?? "—"}</td>
            <td>
              <StatusBadge status={scan.status} />
            </td>
            <td>
              <SeverityInline counts={scan.counts} />
            </td>
            <td className="num">{scan.new ?? "—"}</td>
            <td className="num">{scan.suppressed}</td>
            <td>{scan.source ?? "—"}</td>
            <td>{formatDate(scan.created_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
