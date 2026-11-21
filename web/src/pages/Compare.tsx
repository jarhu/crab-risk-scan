import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import type { Finding, ScanSummary } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { FindingDetail } from "../components/FindingDetail";
import { SeverityInline } from "../components/scans";
import { Drawer, ErrorMessage, Loading, StatusBadge } from "../components/ui";
import { formatDate, shortId } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import { FindingsTable } from "./Findings";

function ScanCard({ label, scan }: { label: string; scan: ScanSummary }) {
  return (
    <div className="card">
      <h2>{label}</h2>
      <p>
        <Link to={`/scans/${encodeURIComponent(String(scan.id))}`}>Scan #{scan.id}</Link> <StatusBadge status={scan.status} />
      </p>
      <p className="muted">
        <span className="mono">{shortId(scan.revision)}</span> {scan.branch ?? ""} · {formatDate(scan.created_at)}
      </p>
      <SeverityInline counts={scan.counts} />
    </div>
  );
}

export default function Compare() {
  const { id = "" } = useParams();
  const [params] = useSearchParams();
  const base = params.get("base") ?? "";
  const { api } = useAuth();
  const { data, error, loading } = useAsync(() => (base ? api.compare(id, base) : Promise.reject(new Error("Choose a base scan to compare against."))), [id, base]);
  const [tab, setTab] = useState<"new" | "fixed">("new");
  const [selected, setSelected] = useState<Finding | null>(null);

  return (
    <div>
      <div className="page-header">
        <p className="breadcrumb">
          {data ? (
            <>
              <Link to={`/projects/${encodeURIComponent(data.head.project)}/scans`}>{data.head.project}</Link> /{" "}
            </>
          ) : null}
          Compare
        </p>
        <h1>Compare scans</h1>
      </div>
      <ErrorMessage error={error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        <>
          <div className="grid two">
            <ScanCard label="Base" scan={data.base} />
            <ScanCard label="Head" scan={data.head} />
          </div>
          <ul className="compare-stats">
            <li>
              <strong>{data.new.length}</strong> new
            </li>
            <li>
              <strong>{data.fixed.length}</strong> fixed
            </li>
            <li>
              <strong>{data.unchanged}</strong> unchanged
            </li>
          </ul>
          <div className="tabs" role="tablist" aria-label="Comparison">
            <button type="button" role="tab" aria-selected={tab === "new"} className={tab === "new" ? "active" : ""} onClick={() => setTab("new")}>
              New ({data.new.length})
            </button>
            <button type="button" role="tab" aria-selected={tab === "fixed"} className={tab === "fixed" ? "active" : ""} onClick={() => setTab("fixed")}>
              Fixed ({data.fixed.length})
            </button>
          </div>
          <div role="tabpanel">
            <FindingsTable findings={tab === "new" ? data.new : data.fixed} onSelect={setSelected} />
          </div>
          <p className="muted">{data.unchanged} findings are present in both scans.</p>
        </>
      ) : null}
      {selected ? (
        <Drawer title={selected.rule} onClose={() => setSelected(null)}>
          <FindingDetail finding={selected} canTriage={false} />
        </Drawer>
      ) : null}
    </div>
  );
}
