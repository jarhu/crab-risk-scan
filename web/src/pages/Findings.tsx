import { useEffect, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { CATEGORIES, EMPTY_FILTERS, SEVERITIES, type Finding, type FindingFilters } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { FindingDetail } from "../components/FindingDetail";
import { Drawer, Empty, ErrorMessage, Loading, Notice, Pagination, SeverityBadge, StatusBadge } from "../components/ui";
import { activeFilterCount, filtersFromParams, filtersToParams } from "../lib/filters";
import { findingLocation } from "../lib/format";
import { useAsync } from "../lib/useAsync";

const PAGE_SIZE = 50;

export interface FindingFiltersFormProps {
  filters: FindingFilters;
  producers: string[];
  onChange: (filters: FindingFilters) => void;
}

/** Filter controls; selects apply immediately, the text search applies on submit. */
export function FindingFiltersForm({ filters, producers, onChange }: FindingFiltersFormProps) {
  const [text, setText] = useState(filters.q);
  useEffect(() => setText(filters.q), [filters.q]);
  const set = <K extends keyof FindingFilters>(key: K, value: FindingFilters[K]) => onChange({ ...filters, [key]: value });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onChange({ ...filters, q: text.trim() });
  };
  return (
    <form className="filters" onSubmit={submit} role="search" aria-label="Filter findings">
      <label className="field">
        <span>Severity</span>
        <select value={filters.severity} onChange={(e) => set("severity", SEVERITIES.find((s) => s === e.target.value) ?? "")}>
          <option value="">Any</option>
          {SEVERITIES.map((level) => (
            <option key={level} value={level}>
              {level}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Category</span>
        <select value={filters.category} onChange={(e) => set("category", CATEGORIES.find((c) => c === e.target.value) ?? "")}>
          <option value="">Any</option>
          {CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {category}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Status</span>
        <select value={filters.status} onChange={(e) => set("status", e.target.value === "open" || e.target.value === "suppressed" ? e.target.value : "")}>
          <option value="">Any</option>
          <option value="open">Open</option>
          <option value="suppressed">Suppressed</option>
        </select>
      </label>
      <label className="field">
        <span>Producer</span>
        <select value={filters.producer} onChange={(e) => set("producer", e.target.value)}>
          <option value="">Any</option>
          {[...new Set([...producers, ...(filters.producer ? [filters.producer] : [])])].map((producer) => (
            <option key={producer} value={producer}>
              {producer}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span>Kind</span>
        <select value={filters.kind} onChange={(e) => set("kind", e.target.value === "vulnerability" || e.target.value === "review" ? e.target.value : "")}>
          <option value="">Any</option>
          <option value="vulnerability">Vulnerability</option>
          <option value="review">Review signal</option>
        </select>
      </label>
      <label className="field">
        <span>New</span>
        <select value={filters.new} onChange={(e) => set("new", e.target.value === "true" || e.target.value === "false" ? e.target.value : "")}>
          <option value="">Any</option>
          <option value="true">New only</option>
          <option value="false">Existing only</option>
        </select>
      </label>
      <label className="field grow">
        <span>Text</span>
        <input type="search" placeholder="Rule, path or package" maxLength={200} value={text} onChange={(e) => setText(e.target.value)} />
      </label>
      <div className="form-actions">
        <button type="submit" className="btn">
          Search
        </button>
        {activeFilterCount(filters) ? (
          <button type="button" className="btn" onClick={() => onChange(EMPTY_FILTERS)}>
            Clear filters
          </button>
        ) : null}
      </div>
    </form>
  );
}

export function FindingsTable({ findings, onSelect }: { findings: Finding[]; onSelect: (finding: Finding) => void }) {
  if (findings.length === 0) return <Empty>No findings match.</Empty>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">Severity</th>
          <th scope="col">Rule</th>
          <th scope="col">Location</th>
          <th scope="col">Category</th>
          <th scope="col">Producer</th>
          <th scope="col">Status</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((finding) => (
          <tr key={finding.fingerprint}>
            <td>
              <SeverityBadge severity={finding.severity} />
            </td>
            <td>
              <button type="button" className="link-button mono" onClick={() => onSelect(finding)}>
                {finding.rule}
              </button>
              {finding.new ? <span className="badge badge-new">new</span> : null}
              {finding.kind === "review" ? <span className="badge">review</span> : null}
            </td>
            <td className="mono">{findingLocation(finding)}</td>
            <td>{finding.category}</td>
            <td>{finding.producer}</td>
            <td>
              <StatusBadge status={finding.status ?? (finding.suppressed ? "suppressed" : "open")} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Findings() {
  const { id = "" } = useParams();
  const { api, canMaintain } = useAuth();
  const [params, setParams] = useSearchParams();
  const filters = filtersFromParams(params);
  const page = Math.max(1, Number.parseInt(params.get("page") ?? "1", 10) || 1);
  const filterKey = filtersToParams(filters, page).toString();
  const scan = useAsync(() => api.scan(id), [id]);
  const list = useAsync(() => api.findings(id, filters, { page, page_size: PAGE_SIZE }), [id, filterKey]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [notice, setNotice] = useState("");

  const project = scan.data?.project ?? "";
  const maintain = project ? canMaintain(project) : false;
  const producers = scan.data?.producers ?? [];

  function afterTriage(message: string) {
    setSelected(null);
    setNotice(message);
    list.reload();
  }

  return (
    <div>
      <div className="page-header">
        <p className="breadcrumb">
          {project ? (
            <>
              <Link to={`/projects/${encodeURIComponent(project)}`}>{project}</Link> /{" "}
            </>
          ) : null}
          <Link to={`/scans/${encodeURIComponent(id)}`}>Scan #{id}</Link>
        </p>
        <h1>Findings</h1>
      </div>
      <FindingFiltersForm filters={filters} producers={producers} onChange={(next) => setParams(filtersToParams(next, 1))} />
      {notice ? <Notice>{notice}</Notice> : null}
      <ErrorMessage error={list.error} />
      {list.loading && !list.data ? <Loading /> : null}
      {list.data ? (
        <>
          <p className="muted" aria-live="polite">
            {list.data.total} findings
          </p>
          <FindingsTable findings={list.data.items} onSelect={setSelected} />
          <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(next) => setParams(filtersToParams(filters, next))} />
        </>
      ) : null}
      {selected ? (
        <Drawer title={selected.rule} onClose={() => setSelected(null)}>
          <FindingDetail
            finding={selected}
            canTriage={maintain}
            onTriage={async (payload) => {
              await api.putException(project, selected.fingerprint, payload);
              afterTriage("Exception saved. Findings were refreshed.");
            }}
            onRemoveException={async () => {
              await api.deleteException(project, selected.fingerprint);
              afterTriage("Exception removed. Findings were refreshed.");
            }}
          />
        </Drawer>
      ) : null}
    </div>
  );
}
