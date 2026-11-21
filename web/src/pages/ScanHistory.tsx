import { useState } from "react";
import { useNavigate } from "react-router";
import { useAuth } from "../auth/AuthContext";
import { useProject } from "../components/Layout";
import { ScanTable } from "../components/scans";
import { ErrorMessage, Loading, Pagination } from "../components/ui";
import { useAsync } from "../lib/useAsync";

const PAGE_SIZE = 50;

export default function ScanHistory() {
  const { project } = useProject();
  const { api } = useAuth();
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<(string | number)[]>([]);
  const { data, error, loading } = useAsync(() => api.scans(project.key, { page, page_size: PAGE_SIZE }), [project.key, page]);

  function toggle(id: string | number) {
    setSelected((current) => {
      if (current.includes(id)) return current.filter((item) => item !== id);
      return [...current, id].slice(-2);
    });
  }

  function compare() {
    if (selected.length !== 2 || !data) return;
    // The newer scan is the head; history is ordered newest first, so order by creation time.
    const chosen = data.items.filter((scan) => selected.includes(scan.id));
    const [head, base] = [...chosen].sort((a, b) => b.created_at.localeCompare(a.created_at));
    const headId = head?.id ?? selected[0];
    const baseId = base?.id ?? selected[1];
    navigate(`/scans/${encodeURIComponent(String(headId))}/compare?base=${encodeURIComponent(String(baseId))}`);
  }

  return (
    <div>
      <div className="row">
        <h2>Scan history</h2>
        <div className="actions">
          <span className="muted" aria-live="polite">
            {selected.length}/2 selected
          </span>
          <button type="button" className="btn btn-primary" disabled={selected.length !== 2} onClick={compare}>
            Compare selected
          </button>
        </div>
      </div>
      <ErrorMessage error={error} />
      {loading && !data ? <Loading /> : null}
      {data ? (
        <>
          <ScanTable scans={data.items} selected={selected} onToggle={toggle} />
          <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPage={setPage} />
        </>
      ) : null}
    </div>
  );
}
