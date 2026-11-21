import { CATEGORIES, SEVERITIES, type CategoryCounts, type SeverityCounts, type TopPackage, type TopRule, type TrendPoint } from "../api/types";
import { totalCounts } from "../lib/format";
import { Empty } from "./ui";

const CATEGORY_LABELS: Record<string, string> = {
  sast: "Code (SAST)",
  secrets: "Secrets",
  iac: "Infrastructure as code",
  sca: "Dependencies",
  container: "Containers",
};

export function SeverityCards({ counts }: { counts: Partial<SeverityCounts> | undefined }) {
  return (
    <ul className="severity-cards" aria-label="Open findings by severity">
      {SEVERITIES.map((level) => (
        <li key={level} className={`severity-card sev-card-${level}`}>
          <span className="severity-count" data-testid={`severity-${level}`}>
            {counts?.[level] ?? 0}
          </span>
          <span className="severity-label">{level}</span>
        </li>
      ))}
    </ul>
  );
}

export function CategoryBars({ categories }: { categories: Partial<CategoryCounts> | undefined }) {
  const max = Math.max(1, ...CATEGORIES.map((c) => categories?.[c] ?? 0));
  return (
    <dl className="bars" aria-label="Open findings by category">
      {CATEGORIES.map((category) => {
        const value = categories?.[category] ?? 0;
        return (
          <div className="bar-row" key={category}>
            <dt>{CATEGORY_LABELS[category]}</dt>
            <dd>
              <span className="bar-track">
                <span className="bar-fill" style={{ width: `${(value / max) * 100}%` }} />
              </span>
              <span className="bar-value">{value}</span>
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

export function PolicySummary({ policy }: { policy: { passed: number; failed: number; incomplete: number } | undefined }) {
  const passed = policy?.passed ?? 0;
  const failed = policy?.failed ?? 0;
  const incomplete = policy?.incomplete ?? 0;
  const total = Math.max(1, passed + failed + incomplete);
  return (
    <div className="policy-summary">
      <div className="stack-bar" role="img" aria-label={`Policy: ${passed} passed, ${failed} failed, ${incomplete} incomplete`}>
        <span className="stack-passed" style={{ width: `${(passed / total) * 100}%` }} />
        <span className="stack-failed" style={{ width: `${(failed / total) * 100}%` }} />
        <span className="stack-incomplete" style={{ width: `${(incomplete / total) * 100}%` }} />
      </div>
      <ul className="legend">
        <li>
          <span className="swatch stack-passed" /> Passed {passed}
        </li>
        <li>
          <span className="swatch stack-failed" /> Failed {failed}
        </li>
        <li>
          <span className="swatch stack-incomplete" /> Incomplete {incomplete}
        </li>
      </ul>
    </div>
  );
}

/** Stacked daily bars of open findings by severity. */
export function TrendChart({ trend }: { trend: TrendPoint[] | undefined }) {
  if (!trend || trend.length === 0) return <Empty>No trend data yet.</Empty>;
  const width = 640;
  const height = 160;
  const max = Math.max(1, ...trend.map((point) => totalCounts(point.counts)));
  const slot = width / trend.length;
  const barWidth = Math.max(2, slot * 0.7);
  const first = trend[0];
  const last = trend[trend.length - 1];
  return (
    <figure className="trend">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Open findings per day" preserveAspectRatio="none">
        {trend.map((point, index) => {
          let y = height;
          return (
            <g key={point.date}>
              <title>{`${point.date}: ${totalCounts(point.counts)} open`}</title>
              {[...SEVERITIES].reverse().map((level) => {
                const value = point.counts?.[level] ?? 0;
                if (!value) return null;
                const h = (value / max) * (height - 4);
                y -= h;
                return <rect key={level} className={`trend-${level}`} x={index * slot + (slot - barWidth) / 2} y={y} width={barWidth} height={h} />;
              })}
            </g>
          );
        })}
      </svg>
      <figcaption className="trend-axis">
        <span>{first?.date}</span>
        <span>max {max}</span>
        <span>{last?.date}</span>
      </figcaption>
    </figure>
  );
}

export function TopRules({ rules }: { rules: TopRule[] | undefined }) {
  if (!rules?.length) return <Empty>No open findings.</Empty>;
  return (
    <table className="table compact">
      <thead>
        <tr>
          <th scope="col">Rule</th>
          <th scope="col">Producer</th>
          <th scope="col" className="num">
            Count
          </th>
        </tr>
      </thead>
      <tbody>
        {rules.map((rule) => (
          <tr key={`${rule.producer}/${rule.rule}`}>
            <td className="mono">{rule.rule}</td>
            <td>{rule.producer}</td>
            <td className="num">{rule.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function TopPackages({ packages }: { packages: TopPackage[] | undefined }) {
  if (!packages?.length) return <Empty>No vulnerable packages.</Empty>;
  return (
    <table className="table compact">
      <thead>
        <tr>
          <th scope="col">Package</th>
          <th scope="col">Version</th>
          <th scope="col" className="num">
            Count
          </th>
        </tr>
      </thead>
      <tbody>
        {packages.map((pkg) => (
          <tr key={pkg.purl ?? `${pkg.name}@${pkg.version ?? ""}`}>
            <td className="mono" title={pkg.purl ?? undefined}>
              {pkg.name}
            </td>
            <td className="mono">{pkg.version ?? "—"}</td>
            <td className="num">{pkg.count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
