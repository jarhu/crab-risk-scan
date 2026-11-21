import { SEVERITIES, type Finding, type SeverityCounts } from "../api/types";

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function shortId(value: string | null | undefined, length = 12): string {
  if (!value) return "—";
  return value.length > length ? value.slice(0, length) : value;
}

export function totalCounts(counts: Partial<SeverityCounts> | undefined): number {
  if (!counts) return 0;
  return SEVERITIES.reduce((sum, level) => sum + (counts[level] ?? 0), 0);
}

export function findingLocation(finding: Pick<Finding, "path" | "line" | "package">): string {
  if (finding.path) return finding.line ? `${finding.path}:${finding.line}` : finding.path;
  if (finding.package) return `${finding.package.name}${finding.package.version ? `@${finding.package.version}` : ""}`;
  return "—";
}

export function sourceLabel(source: { type: string; path?: string; url?: string; ref?: string } | null | undefined): string {
  if (!source) return "—";
  if (source.type === "path") return `path ${source.path ?? ""}`;
  if (source.type === "git") return `git ${source.url ?? ""}${source.ref ? ` @ ${source.ref}` : ""}`;
  return source.type;
}
