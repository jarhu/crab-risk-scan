import { CATEGORIES, EMPTY_FILTERS, SEVERITIES, type FindingFilters } from "../api/types";

const KINDS = ["vulnerability", "review"] as const;
const STATUSES = ["open", "suppressed"] as const;
const BOOLS = ["true", "false"] as const;

function pick<T extends string>(value: string | null, allowed: readonly T[]): T | "" {
  return allowed.find((item) => item === value) ?? "";
}

/** Read finding filters from URL search parameters, dropping unknown values. */
export function filtersFromParams(params: URLSearchParams): FindingFilters {
  return {
    severity: pick(params.get("severity"), SEVERITIES),
    category: pick(params.get("category"), CATEGORIES),
    status: pick(params.get("status"), STATUSES),
    producer: (params.get("producer") ?? "").slice(0, 64),
    kind: pick(params.get("kind"), KINDS),
    new: pick(params.get("new"), BOOLS),
    q: (params.get("q") ?? "").slice(0, 200),
  };
}

/** Write filters and page back to search parameters, omitting empty values. */
export function filtersToParams(filters: FindingFilters, page = 1): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of Object.keys(EMPTY_FILTERS) as (keyof FindingFilters)[]) {
    const value = filters[key].trim();
    if (value) params.set(key, value);
  }
  if (page > 1) params.set("page", String(page));
  return params;
}

export function activeFilterCount(filters: FindingFilters): number {
  return Object.values(filters).filter((value) => value.trim() !== "").length;
}
