// Types for the CRAB server API v1 and the schema-3 report fields the WebUI reads.

export const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = ["sast", "secrets", "iac", "sca", "container"] as const;
export type Category = (typeof CATEGORIES)[number];

export const REPORT_FORMATS = ["json", "sarif", "markdown", "html", "csv", "codequality", "vex"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number] | "docx";

export const EXCEPTION_STATUSES = ["accepted", "false_positive", "not_affected"] as const;
export type ExceptionStatus = (typeof EXCEPTION_STATUSES)[number];

export const JUSTIFICATIONS = [
  "code_not_present",
  "code_not_reachable",
  "requires_configuration",
  "requires_dependency",
  "requires_environment",
  "protected_by_compiler",
  "protected_at_runtime",
  "protected_at_perimeter",
  "protected_by_mitigating_control",
] as const;
export type Justification = (typeof JUSTIFICATIONS)[number];

export type GlobalRole = "admin" | "member";
export type ProjectRole = "maintainer" | "viewer";

export type SeverityCounts = Record<Severity, number>;
export type CategoryCounts = Record<Category, number>;

export interface Page<T> {
  items: T[];
  total: number;
}

export interface Membership {
  project: string;
  role: ProjectRole;
}

export interface User {
  id: number | string;
  username: string;
  role: GlobalRole;
  active: boolean;
  created_at?: string;
  memberships?: Membership[];
}

export interface LoginResponse {
  token: string;
  expires_at: string;
  user: User;
}

export interface PolicyViolation {
  gate: string;
  count: number;
  limit?: number;
}

export interface ScanSummary {
  id: number | string;
  project: string;
  revision: string | null;
  branch: string | null;
  source: string | null;
  status: "passed" | "failed" | "incomplete";
  created_at: string;
  counts: SeverityCounts;
  categories: CategoryCounts;
  total: number;
  suppressed: number;
  new: number | null;
  policy: { passed: boolean; violations: PolicyViolation[] };
  url?: string;
}

export interface ReportImport {
  input: number;
  producer: string;
  origin: "engine" | "report" | "manifest";
  status: "complete" | "partial" | "failed" | "imported" | "skipped";
  reason?: string;
  producer_version: string | null;
  rule_pack: string | null;
  targets: number | null;
}

export interface ReportError {
  reason: string;
  path?: string;
  input?: number;
  producer?: string;
}

export interface PolicyResult {
  passed: boolean;
  source: "default" | "policy-file";
  minimum_severity: Severity | "none";
  new_only: boolean;
  include_review: boolean;
  actionable: number;
  suppressed: number;
  disabled_findings: number;
  violations: PolicyViolation[];
  expired_exceptions: { fingerprint: string; expires: string }[];
  stale_exceptions: string[];
}

export interface PackageRef {
  ecosystem?: string;
  name: string;
  version: string | null;
  purl: string | null;
}

export interface FixedFinding {
  fingerprint: string;
  producer: string;
  rule: string;
  severity: Severity;
  category: Category;
  path: string | null;
  line: number | null;
  package?: PackageRef;
}

export interface Comparison {
  base_revision: string | null;
  new: number;
  unchanged: number;
  fixed: FixedFinding[];
}

export interface ScanDetail extends ScanSummary {
  imports: ReportImport[];
  errors: ReportError[];
  policy: PolicyResult & { passed: boolean; violations: PolicyViolation[] };
  comparison: Comparison | null;
  target: string;
  repository: string | null;
  tool: { name: string; version: string };
  has_sbom: boolean;
  producers: string[];
}

export interface FindingException {
  status: ExceptionStatus;
  reason: string;
  reviewer: string;
  expires?: string | null;
  ticket?: string | null;
  justification?: Justification | null;
}

export interface Finding {
  fingerprint: string;
  producer: string;
  producer_version: string | null;
  rule_pack: string | null;
  module: string;
  category: Category;
  kind: "vulnerability" | "review";
  rule: string;
  severity: Severity;
  original_severity: string;
  message: string;
  path: string | null;
  line: number | null;
  end_line?: number;
  column?: number;
  end_column?: number;
  cwe?: string[];
  help_uri?: string;
  confidence?: string;
  resource?: string;
  framework?: string;
  package?: PackageRef;
  manifest?: string | null;
  image_digest?: string;
  aliases?: string[];
  risk_type?: "vulnerability" | "malicious" | "license";
  fixed_version?: string;
  cvss?: { score: number; vector: string | null; source: string | null };
  epss?: { score: number; percentile: number | null; date: string | null };
  kev?: boolean;
  license?: string;
  new?: boolean;
  suppressed: boolean;
  status?: "open" | "suppressed";
  exception?: FindingException | null;
}

export interface CompareResult {
  base: ScanSummary;
  head: ScanSummary;
  new: Finding[];
  fixed: Finding[];
  unchanged: number;
}

export interface ProjectException {
  fingerprint: string;
  status: ExceptionStatus;
  justification: Justification | null;
  reason: string;
  reviewer: string;
  expires: string | null;
  ticket: string | null;
  created_at: string;
  updated_at: string;
}

export interface ExceptionInput {
  status: ExceptionStatus;
  reason: string;
  justification?: Justification;
  expires?: string;
  ticket?: string;
}

export interface Project {
  key: string;
  name: string;
  repository_url?: string | null;
  default_branch?: string | null;
  /** Admin-set directory that non-admin path jobs and schedules must stay inside. */
  scan_path?: string | null;
  latest_scan?: ScanSummary | null;
  role?: "admin" | ProjectRole | null;
}

export interface ProjectInput {
  key?: string;
  name: string;
  repository_url?: string | null;
  default_branch?: string | null;
  scan_path?: string | null;
}

export interface Member {
  user_id: number | string;
  username: string;
  role: ProjectRole;
}

export type TokenScope = "scan:upload" | "worker" | "read";

export interface ApiToken {
  id: number | string;
  name: string;
  scopes: TokenScope[];
  project: string | null;
  created_at: string;
  last_used_at?: string | null;
  created_by?: string | null;
  prefix?: string;
}

export interface CreatedToken extends ApiToken {
  token: string;
}

export interface TokenInput {
  name: string;
  scopes: TokenScope[];
  project?: string;
}

export type JobSource = { type: "path"; path: string } | { type: "git"; url: string; ref?: string };

export interface JobOptions {
  engines?: string;
  sbom?: boolean;
  fail_on?: string;
}

export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface Job {
  id: number | string;
  project: string;
  status: JobStatus;
  source: JobSource;
  options: JobOptions;
  worker: string | null;
  attempts: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  scan_id: number | string | null;
  error: string | null;
  schedule_id?: number | string | null;
}

export interface JobInput {
  source: JobSource;
  options: JobOptions;
}

export interface Schedule {
  id: number | string;
  project: string;
  cron: string;
  source: JobSource;
  options: JobOptions;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
}

export interface ScheduleInput {
  cron: string;
  source: JobSource;
  options: JobOptions;
  enabled: boolean;
}

export interface Worker {
  name: string;
  last_seen_at: string | null;
  current_job: number | string | null;
  active: boolean;
  capabilities?: { git?: boolean };
}

export interface TrendPoint {
  date: string;
  counts: SeverityCounts;
}

export interface TopRule {
  producer: string;
  rule: string;
  count: number;
}

export interface TopPackage {
  name: string;
  version: string | null;
  purl: string | null;
  count: number;
}

export interface Dashboard {
  projects: number;
  scans: number;
  counts: SeverityCounts;
  categories: CategoryCounts;
  policy: { passed: number; failed: number; incomplete: number };
  projects_summary: { key: string; name: string; latest_scan: ScanSummary | null }[];
  trend: TrendPoint[];
  top_rules: TopRule[];
  top_packages: TopPackage[];
}

export interface ProjectDashboard {
  project?: string;
  latest_scan: ScanSummary | null;
  counts: SeverityCounts;
  categories: CategoryCounts;
  policy: { passed: number; failed: number; incomplete: number };
  trend: TrendPoint[];
  top_rules: TopRule[];
  top_packages: TopPackage[];
  recent_scans: ScanSummary[];
}

export interface FindingFilters {
  severity: Severity | "";
  category: Category | "";
  status: "open" | "suppressed" | "";
  producer: string;
  kind: "vulnerability" | "review" | "";
  new: "true" | "false" | "";
  q: string;
}

export const EMPTY_FILTERS: FindingFilters = {
  severity: "",
  category: "",
  status: "",
  producer: "",
  kind: "",
  new: "",
  q: "",
};
