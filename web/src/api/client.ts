import type {
  ApiToken,
  CompareResult,
  CreatedToken,
  Dashboard,
  ExceptionInput,
  Finding,
  FindingFilters,
  Job,
  JobInput,
  JobStatus,
  LoginResponse,
  Member,
  Page,
  Project,
  ProjectDashboard,
  ProjectException,
  ProjectInput,
  ProjectRole,
  ReportFormat,
  ScanDetail,
  ScanSummary,
  Schedule,
  ScheduleInput,
  TokenInput,
  User,
  Worker,
} from "./types";

export const TOKEN_KEY = "crab.session";
export const API_BASE = "/api/v1";
export const MAX_PAGE_SIZE = 500;

type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue>;

export interface PageRequest {
  page?: number;
  page_size?: number;
}

/** An HTTP error from the API, carrying the server's `detail` message. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export interface Download {
  blob: Blob;
  filename: string;
}

export interface ClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  storage?: Storage;
  onUnauthorized?: () => void;
}

const DEFAULT_ERROR = "Request failed";

/** Turn a FastAPI error body into one readable sentence. */
export function errorDetail(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object" || !("detail" in body)) return fallback;
  const detail = body.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (!Array.isArray(detail)) return fallback;
  const parts: string[] = [];
  for (const item of detail) {
    if (typeof item === "string") {
      parts.push(item);
    } else if (item && typeof item === "object" && "msg" in item) {
      const loc = "loc" in item && Array.isArray(item.loc) ? item.loc.filter((p: unknown) => p !== "body").join(".") : "";
      parts.push(loc ? `${loc}: ${String(item.msg)}` : String(item.msg));
    }
  }
  return parts.length ? parts.join("; ") : fallback;
}

/** Keep only a plain file name from a Content-Disposition header. */
export function filenameFromDisposition(header: string | null, fallback: string): string {
  if (!header) return fallback;
  let name: string | undefined;
  const star = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/.exec(header);
  if (star?.[1]) {
    try {
      name = decodeURIComponent(star[1].trim());
    } catch {
      name = undefined;
    }
  }
  if (!name) {
    const plain = /filename\s*=\s*"?([^";]+)"?/.exec(header);
    name = plain?.[1]?.trim();
  }
  if (!name) return fallback;
  const base = name.split(/[\\/]/).pop() ?? "";
  const clean = base.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\.+/, "").slice(0, 120);
  return clean || fallback;
}

const FORMAT_FILENAMES: Record<string, string> = {
  json: "report.json",
  sarif: "report.sarif",
  markdown: "report.md",
  html: "report.html",
  csv: "report.csv",
  codequality: "gl-code-quality-report.json",
  vex: "report.vex.json",
};

export function reportFilename(scanId: string | number, format: ReportFormat, template?: string): string {
  if (format === "docx") return `scan-${scanId}-${template ?? "technical"}.docx`;
  return `scan-${scanId}-${FORMAT_FILENAMES[format] ?? `report.${format}`}`;
}

function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `${path}?${text}` : path;
}

function seg(value: string | number): string {
  return encodeURIComponent(String(value));
}

function normalizePage<T>(body: unknown): Page<T> {
  // List items are API-defined shapes; the server is the trusted boundary for their element type.
  if (Array.isArray(body)) return { items: body as T[], total: body.length };
  if (body && typeof body === "object" && "items" in body && Array.isArray(body.items)) {
    const items = body.items as T[];
    const total = "total" in body && typeof body.total === "number" ? body.total : items.length;
    return { items, total };
  }
  return { items: [], total: 0 };
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly storage: Storage | undefined;
  private unauthorized: (() => void) | undefined;

  constructor(options: ClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? API_BASE;
    this.fetchImpl = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.storage = options.storage ?? (typeof sessionStorage === "undefined" ? undefined : sessionStorage);
    this.unauthorized = options.onUnauthorized;
  }

  onUnauthorized(handler: (() => void) | undefined): void {
    this.unauthorized = handler;
  }

  getToken(): string | null {
    return this.storage?.getItem(TOKEN_KEY) ?? null;
  }

  setToken(token: string): void {
    this.storage?.setItem(TOKEN_KEY, token);
  }

  clearToken(): void {
    this.storage?.removeItem(TOKEN_KEY);
  }

  private async send(method: string, path: string, query?: Query, body?: unknown, accept = "application/json"): Promise<Response> {
    const headers: Record<string, string> = { Accept: accept };
    const token = this.getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const init: RequestInit = { method, headers, credentials: "same-origin" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let response: Response;
    try {
      response = await this.fetchImpl(this.baseUrl + withQuery(path, query), init);
    } catch {
      throw new ApiError(0, "The server could not be reached");
    }
    if (response.ok) return response;
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
    const fallback = response.status === 401 ? "Your session has ended. Sign in again." : `${DEFAULT_ERROR} (${response.status})`;
    const error = new ApiError(response.status, errorDetail(parsed, fallback));
    if (response.status === 401 && path !== "/auth/login") {
      this.clearToken();
      this.unauthorized?.();
    }
    throw error;
  }

  async request<T>(method: string, path: string, options: { query?: Query; body?: unknown } = {}): Promise<T> {
    const response = await this.send(method, path, options.query, options.body);
    if (response.status === 204) return undefined as T;
    const text = await response.text();
    if (!text) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new ApiError(response.status, "The server returned an unreadable response");
    }
  }

  async list<T>(path: string, query: Query & PageRequest = {}): Promise<Page<T>> {
    const body = await this.request<unknown>("GET", path, { query: { page: 1, page_size: 50, ...query } });
    return normalizePage<T>(body);
  }

  /** Fetch every page of a list endpoint, up to `limit` items. */
  async listAll<T>(path: string, query: Query = {}, limit = 5000): Promise<T[]> {
    const items: T[] = [];
    for (let page = 1; items.length < limit; page += 1) {
      const result = await this.list<T>(path, { ...query, page, page_size: MAX_PAGE_SIZE });
      items.push(...result.items);
      if (result.items.length < MAX_PAGE_SIZE || items.length >= result.total) break;
    }
    return items.slice(0, limit);
  }

  async download(path: string, query: Query | undefined, fallbackName: string): Promise<Download> {
    const response = await this.send("GET", path, query, undefined, "*/*");
    const blob = await response.blob();
    return { blob, filename: filenameFromDisposition(response.headers.get("Content-Disposition"), fallbackName) };
  }

  // Auth
  async login(username: string, password: string): Promise<LoginResponse> {
    const result = await this.request<LoginResponse>("POST", "/auth/login", { body: { username, password } });
    this.setToken(result.token);
    return result;
  }

  async logout(): Promise<void> {
    try {
      if (this.getToken()) await this.request<void>("POST", "/auth/logout");
    } finally {
      this.clearToken();
    }
  }

  me(): Promise<User> {
    return this.request<User>("GET", "/auth/me");
  }

  health(): Promise<{ status: string; version: string }> {
    return this.request("GET", "/health");
  }

  // Users
  users(page: PageRequest = {}): Promise<Page<User>> {
    return this.list<User>("/users", { ...page });
  }
  allUsers(): Promise<User[]> {
    return this.listAll<User>("/users");
  }
  createUser(body: { username: string; password: string; role: string; active: boolean }): Promise<User> {
    return this.request("POST", "/users", { body });
  }
  updateUser(id: string | number, body: Partial<{ username: string; password: string; role: string; active: boolean }>): Promise<User> {
    return this.request("PATCH", `/users/${seg(id)}`, { body });
  }
  deleteUser(id: string | number): Promise<void> {
    return this.request("DELETE", `/users/${seg(id)}`);
  }

  // Tokens
  tokens(query: Query & PageRequest = {}): Promise<Page<ApiToken>> {
    return this.list<ApiToken>("/tokens", query);
  }
  createToken(body: TokenInput): Promise<CreatedToken> {
    return this.request("POST", "/tokens", { body });
  }
  deleteToken(id: string | number): Promise<void> {
    return this.request("DELETE", `/tokens/${seg(id)}`);
  }

  // Projects
  projects(page: PageRequest = {}): Promise<Page<Project>> {
    return this.list<Project>("/projects", { ...page });
  }
  allProjects(): Promise<Project[]> {
    return this.listAll<Project>("/projects");
  }
  project(key: string): Promise<Project> {
    return this.request("GET", `/projects/${seg(key)}`);
  }
  createProject(body: ProjectInput): Promise<Project> {
    return this.request("POST", "/projects", { body });
  }
  updateProject(key: string, body: Partial<ProjectInput>): Promise<Project> {
    return this.request("PATCH", `/projects/${seg(key)}`, { body });
  }
  deleteProject(key: string): Promise<void> {
    return this.request("DELETE", `/projects/${seg(key)}`);
  }
  projectDashboard(key: string, days = 30): Promise<ProjectDashboard> {
    return this.request("GET", `/projects/${seg(key)}/dashboard`, { query: { days } });
  }

  // Members
  members(key: string): Promise<Page<Member>> {
    return this.list<Member>(`/projects/${seg(key)}/members`, { page_size: MAX_PAGE_SIZE });
  }
  setMember(key: string, userId: string | number, role: ProjectRole): Promise<Member> {
    return this.request("PUT", `/projects/${seg(key)}/members/${seg(userId)}`, { body: { role } });
  }
  removeMember(key: string, userId: string | number): Promise<void> {
    return this.request("DELETE", `/projects/${seg(key)}/members/${seg(userId)}`);
  }

  // Scans
  scans(key: string, page: PageRequest = {}): Promise<Page<ScanSummary>> {
    return this.list<ScanSummary>(`/projects/${seg(key)}/scans`, { ...page });
  }
  scan(id: string | number): Promise<ScanDetail> {
    return this.request("GET", `/scans/${seg(id)}`);
  }
  findings(id: string | number, filters: Partial<FindingFilters>, page: PageRequest = {}): Promise<Page<Finding>> {
    return this.list<Finding>(`/scans/${seg(id)}/findings`, { ...filters, ...page });
  }
  compare(id: string | number, base: string | number): Promise<CompareResult> {
    return this.request("GET", `/scans/${seg(id)}/compare`, { query: { base } });
  }
  report(id: string | number, format: ReportFormat, template?: "technical" | "executive"): Promise<Download> {
    return this.download(`/scans/${seg(id)}/report`, { format, template }, reportFilename(id, format, template));
  }
  sbom(id: string | number): Promise<Download> {
    return this.download(`/scans/${seg(id)}/sbom`, undefined, `scan-${id}-sbom.cdx.json`);
  }

  // Exceptions
  exceptions(key: string, page: PageRequest = {}): Promise<Page<ProjectException>> {
    return this.list<ProjectException>(`/projects/${seg(key)}/exceptions`, { ...page });
  }
  putException(key: string, fingerprint: string, body: ExceptionInput): Promise<ProjectException> {
    return this.request("PUT", `/projects/${seg(key)}/exceptions/${seg(fingerprint)}`, { body });
  }
  deleteException(key: string, fingerprint: string): Promise<void> {
    return this.request("DELETE", `/projects/${seg(key)}/exceptions/${seg(fingerprint)}`);
  }
  exportExceptions(key: string): Promise<Download> {
    return this.download(`/projects/${seg(key)}/exceptions/export`, undefined, `${key}-exceptions.json`);
  }

  // Jobs
  projectJobs(key: string, page: PageRequest = {}): Promise<Page<Job>> {
    return this.list<Job>(`/projects/${seg(key)}/jobs`, { ...page });
  }
  createJob(key: string, body: JobInput): Promise<Job> {
    return this.request("POST", `/projects/${seg(key)}/jobs`, { body });
  }
  jobs(filter: { status?: JobStatus | ""; project?: string } = {}, page: PageRequest = {}): Promise<Page<Job>> {
    return this.list<Job>("/jobs", { ...filter, ...page });
  }
  job(id: string | number): Promise<Job> {
    return this.request("GET", `/jobs/${seg(id)}`);
  }
  cancelJob(id: string | number): Promise<Job> {
    return this.request("POST", `/jobs/${seg(id)}/cancel`);
  }

  // Workers
  async workers(): Promise<Worker[]> {
    const body = await this.request<unknown>("GET", "/workers");
    return normalizePage<Worker>(body).items;
  }

  // Schedules
  schedules(key: string): Promise<Page<Schedule>> {
    return this.list<Schedule>(`/projects/${seg(key)}/schedules`, { page_size: MAX_PAGE_SIZE });
  }
  createSchedule(key: string, body: ScheduleInput): Promise<Schedule> {
    return this.request("POST", `/projects/${seg(key)}/schedules`, { body });
  }
  updateSchedule(id: string | number, body: Partial<ScheduleInput>): Promise<Schedule> {
    return this.request("PATCH", `/schedules/${seg(id)}`, { body });
  }
  deleteSchedule(id: string | number): Promise<void> {
    return this.request("DELETE", `/schedules/${seg(id)}`);
  }

  // Dashboard
  dashboard(days = 30): Promise<Dashboard> {
    return this.request("GET", "/dashboard", { query: { days } });
  }
}

export const api = new ApiClient();

/** Save a downloaded blob through a temporary object URL. */
export function saveDownload(download: Download): void {
  const url = URL.createObjectURL(download.blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = download.filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
