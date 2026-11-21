# API reference

The base path is `/api/v1`. Requests and responses use JSON. Authenticate with `Authorization: Bearer <token>`, using a session token from `POST /auth/login` or an API token. Timestamps are ISO 8601 UTC strings ending in `Z`. Errors use `{"detail": "..."}`. With `CRAB_API_DOCS=1` the server also publishes OpenAPI at `/api/openapi.json` and interactive docs at `/api/docs`; both are disabled by default.

List endpoints return `{"items": [...], "total": n}` and accept `page` (default 1, maximum 100000) and `page_size` (default 50, maximum 500).

| Status | Meaning |
|---|---|
| 400 | Body is not JSON, or contains `NaN` or `Infinity` |
| 401 | Missing, invalid or expired credentials |
| 403 | Authenticated, but the role or token scope is insufficient |
| 404 | Not found, or not visible to the caller |
| 409 | Conflict: duplicate name, last admin, job not held by this worker, job already finished |
| 413 | Request body, report or SBOM larger than 32 MiB |
| 422 | Validation failure |
| 429 | Sign-in temporarily locked for the account or the client address; see `Retry-After` |
| 503 | Password hashing is saturated (sign-in, user creation, password change); see `Retry-After` |
| 501 | Report format needs an optional dependency that is not installed |

## Authentication and users

| Method and path | Body | Response | Permission |
|---|---|---|---|
| GET /health | | `{status: "ok", version}` | none |
| POST /auth/login | `{username, password}` | `{token, expires_at, user: Me}` | none |
| POST /auth/logout | | 204 | session |
| GET /auth/me | | Me | session |
| GET /users | | User items | admin |
| POST /users | `{username, password, role?: "admin"\|"member", active?: bool}` | 201 User | admin |
| PATCH /users/{id} | any of `{username, password, role, active}` | User | admin |
| DELETE /users/{id} | | 204 | admin |

User: `{id, username, role, active, created_at}`. Me adds `memberships: [{project, role}]`. Usernames are lowercased. The last active admin cannot be demoted, deactivated or deleted, and admins cannot delete themselves.

## API tokens

| Method and path | Body | Response | Permission |
|---|---|---|---|
| GET /tokens?project=KEY | | Token items | admin: all; maintainers: tokens of projects they maintain |
| POST /tokens | `{name, scopes: ["scan:upload"\|"worker"\|"read"], project?: KEY}` | 201 Token plus `token` | admin; maintainers for project-bound `scan:upload` and `read` tokens |
| DELETE /tokens/{id} | | 204 | admin; maintainer of the token's project |

Token: `{id, name, scopes, project: KEY|null, prefix, created_by, created_at, last_used_at}`. The secret appears only in the POST response.

## Projects and members

| Method and path | Body | Response | Permission |
|---|---|---|---|
| GET /projects | | Project items with `latest_scan` | visible projects |
| POST /projects | `{key, name, repository_url?, default_branch?, scan_path?}` | 201 Project | admin |
| GET /projects/{key} | | Project | viewer |
| PATCH /projects/{key} | any of `{name, repository_url, default_branch, scan_path}` | Project | maintainer; `scan_path` admin only (403 otherwise) |
| DELETE /projects/{key} | | 204 | admin |
| GET /projects/{key}/members | | `{user_id, username, role}` items | maintainer |
| GET /projects/{key}/candidates?q=TEXT | | `{items: [{id, username}]}`, active users by case-insensitive prefix, at most 20 | maintainer |
| PUT /projects/{key}/members/{user_id} | `{role: "maintainer"\|"viewer"}` | Member | maintainer |
| DELETE /projects/{key}/members/{user_id} | | 204 | maintainer |

Project: `{id, key, name, repository_url, default_branch, scan_path, created_at, role, latest_scan}`. `role` is the caller's effective role: `admin`, `maintainer`, `viewer` or null. Keys are 1 to 64 characters of lowercase letters, digits, `.`, `_` and `-`. `scan_path` is an absolute directory inside `CRAB_SCAN_ROOTS`, or null; an empty value clears it.

## Scans

| Method and path | Body or query | Response | Permission |
|---|---|---|---|
| POST /projects/{key}/scans | `{report, sbom?, source?: "runner"\|"upload", ci?: {platform, run_url}}` | 201 ScanSummary plus `url` | maintainer or `scan:upload` token |
| GET /projects/{key}/scans | `branch?` | ScanSummary items, newest first | viewer |
| GET /scans/{id} | | ScanDetail | viewer |
| GET /scans/{id}/findings | `severity`, `category`, `status=open\|suppressed`, `producer`, `kind=vulnerability\|review`, `new=true\|false`, `q` | Finding items in report order | viewer |
| GET /scans/{id}/compare?base={id} | | `{base, head, new: [Finding], fixed: [Finding], unchanged: n}` | viewer |
| GET /scans/{id}/report | `format=json\|sarif\|markdown\|html\|csv\|docx\|codequality\|vex`, `template=technical\|executive` | File download | viewer |
| GET /scans/{id}/sbom | | Stored SBOM download, or 404 | viewer |

The report must validate against schema 3. Reports and SBOMs are limited to 32 MiB each. The SBOM must be CycloneDX or SPDX JSON. `url` points to the scan page of the WebUI.

ScanSummary: `{id, project, revision, branch, source, status: "passed"|"failed"|"incomplete", created_at, counts: {critical, high, medium, low, info, unknown}, categories: {sast, secrets, iac, sca, container}, total, suppressed, new, policy: {passed, violations}}`. `counts`, `categories` and `total` cover unsuppressed findings under the current exceptions. `suppressed` counts the rest. `new` is the comparison's new count, or null without a comparison. `source` is `upload`, `runner` or `job`. `status` is `incomplete` when the report has errors.

ScanDetail adds `imports`, `errors`, `comparison`, `target`, `repository`, `tool`, `ci`, `job_id`, `has_sbom`, `producers` (the distinct producers of the scan's findings, for filters) and the full `policy` result.

`severity`, `category` and `producer` filters accept comma-separated lists. `q` matches rule, path, package name and purl, case-insensitively. Finding items are schema-3 findings with the current `suppressed` flag, `status` (`open` or `suppressed`) and `exception` (or null). Report downloads apply the current project exceptions to every finding. The stored policy result is unchanged.

## Exceptions

| Method and path | Body | Response | Permission |
|---|---|---|---|
| GET /projects/{key}/exceptions | | Exception items | viewer |
| PUT /projects/{key}/exceptions/{fingerprint} | `{status, reason, justification?, expires?, ticket?}` | Exception | maintainer session |
| DELETE /projects/{key}/exceptions/{fingerprint} | | 204 | maintainer session |
| GET /projects/{key}/exceptions/export | | Exceptions v2 file download | viewer |

Exception: `{fingerprint, status, justification, reason, reviewer, expires, ticket, created_at, updated_at}`. `status` is `accepted`, `false_positive` or `not_affected`. `not_affected` requires a CycloneDX VEX justification. `expires` is `YYYY-MM-DD`. The reviewer is the signed-in user.

## Jobs and workers

| Method and path | Body or query | Response | Permission |
|---|---|---|---|
| POST /projects/{key}/jobs | `{source: {type: "path", path} \| {type: "git", url, ref?}, options?: {engines?, sbom?, fail_on?}}` | 201 Job | maintainer session |
| GET /projects/{key}/jobs | `status?` | Job items, newest first | maintainer |
| GET /jobs | `status?`, `project?` | Job items | admin |
| GET /jobs/{id} | | Job plus `log` | viewer of the project |
| POST /jobs/{id}/cancel | | Job | maintainer of the project |
| POST /workers/claim | `{worker, capabilities: {git: bool}}` | 200 `{job, lease_seconds}` or 204 | `worker` token |
| POST /jobs/{id}/heartbeat | `{worker?}` | `{lease_seconds, cancelled}` | `worker` token holding the lease |
| POST /jobs/{id}/complete | `{report, sbom?, log?, worker?}` | `{scan_id}` | `worker` token holding the lease |
| POST /jobs/{id}/fail | `{error, log?, worker?}` | `{id, status}` | `worker` token holding the lease |
| GET /workers | | `{name, last_seen_at, current_job, active, capabilities}` items | admin |

Job: `{id, project, status: "queued"|"running"|"succeeded"|"failed"|"cancelled", source, options, worker, attempts, created_at, started_at, finished_at, scan_id, error, schedule_id}`. Claimed jobs also carry the project's `repository_url`. Path sources must be absolute, not UNC or device paths, and inside `CRAB_SCAN_ROOTS`. Non-admin callers must also stay inside the project's `scan_path`; without one, their path sources answer 422. Git URLs must be http or https without credentials, and their host must be listed in `CRAB_GIT_HOSTS` (otherwise 422). A project holds at most 100 queued jobs. The server authorizes an upload before reading its body. A complete call with an invalid report fails the job and answers 422. Logs keep the last 64 KiB. Any `worker` token can claim any project's job.

## Schedules

| Method and path | Body | Response | Permission |
|---|---|---|---|
| GET /projects/{key}/schedules | | Schedule items | maintainer |
| POST /projects/{key}/schedules | `{cron, source, options?, enabled?}` | 201 Schedule | maintainer session |
| PATCH /schedules/{id} | any of `{cron, source, options, enabled}` | Schedule | maintainer session |
| DELETE /schedules/{id} | | 204 | maintainer session |

Schedule: `{id, project, cron, source, options, enabled, next_run_at, last_run_at, last_job_id, created_at}`. Cron expressions have five fields evaluated in UTC. Disabled schedules have a null `next_run_at`. Sources follow the job rules for the caller who set them, and are checked again at every run. A project holds at most 50 schedules.

## Dashboards

| Method and path | Query | Response | Permission |
|---|---|---|---|
| GET /dashboard | `days` (1-365, default 30) | Organization dashboard | visible projects |
| GET /projects/{key}/dashboard | `days` | Project dashboard | viewer |

Organization dashboard: `{projects, scans, counts, categories, policy: {passed, failed, incomplete}, projects_summary: [{key, name, latest_scan}], trend: [{date, counts}], top_rules: [{producer, rule, count}], top_packages: [{name, version, purl, count}]}`. Counts, categories, policy states and the top ten lists cover each visible project's latest scan with current exceptions. `trend` has one entry per day; each day sums the latest scan of every project up to that day.

Project dashboard: `{project, latest_scan, scans, counts, categories, policy, trend, top_rules, top_packages, recent_scans}` with up to ten recent ScanSummary items.

[Server deployment](server.md) · [WebUI](webui.md) · [CI runner](ci.md) · [Report schema](reporting.md)
