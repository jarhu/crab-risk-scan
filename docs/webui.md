# WebUI

The WebUI is a single-page application for the CRAB server. It lives in `web/` (Vite, React, React Router and TypeScript, with no CSS framework) and calls only the server API v1 under `/api/v1`. `crab-risk-scan serve` serves the built files at `/`. Any path outside `/api` falls back to `index.html`.

## Pages

| Path | Page | Contents |
|---|---|---|
| `/login` | Login | Username and password. On success the session token goes to `sessionStorage` and the browser returns to the page it came from. |
| `/` | Organization dashboard | Severity cards, category bars, policy pass, fail and incomplete counts, a daily trend (7 to 365 days), top rules, top packages and the latest scan for each project. All figures come from each visible project's latest scan. |
| `/projects` | Projects | List with role, policy status and open findings. Administrators also see a create form. |
| `/projects/:key` | Project overview | Severity cards, category bars, policy status, trend, top rules and packages, and recent scans. |
| `/projects/:key/scans` | Scan history | Scans from newest to oldest. Select two scans to compare them. |
| `/scans/:id` | Scan detail | Metadata, policy result and violations, expired and stale exceptions, coverage table from `imports`, errors, embedded comparison, and report downloads. |
| `/scans/:id/findings` | Findings | Filters for severity, category, status, producer, kind, new and free text. Filters are kept in the URL. Opening a finding shows a detail drawer with a triage form. |
| `/scans/:id/compare?base=:id` | Compare | Lists new and fixed findings and counts unchanged ones. |
| `/projects/:key/exceptions` | Exceptions | Lists, edits and deletes exceptions, and downloads the exceptions v2 export for CI. |
| `/projects/:key/jobs` | Jobs | A run form for a server path or git source, with engines, SBOM and fail-on options, and the project's job list. The list refreshes every 3 seconds while a job is queued or running. |
| `/projects/:key/schedules` | Schedules | Creates, edits, enables, disables and deletes cron schedules, with the next and last run in UTC. |
| `/projects/:key/settings` | Project settings | Project details, members and roles, and project tokens. The scan path is editable by administrators and shown read-only to maintainers. A new token's secret is shown once. |
| `/admin/users` | Users | Creates, edits, deactivates and deletes users. |
| `/admin/tokens` | Service tokens | Worker, upload and read tokens, either global or bound to a project. A new token's secret is shown once. |
| `/admin/workers` | Workers and job queue | Worker state and capabilities, plus the job queue for every project with status and project filters. The page refreshes every 5 seconds. |

The scan detail page downloads JSON, SARIF, Markdown, HTML, CSV, GitLab Code Quality, CycloneDX VEX, DOCX technical, DOCX executive and the stored CycloneDX SBOM. The server renders each download when it is requested and applies the project's current exceptions. The browser fetches the file with the bearer token and saves it as a blob.

## Roles

| Role | What the WebUI shows |
|---|---|
| Global `admin` | Every page and every control, including project create and delete, users, service tokens, workers and the global job queue. |
| Project `maintainer` | The triage form, exception edit and delete, the run form, job cancel, schedule controls, project detail edits, member management and project tokens. |
| Project `viewer` | Read-only pages. Edit controls are hidden. |
| Global `member` without membership | An empty project list. |

Hidden controls only make the interface simpler. The server enforces every permission. When it returns 403, the page shows the server's `detail` message, and a 401 clears the session and opens the login page.

## Security properties

| Property | Implementation |
|---|---|
| Token storage | The session token is kept in `sessionStorage` (key `crab.session`), so it is cleared when the tab closes. Sign out calls `POST /auth/logout`. |
| Untrusted text | Every API string is rendered as a React text node. The source contains no `dangerouslySetInnerHTML`. |
| Links | Links built from data, such as repository URLs and `help_uri`, are rendered only for `http:` and `https:` URLs. Other values are shown as plain text. External links use `rel="noopener noreferrer nofollow"`. |
| Download names | File names from `Content-Disposition` are reduced to `[A-Za-z0-9._-]` without path components. |
| Post-login redirect | Only same-origin application paths are accepted as `next`. |

## Development

Start the API server, then run the Vite dev server. The dev server proxies `/api` to `http://127.0.0.1:8080`.

```sh
crab-risk-scan serve --host 127.0.0.1 --port 8080 --data-dir .crab-dev
cd web
npm ci
npm run dev        # http://localhost:5173
```

On first start, set `CRAB_ADMIN_USERNAME` and `CRAB_ADMIN_PASSWORD` to create the first administrator. See [server.md](server.md).

| Script | Effect |
|---|---|
| `npm run dev` | Vite dev server with hot reload and the `/api` proxy. |
| `npm run typecheck` | `tsc --noEmit` in strict mode. |
| `npm test` | Vitest with jsdom and Testing Library. Covers API client auth and errors, findings filter state, the triage payload, the severity summary, link and text safety, and role-gated controls. |
| `npm run build` | Type check, then a production build into `crab_risk_scan/server/static/`. |

## Build output and packaging

`vite build` writes `index.html` and hashed files under `assets/` to `crab_risk_scan/server/static/`, and empties that folder first. The folder is git-ignored. `pyproject.toml` includes `server/static/**/*` as package data, so run `npm ci && npm run build` in `web/` before you build a wheel. When the folder has no `index.html`, `crab-risk-scan serve` serves a short page that explains how to build the WebUI.

The server image builds the WebUI in a Node stage (`npm ci && npm run build` in `web/`). It then copies `crab_risk_scan/server/static/` into the Python stage before installing the package. The image therefore needs no Node runtime. `package-lock.json` pins every dependency so builds are reproducible.

[Server](server.md) · [API](api.md) · [Reporting](reporting.md) · [Architecture](architecture.md)
