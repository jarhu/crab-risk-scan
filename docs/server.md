# Self-hosted server

`crab-risk-scan serve` runs the REST API, the WebUI and the schedule loop in one process. Workers run `crab-risk-scan worker` on the scanner image and call the same CLI as local scans. The server stores reports, SBOMs, findings, exceptions, jobs and schedules in SQLite or PostgreSQL. The [API reference](api.md) lists every endpoint.

## Install and run

The server needs the `server` extra. PostgreSQL needs the `postgres` extra and DOCX downloads need the `docx` extra.

```sh
pip install 'crab-risk-scan[server,docx]'
crab-risk-scan serve --host 127.0.0.1 --port 8080
```

On the first start with an empty user table, the server creates an administrator. It uses `CRAB_ADMIN_USERNAME` (default `admin`) and `CRAB_ADMIN_PASSWORD`. Without a password, it generates one and prints it once to stderr. Only the scrypt hash is stored.

Release wheels and the server image contain the WebUI. A source checkout needs `npm ci && npm run build` in `web/` first. Without the assets, `/` shows a page that explains this, and the API keeps working.

## Docker Compose

`compose.yaml` at the repository root defines the deployment.

| Service | Image | Networks | Purpose |
|---|---|---|---|
| api | `deployments/docker/server.Dockerfile` | frontend, workers, database | API, WebUI and scheduler. Publishes port 8080 on `127.0.0.1` by default. |
| worker | `deployments/docker/scanner.Dockerfile` | workers (internal) | Claims jobs and runs scans. Reaches only the API. |
| db | `postgres:17-alpine`, profile `postgres` | database (internal) | Optional PostgreSQL. |

| Volume or mount | Mounted at | Contents |
|---|---|---|
| crab-data | `/var/lib/crab` in api | SQLite database |
| `${CRAB_SCAN_DIR:-./scan}` | `/scan` in api and worker, read-only | Repositories that path jobs may scan |
| crab-cache | `/opt/crab/cache` in worker | Trivy and OSV vulnerability databases |
| crab-postgres | PostgreSQL data directory | PostgreSQL database |

```sh
mkdir -p scan
docker compose up -d --build api
docker compose logs api                       # initial admin password when CRAB_ADMIN_PASSWORD is unset
docker compose exec api crab-risk-scan admin create-token compose-workers --scope worker
echo "CRAB_WORKER_TOKEN=<token>" >> .env
docker compose up -d worker
```

The worker network is internal, so workers have no internet access. Prepare the vulnerability databases into the cache volume from a networked container, for example `docker compose run --rm --no-deps --network bridge --entrypoint crab-risk-scan worker db update`, or build the scanner image with `PREFETCH_DB=true`. Git jobs need network access to the git host: attach the worker to a network that reaches it, add `--allow-git` to its command and list the host in `CRAB_GIT_HOSTS`. `CRAB_WORKERS` sets the number of worker replicas.

For PostgreSQL, set `POSTGRES_PASSWORD` and `CRAB_DATABASE_URL=postgresql+psycopg://crab:<password>@db:5432/crab` in `.env`, then run `docker compose --profile postgres up -d --build`.

The Docker files were written for this release but are not exercised by the test suite.

## Configuration

| Setting | Flag | Environment | Default |
|---|---|---|---|
| Listen address | `--host`, `--port` | | `127.0.0.1`, `8080` |
| Database URL | `--database` | `CRAB_DATABASE_URL` | `sqlite:///<data dir>/crab.db` |
| Data directory | `--data-dir` | `CRAB_DATA_DIR` | Platform user data directory, `crab-risk-scan` |
| Allowed scan roots for path jobs | | `CRAB_SCAN_ROOTS` (`os.pathsep`-separated absolute paths) | none: path jobs are rejected |
| Allowed git hosts | | `CRAB_GIT_HOSTS` (comma-separated `host` or `host:port`) | none: git sources are rejected |
| First administrator | | `CRAB_ADMIN_USERNAME`, `CRAB_ADMIN_PASSWORD` | `admin`, generated password |
| Session lifetime in hours | | `CRAB_SESSION_HOURS` | 12 |
| Job lease in seconds | | `CRAB_LEASE_SECONDS` | 300 |
| Attempts per job before it fails | | `CRAB_JOB_MAX_ATTEMPTS` | 3 |
| Schedule loop | `--no-scheduler` | `CRAB_SCHEDULER=0` | enabled |
| Schedule loop interval in seconds | | `CRAB_SCHEDULER_INTERVAL` | 30 |
| Trusted reverse proxies | `--forwarded-allow-ips` | `FORWARDED_ALLOW_IPS` (read by uvicorn) | `127.0.0.1` |
| Failed sign-ins per client address per lockout window | | `CRAB_LOGIN_MAX_FAILURES_PER_CLIENT` (0 disables) | 100 |
| Concurrent password hash computations | | `CRAB_PASSWORD_HASH_CONCURRENCY` | 4 |
| OpenAPI document and Swagger UI | | `CRAB_API_DOCS=1` | disabled |

Uploads accept up to 32 MiB per report and per SBOM. Larger documents receive 413.

`CRAB_GIT_HOSTS` entries match the URL host exactly and case-insensitively. An entry without a port matches only the scheme's default port (443 or 80). Literal loopback, link-local, unspecified, multicast and reserved addresses are rejected even when listed. Existing schedules are checked again at every run.

| Per-project limit | Value | Beyond the limit |
|---|---|---|
| Schedules | 50 | 422 |
| Queued jobs | 100 | 422; a due schedule run is recorded as a failed job |

The server creates missing tables at startup and records the schema version in `crab_schema`. It refuses to start on a database written by a newer release.

## Users and roles

| Role | Scope | Can |
|---|---|---|
| admin | global | Everything, including users, projects, service tokens, the job queue and workers |
| member | global | Sign in and see projects where they hold a membership |
| maintainer | project | Upload scans, triage exceptions, run jobs inside the project's scan path, manage schedules, project settings except the scan path, members and project tokens |
| viewer | project | Read scans, findings, reports, exceptions, jobs and dashboards |

Projects that a principal cannot see answer 404. Visible projects with an insufficient role answer 403.

`crab-risk-scan admin` manages users and tokens directly in the database. It accepts `--database` and `--data-dir` like `serve`.

| Command | Effect |
|---|---|
| `admin create-user NAME [--role admin\|member] [--password-stdin]` | Create a user. Prompts twice on a terminal. |
| `admin set-password NAME [--password-stdin]` | Replace the password, revoke sessions and clear the sign-in lockout |
| `admin unlock NAME` | Clear the account's failed sign-in counter and lockout |
| `admin create-token NAME --scope SCOPE [--scope ...] [--project KEY]` | Print a new API token once |
| `admin list-tokens [--project KEY]` | List tokens with their 12-character prefix, never the secret |

## API tokens

| Scope | Grants | Who creates it |
|---|---|---|
| `scan:upload` | `POST /projects/{key}/scans`. CI runners use it. | Admins; maintainers for their project |
| `read` | Read endpoints of the bound project, or of all projects for unbound tokens | Admins; maintainers for their project |
| `worker` | Claim, heartbeat, complete and fail jobs of every project | Admins only, never bound to a project |

Tokens start with `crab_`. The server stores only their SHA-256 digest.

Any `worker` token can claim any project's job and receives its source. Treat worker tokens as instance-wide credentials.

A token created through the API stays valid only while its creator is active and could still create it: a project-bound token created by a non-admin needs the creator to remain a maintainer of that project, and a global token needs the creator to remain an admin. Deleting the creator deletes the token. Tokens created with `admin create-token` have no creator and are unaffected.

## Workers

```sh
crab-risk-scan worker --server https://crab.example.com --token "$CRAB_WORKER_TOKEN" \
    --scan-root /srv/repos [--allow-git] [--git-host HOST[:PORT] ...] [--name NAME] [--poll-interval 10] \
    [--timeout 3600] [--once]
```

The worker uses only the standard library. Each job runs this command in a private temporary directory, so the target never lands on the Python import path:

```text
python -m crab_risk_scan scan <dir> --output <tmp>/report.json [--sbom --output <tmp>/sbom.cdx.json]
       [--engines E] [--fail-on L] [--revision SHA] [--branch REF] [--repository URL]
```

Exit 0, 1 or 2 with a report completes the job and stores a scan. Other outcomes fail the job with a log tail of at most 64 KiB.

| Mechanism | Behaviour |
|---|---|
| Claim | A conditional update on the job status hands each queued job to exactly one worker |
| Lease | `CRAB_LEASE_SECONDS`. The worker sends heartbeats every third of the lease. |
| Lost worker | Expired leases return the job to the queue until `CRAB_JOB_MAX_ATTEMPTS`, then the job fails |
| Cancellation | Cancelling a running job makes the next heartbeat stop the scan subprocess |
| Path sources | Must stay inside `CRAB_SCAN_ROOTS` on the server and inside `--scan-root` (or `CRAB_SCAN_ROOTS`) on the worker. Jobs and schedules created by non-admins must also stay inside the project's `scan_path`, which only admins set; without one they are rejected. UNC and device paths are rejected. A path must first lie lexically inside a root, as configured or as resolved (temporary folders are reached through aliases such as macOS `/var` and Windows 8.3 short names); only then is it resolved, and the result must stay inside the resolved root, which catches symlink escapes. |
| Git sources | http or https URLs without credentials whose host is listed in `CRAB_GIT_HOSTS`. Only workers started with `--allow-git` receive them. `--git-host` (default `CRAB_GIT_HOSTS`) restricts hosts on the worker when set. The worker resolves the host, refuses loopback, link-local, unspecified, multicast and reserved addresses, and pins git to the checked address. Git runs with a minimal environment, no credential helpers, redirects, LFS filters, submodules, hooks or symlinks, and only the http and https protocols. Job logs contain a failure category, never git's output. |
| Stop | SIGTERM finishes the current job, then exits |

## Schedules

Schedules use five-field cron expressions in UTC: minute, hour, day of month, month and day of week. Fields accept lists, ranges, steps and three-letter names. When both day fields are restricted, either one matches. Each API instance runs the schedule loop. A compare-and-set on `next_run_at` lets exactly one instance enqueue each due run, so several instances never double-enqueue. Runs missed while every instance was down are not backfilled: the next run is computed from the current time.

## Triage and reports

Exceptions are stored per project and per fingerprint. A project exception overrides the exception embedded in an uploaded report for the same fingerprint. Embedded exceptions without a project counterpart still apply. Expired exceptions (on or after `expires`) never suppress. Summary counts, findings, dashboards and report downloads use the current exceptions. The stored `policy` section and scan status record the gate result at scan time. Re-gate in CI with the exported exceptions file:

```sh
curl -H "Authorization: Bearer $CRAB_TOKEN" -o crab-exceptions.json \
    https://crab.example.com/api/v1/projects/demo/exceptions/export
crab-risk-scan gate report.json --exceptions crab-exceptions.json
```

## Backup and restore

| Database | Backup | Restore |
|---|---|---|
| SQLite | `sqlite3 crab.db ".backup crab-backup.db"` while the server runs, or copy `crab.db` after stopping it | Stop the server and replace `crab.db` |
| PostgreSQL | `pg_dump -Fc crab > crab.dump` | `pg_restore -d crab --clean crab.dump` |

In Compose, the SQLite file is `/var/lib/crab/crab.db` in the `crab-data` volume. The vulnerability cache can be rebuilt with `db update` and needs no backup.

## Security notes

| Topic | Behaviour |
|---|---|
| Passwords | scrypt (N=2^15, r=8, p=1) with a random salt, compared in constant time; 10 to 1024 characters |
| Sessions | Random bearer tokens, stored as SHA-256 digests, expiring after `CRAB_SESSION_HOURS`. Password changes and deactivation revoke them. |
| Sign-in throttling | Each attempt is counted before the password check, atomically, so concurrent requests cannot exceed the limit. Five failures within 15 minutes lock the account name for 15 minutes; `CRAB_LOGIN_MAX_FAILURES_PER_CLIENT` failures lock the client address (429 with Retry-After). Behind a reverse proxy, pass `--forwarded-allow-ips` with the proxy address, otherwise every client shares the proxy's bucket. The schedule loop prunes expired records. |
| Password hashing | At most `CRAB_PASSWORD_HASH_CONCURRENCY` scrypt computations run at once. A request that waits more than 5 seconds receives 503 with Retry-After. |
| Request bodies | Authorization happens before an upload body is read. At most two large bodies are buffered and parsed at once, off the event loop. `NaN` and `Infinity` are rejected. |
| Uploads | Schema-3 validation with jsonschema. Errors name the JSON path and failing keyword, never the value. |
| Response headers | `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, a same-origin Content Security Policy, and `no-store` on API responses |
| HTML reports | Downloaded with a sandbox Content Security Policy |
| Transport | The server speaks plain HTTP. Terminate TLS at a reverse proxy and set `FORWARDED_ALLOW_IPS` to its address. |
| SQLite | Write transactions serialize. Use PostgreSQL for many concurrent users or several API instances. |

[API reference](api.md) · [WebUI](webui.md) · [CI runner](ci.md) · [Reporting](reporting.md) · [Architecture](architecture.md)
