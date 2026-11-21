# PR #3: security review

Security review of [PR #3](https://github.com/jarhu/crab-risk-scan/pull/3) at commit `984f80e`, and the fixes added to the PR.

## Method

Four independent security reviews read the code against the threat model below. Each finding needed file and line evidence. The consolidated list was triaged by a second model for severity, false positives and fix design, and the fixes follow that triage. Codex Astra Max was requested but is not available in this environment.

| Review | Scope |
|---|---|
| Server | API authorization, sessions and tokens, uploads, path and git jobs, worker, WebUI, `compose.yaml` |
| Engines | Engine orchestration, `engines install`, CLI, CI runner, CI templates, scanner image |
| Core | Report parsing, fingerprints, policy and exceptions, every renderer |
| Delivery | GitHub workflows, release pipeline, Dockerfiles, dependency pinning |

Threat model: scanned repositories, imported reports, SBOMs and templates are untrusted. CI hosts hold secrets. The server is multi-user, and low-privilege users or leaked low-scope tokens are attackers. Generated reports are opened by people and ingested by GitHub, GitLab and Azure DevOps.

## Findings and fixes

| ID | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|
| F1 | High | A UNC path in an imported report, a SARIF URI or a server path job was resolved, so Windows opened an SMB connection to the named host and could disclose NTLM credentials. Confirmed: a 21-second connection attempt. | Report paths are checked lexically against the scanned directory, as given and resolved. UNC and device paths are rejected before any file access in reports, SARIF, Checkov, server path jobs and the worker. | `test_reports.NetworkPathTests`, server and worker tests that fail if `realpath` sees a UNC path |
| F2 | Medium | Secret fingerprints ignored the secret value, so an exception for a placeholder also suppressed a real key placed at the same position. | Credential fingerprints carry a 16-bit tag of the flagged line: a new value gives a new fingerprint, while 16 bits cannot confirm a guess. | `test_architecture` credential fingerprint and swapped-secret tests |
| F3 | Low | `help_uri` from imported reports went unencoded into SARIF `help.markdown` and Markdown links: image beacons and table-cell spoofing. | Link targets are percent-encoded for Markdown. | `test_renderers.MarkdownTests.test_help_links_cannot_inject_markdown` |
| F4 | Low | Full line hashes of Bandit hard-coded password findings (B105, B106, B107) verified guessed passwords. | These rules use the credential fingerprint. | Included in the F2 test |
| F5 | Low | The report schema accepted NaN and a trailing newline, so one upload could break a project's report views. | Schema patterns anchor at the true end. JSON inputs and request bodies reject NaN and Infinity. | `test_reports.StrictInputTests`, server upload tests |
| F6 | Low | Custom DOCX templates had no expansion limit and copied external content, such as remote templates or UNC images, into reports. | Expansion and part limits. Macros, embedded objects and non-hyperlink external relationships are rejected. | `test_renderers.DocxTests.test_template_safety_checks` |
| F7 | Medium | Scan uploads were read and parsed before authorization, inside the event loop, so any token holder could exhaust memory. | Authorize first, then parse in the threadpool under a two-slot semaphore. The same applies to job completion. | `test_server` upload tests |
| F8 | Medium | Login throttling was racy (about 40 guesses per window instead of 5), had no per-client limit, and allowed unbounded concurrent scrypt checks. | Attempts are reserved atomically before the check. A per-client bucket. A bounded hashing semaphore that answers 503. Pruning, `admin unlock` and `serve --forwarded-allow-ips`. | `test_server` throttling tests, including 12 parallel logins |
| F9 | High | Git jobs inherited the worker's environment and git credential helpers, followed redirects, ran LFS, reached internal hosts, and returned raw git errors to viewers. | `CRAB_GIT_HOSTS` is default-deny. Git runs with a minimal environment and no system or global config, credentials, redirects, LFS or submodules. Blocked address ranges, DNS pinning, and categorized errors only. | `test_server`, `test_worker` git tests |
| F10 | Medium | `CRAB_SCAN_ROOTS` was shared, so a maintainer could scan another team's checkout into their own project. | An admin-only `scan_path` per project. Non-admin path jobs and schedules must stay inside it. | `test_server`, `test_scheduler`, WebUI `scanPath.test.tsx` |
| F11 | Medium | API tokens survived deactivation or deletion of their creator and the creator's loss of the maintainer role. | Tokens follow the creator: active account, still a maintainer for project tokens, still an admin for global tokens. Deleting the creator deletes the tokens. | `test_server` token tests |
| F12 | Medium | The GitHub Action fell back to the `latest` image when pinned by commit SHA. | The default is the release version. Tags may carry a digest. | `test_delivery` |
| F13 | Medium | Any `v*` tag on any commit published images with no approval. | A `release` environment on the images job, plus a check that the tagged commit is on `main`. Required repository settings are documented. | `test_delivery` |
| F14 | Medium | Build and install inputs were unhashed: pip engines, image dependencies, Node, Postgres, BuildKit and binfmt images, and setuptools. | Hash-locked requirement files for the pip engines and both images. Digest-pinned images. Pinned setuptools. | `test_engines` lock and install tests, `test_delivery` |
| F15 | Medium | The GitHub Action and Azure template mounted the workspace and `$RUNNER_TEMP` read-write into the scanning container. | Read-only source, only outputs and cache writable, `--cap-drop ALL` and `no-new-privileges`. | `test_delivery` |
| F16 | Medium | The GitLab template trusted a `.crab-cache` committed to the repository as the vulnerability database. | Tracked or symlinked caches are refused. Only protected branches push the cache. | `test_delivery` |
| F17 | Low | `.env` secrets and `scan/` could enter the scanner image build context. | Ignore files updated. The image copies only package sources. | `test_delivery` |
| F18 | Medium | Offline scans ran Checkov's Helm framework, which downloads chart dependencies and writes them into the target. | Helm charts are scanned only with `--online`. | `test_engines.CommandTests.test_checkov_helm_framework_only_online` |
| F19 | Low | `engines install` ran `python -m venv` and `-m pip` with the working directory on `sys.path`. | `python -I` with a private working directory. | `test_engines.PipInstallTests` |
| F20 | Low | The runner sent the bearer token to `http://` servers and only warned afterwards. | Plain HTTP is refused before sending, except for loopback addresses. | `test_runner` |
| F21 | Low | `--engine-timeout` applied per command, so ShellCheck batches could run for batches × timeout. | One deadline per engine. | `test_engines.DeadlineTests` |
| F22 | Low | The scanner image's database cache was world-writable. | Owned by uid 10001 with mode 0755. Templates mount their own cache. | `test_delivery` |
| F23 | Medium | Found while fixing F4: Checkov `secrets` results carry the secret's SHA-1 as their resource, which CRAB copied into reports and fingerprints. | Checkov secret results become `secrets` findings without the resource. | `test_architecture.test_checkov_secret_results_drop_the_secret_hash` |

Hardening:
- OpenAPI docs are served only with `CRAB_API_DOCS=1`.
- `page` is bounded.
- Each project may have at most 50 schedules and 100 queued jobs.
- The docs state that worker tokens are instance-wide credentials.

## Verification

All on Windows 11 with Python 3.14, after the fixes:

- **Test suite:** `python -m unittest discover -s tests` ran 270 tests and passed. Three were skipped: the Mojo grammar is not built here, and creating symlinks needs a privilege this account lacks (two tests). The real scanners were installed, so the live engine tests ran too.
- **WebUI:** `npm run typecheck`, `npm test` (24 tests) and `npm run build` all pass. `npm audit` reports 0 vulnerabilities.
- **Live server:** 14 of 14 checks passed against a running server:
  - API docs disabled.
  - `scan_path` isolation, and maintainers cannot change it.
  - A UNC path job rejected in 0.01 s.
  - Git jobs denied by default.
  - A token revoked when its creator is deactivated.
  - An unauthorized upload refused before parsing.
  - NaN rejected.
  - Exactly 5 of 12 parallel bad logins reached the password check.
  - An oversized `page` returns 422.
- **Hash-locked installs:**
  - `engines install --engine bandit` installed from the locked wheels.
  - The Checkov lock installed with `--require-hashes` and passed `pip check`.
  - Both image requirement files installed with `--require-hashes` on Python 3.13, followed by `--no-build-isolation` installs of CRAB that scanned and rendered successfully.

## Residual risks

| Risk | Detail |
|---|---|
| Docker | The Dockerfiles, `compose.yaml` and the container hardening of the CI templates were not built or run, because Docker is not installed on the development host. |
| Git pinning | `http.curloptResolve` needs git 2.37 or later, and the worker tests mock git. Use the `CRAB_GIT_HOSTS` allow-list and an egress firewall for workers. |
| PostgreSQL | The row-lock path of login throttling was exercised on SQLite only. |
| Engine sandbox | Engines run with a restricted environment, a private working directory and time limits, but without a file system or network sandbox. Use the container image with `--network none` for strong isolation. |
| Account lockout | Per-account lockout can still be triggered on purpose. Administrators recover with `crab-risk-scan admin unlock`. |
| Worker tokens | A worker token can claim any project's job. Treat it as an instance-wide credential. |
| Baselines | `--new-since` gates trust the base report. Take it from a protected branch artifact. |

[Delivery report](PR_3_readme.md) · [Gap analysis](../gap-analysis.md) · [Server](../server.md) · [CI](../ci.md) · [Integrations](../integrations.md)
