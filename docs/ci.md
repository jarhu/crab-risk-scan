# CI runner

`crab-risk-scan ci` runs the same scan as `scan`, writes a fixed artifact folder and reports the result through the CI platform. It exits with the policy result. The runner works offline. Connected mode adds an upload to a CRAB server.

```sh
crab-risk-scan ci . --policy .crab/policy.json --exceptions .crab/exceptions.json --sbom
```

## Usage

`ci` accepts every `scan` flag: engine selection, saved-report imports, `--policy`, `--exceptions`, `--fail-on`, `--new-since`, `--epss`, `--kev`, `--cache-dir`, `--engine-path`, `--sbom` and the rest. Run `crab-risk-scan ci --help` for the full list. The runner adds these flags:

| Flag | Default | Effect |
|---|---|---|
| `--output-dir DIR` | `crab-results` | Artifact folder |
| `--server URL` | none | CRAB server base URL. Enables connected mode and requires `--project`. Must use `https`, except for a loopback address, because the bearer token would otherwise cross the network unencrypted. |
| `--project KEY` | none | Server project that receives the scan |
| `--token TOKEN` | `CRAB_TOKEN` | API token with the `scan:upload` scope. Prefer the environment variable, because command lines appear in process listings. |
| `--annotations N` | 50 | Maximum number of unsuppressed findings shown as annotations or console lines |
| `--no-fail` | off | Exit 0 when the policy fails. Incomplete scans still exit 2. |
| `--require-upload` | off | Exit 2 when the upload fails. Without it, an upload failure is a warning. |
| `--format vex\|docx` | none | Also write `report.vex.json` or `report.docx` into the folder |
| `--output FILE` | none | Write an additional report file. The format follows the file name. |
| `--template NAME` | technical | `technical`, `executive` or a `.docx` file for the Markdown, HTML and DOCX reports |

Install CRAB in a trusted environment and run the installed command from outside the target checkout's import path. The scanner image does this for you.

## Artifacts

| File | Content |
|---|---|
| `report.json` | Schema-3 report |
| `report.sarif` | SARIF 2.1.0 for GitHub code scanning, GitLab Ultimate and Azure DevOps |
| `report.md` | Markdown report, also used as the job summary |
| `report.html` | Standalone HTML report |
| `report.csv` | One row per finding |
| `gl-code-quality-report.json` | GitLab Code Quality report |
| `sbom.cdx.json` | CycloneDX SBOM, with `--sbom` |
| `crab-run.json` | Run record: platform, run URL, start and finish times, outputs, scan and final exit status, policy summary, severity counts and upload result |

`crab-run.json` never contains the token. A scan that produced no report still writes `crab-run.json` with `scan_error`.

## Platform detection

The runner fills `--revision`, `--branch` and `--repository` from the platform when they are not given. Values that fail validation are dropped. Credentials embedded in repository URLs are removed.

| Platform | Detected by | Revision | Branch | Repository | Run URL |
|---|---|---|---|---|---|
| GitHub Actions | `GITHUB_ACTIONS=true` | `GITHUB_SHA` | `GITHUB_HEAD_REF`, else the branch in `GITHUB_REF` | `GITHUB_SERVER_URL/GITHUB_REPOSITORY` | `.../actions/runs/GITHUB_RUN_ID/attempts/GITHUB_RUN_ATTEMPT` |
| GitLab CI | `GITLAB_CI=true` | `CI_COMMIT_SHA` | `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`, else `CI_COMMIT_BRANCH` | `CI_PROJECT_URL` | `CI_PIPELINE_URL` |
| Azure Pipelines | `TF_BUILD=True` | `BUILD_SOURCEVERSION` | `SYSTEM_PULLREQUEST_SOURCEBRANCH`, else `BUILD_SOURCEBRANCH` | `BUILD_REPOSITORY_URI` | `SYSTEM_COLLECTIONURI/SYSTEM_TEAMPROJECT/_build/results?buildId=BUILD_BUILDID` |
| Jenkins | `JENKINS_URL` | `GIT_COMMIT` | `CHANGE_BRANCH`, `BRANCH_NAME`, else `GIT_BRANCH` without `origin/` | `GIT_URL` (http and https only) | `BUILD_URL` |

Tag pipelines have no branch. When several variables are present, the order of the table decides.

## Platform output

| Platform | Output |
|---|---|
| GitHub Actions | `report.md` appended to `GITHUB_STEP_SUMMARY` (a compact summary when it exceeds the 1 MiB limit). `::error`, `::warning` and `::notice` annotations for critical and high, medium, and other findings. Outputs in `GITHUB_OUTPUT`. |
| Azure Pipelines | `##vso[task.logissue]` errors for critical and high findings, warnings for the rest. `##vso[task.uploadsummary]` with `report.md`. |
| GitLab CI | Console summary with the top findings. Code Quality and SARIF artifacts through the template. |
| Jenkins and local runs | Console summary with the top findings |

Annotation paths are relative to the checkout root (`GITHUB_WORKSPACE`, `BUILD_SOURCESDIRECTORY`), so subdirectory scans annotate the right files. Annotation data and properties are escaped, so file names and messages cannot inject workflow or logging commands. Console text has control characters replaced.

GitHub outputs: `exit-code`, `passed`, `actionable`, `suppressed`, `findings`, `errors`, one count per severity (`critical` ... `unknown`, unsuppressed only), `results-dir`, `json`, `sarif`, `markdown`, `html`, `csv`, `codequality`, `sbom`, `run`, `upload-status` (`uploaded`, `failed` or `not_configured`) and `scan-url`.

## Exit status

| Status | Meaning |
|---|---|
| 0 | Policy passed, or the policy failed with `--no-fail` |
| 1 | Policy failed |
| 2 | Incomplete: the report has errors, artifacts could not be written, the scan could not run, a usage error, or an upload failure with `--require-upload` |

Exit 2 takes precedence. `--no-fail` never hides an incomplete scan.

## Trusted baselines

`--new-since` compares the scan with a baseline report. Policies with `new_only` gates fail only on findings that are not in the baseline, so the baseline decides what the gate ignores. A baseline from the scanned branch, a pull request or the checkout itself lets the code under review hide its own findings.

| Rule | Why |
|---|---|
| Take the baseline from a protected branch, for example a workflow artifact of the last `main` run | Only reviewed code produced it |
| Never read the baseline from the checked-out tree of a pull request | The author controls that file |
| Download it in a step the pull request cannot change, with a token limited to reading artifacts | The download step is part of the trust boundary |

## Standalone and connected modes

Standalone mode is the default. The scan runs offline and nothing leaves the job except the artifacts the CI system stores.

Connected mode sends `POST /api/v1/projects/{key}/scans` to the server with the report, the SBOM when generated, `source: runner` and the platform and run URL. See the [API reference](api.md).

| Rule | Behaviour |
|---|---|
| Token | `--token` or `CRAB_TOKEN`, sent only as `Authorization: Bearer`. Never printed or recorded. |
| Redirects | Not followed, so the token cannot be forwarded to another location |
| Plain HTTP | Allowed. A warning is printed unless the host is a loopback address. |
| Size | The report and SBOM are limited to 32 MiB each, matching the server |
| Failure | A warning on stderr and in the platform's warning channel. `--require-upload` turns it into exit 2. |
| Record | `crab-run.json` `upload`: `status`, `http_status`, `scan_id`, `url`, `reason` and the server's `detail` |

Create a project token with the `scan:upload` scope in the WebUI project settings and store it as a CI secret.

## Scanner image

`deployments/docker/scanner.Dockerfile` builds `ghcr.io/jarhu/crab-risk-scan`. The release workflow publishes it for `linux/amd64` and `linux/arm64` with build provenance and an SBOM.

| Property | Value |
|---|---|
| Base | `python:3.13-slim`, pinned by digest. Dockerfile frontend `docker/dockerfile:1.7`, pinned by digest. |
| Python dependencies | Hash-locked in `deployments/docker/requirements-scanner.txt`, installed with `pip install --require-hashes --no-deps`. CRAB itself is installed with `--no-deps --no-build-isolation`. |
| Engines | `crab-risk-scan engines install --dest /opt/crab/engines`, checksum-verified. `CRAB_ENGINE_DIR=/opt/crab/engines/bin`. |
| Databases | `CRAB_CACHE_DIR=/opt/crab/cache`, owned by uid 10001, mode 0755. Other uids can read but not write it. |
| User | `crab`, uid and gid 10001. Runs under any uid; other uids need their own cache directory. |
| Build context | Only `pyproject.toml`, `LICENSE`, `README.md`, `crab_risk_scan/` and the requirement file are copied. `.dockerignore` also excludes `.env` files, `scan/` and `.crab-cache`. |
| Entrypoint | `crab-risk-scan`, working directory `/work` |

| Build argument | Default | Effect |
|---|---|---|
| `INSTALL_PWSH` | `false` | Install PowerShell 7.6 LTS (checksum-pinned) so the PSScriptAnalyzer engine runs. The published image sets it to `true`. |
| `PREFETCH_DB` | `false` | Run `crab-risk-scan db update` during the build so scans work offline without a cache volume |
| `PYTHON_IMAGE` | pinned digest | Alternative base image |

```sh
docker build -f deployments/docker/scanner.Dockerfile --build-arg INSTALL_PWSH=true -t crab-risk-scan .
mkdir -p "$HOME/crab-results" "$HOME/crab-cache"
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/work:ro" -v "$HOME/crab-results:/out" -v "$HOME/crab-cache:/cache" \
  crab-risk-scan ci . --output-dir /out --cache-dir /cache
```

The CI templates run the container under the host uid so results stay writable. They therefore mount their own cache directory. A database prefetched into the image (`PREFETCH_DB=true`) is used only when the container runs as uid 10001, for example in the GitLab template.

### Hash-locked image requirements

The server image uses `deployments/docker/requirements-server.txt` (server, DOCX and PostgreSQL extras), the scanner image `requirements-scanner.txt` (DOCX extra). Both include `setuptools` from `deployments/docker/build-requirements.in`, which must equal the `[build-system]` pin in `pyproject.toml`. The files are universal: one set of hashes covers `linux/amd64` and `linux/arm64`. Regenerate them after any dependency change, with `uv` installed in a throwaway virtual environment outside the repository:

```sh
python -m venv /tmp/uv-venv && /tmp/uv-venv/bin/pip install uv
for spec in "scanner --extra docx" "server --extra server --extra docx --extra postgres"; do
  set -- $spec; name=$1; shift
  /tmp/uv-venv/bin/uv pip compile pyproject.toml deployments/docker/build-requirements.in "$@" \
    --universal --python-version 3.13 --generate-hashes \
    --custom-compile-command "see docs/ci.md (Hash-locked image requirements)" \
    -o "deployments/docker/requirements-$name.txt"
done
rm -rf /tmp/uv-venv
```

### Pinned image inputs

| Input | Where |
|---|---|
| `python:3.13-slim`, `node:24-slim`, `docker/dockerfile:1.7` | `PYTHON_IMAGE`, `NODE_IMAGE` and `# syntax=` in both Dockerfiles |
| `postgres:17-alpine` | `compose.yaml` |
| `tonistiigi/binfmt`, `moby/buildkit` | `setup-qemu-action` `image` and `setup-buildx-action` `driver-opts` in `release.yml` |

All are pinned to the multi-arch index digest. To update one, read the digest from the registry, for example `docker buildx imagetools inspect node:24-slim`, and replace tag and digest together. `tests/test_delivery.py` fails on an unpinned image.

### Verifying published images

Pin the image by digest and verify its provenance before use:

```sh
gh attestation verify oci://ghcr.io/jarhu/crab-risk-scan:0.3.0 --repo jarhu/crab-risk-scan
docker buildx imagetools inspect ghcr.io/jarhu/crab-risk-scan:0.3.0 --format '{{json .Manifest.Digest}}'
```

Use the verified digest as `ghcr.io/jarhu/crab-risk-scan:0.3.0@sha256:...` in `image-tag` (GitHub, as `0.3.0@sha256:...`), `image` (Azure), `CRAB_IMAGE` (GitLab, Jenkins) or the pre-commit `entry`.

### Release settings

The release workflow publishes only tags whose commit is an ancestor of `origin/main`. It also needs these repository settings:

| Setting | Value |
|---|---|
| Environment `pypi` | Required reviewers. Deployment tag rule `v*`. |
| Environment `release` | Required reviewers. Deployment tag rule `v*`. Gates the image publication. |
| Tag ruleset | Restrict creation, update and deletion of `v*` tags to maintainers |
| PyPI | Trusted publisher for this repository, workflow `release.yml`, environment `pypi` |

## GitHub Actions

`integrations/github-actions/action.yml` runs the scanner image, uploads SARIF to code scanning, uploads the results folder and then enforces the policy. The scan step runs with `--network none` unless `server-url` is set.

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  crab:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: actions/cache@v6
        with:
          path: ${{ runner.temp }}/crab-cache
          key: crab-db-${{ github.run_id }}
          restore-keys: crab-db-
      - uses: jarhu/crab-risk-scan/integrations/github-actions@v0.3.0
        with:
          policy: .crab/policy.json
          exceptions: .crab/exceptions.json
          sbom: "true"
          cache-dir: crab-cache
          update-db: "true"
          server-url: https://crab.example.com
          project: demo-service
          token: ${{ secrets.CRAB_TOKEN }}
```

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | Directory to scan |
| `engines`, `fail-on`, `policy`, `exceptions`, `new-since`, `sbom` | scan defaults | Passed to `ci` |
| `annotations` | 50 | Annotation limit |
| `no-fail` | `false` | Pass the job when the policy fails |
| `output-dir` | `$RUNNER_TEMP/crab-results` | Results folder |
| `cache-dir`, `update-db` | none, `false` | Database cache outside the workspace. Relative paths resolve against `$RUNNER_TEMP`. |
| `upload-sarif`, `sarif-category` | `true`, `crab-risk-scan` | Code scanning upload. Needs `security-events: write`. |
| `artifact-name` | `crab-results` | Workflow artifact. Empty disables it. |
| `server-url`, `project`, `token`, `require-upload` | none | Connected mode |
| `image`, `image-tag` | `ghcr.io/jarhu/crab-risk-scan`, `0.3.0` (the release version) | Scanner image. `image-tag` accepts `TAG` or `TAG@sha256:DIGEST`. |
| `args` | none | Extra `ci` arguments, split on spaces |

`persist-credentials: false` keeps the checkout token out of `.git/config`, where the scanned tree and its engines could read it. When you pin the action by commit SHA, the image tag still defaults to the release version of that commit, never `latest`. Pin `image-tag` with a digest for immutable runs.

The container gets the workspace read-only. Only the results folder, the cache directory and the `GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY` files are writable, and it runs with `--cap-drop ALL` and `no-new-privileges`. Policy, exception and baseline paths must be inside the workspace. Code scanning resolves SARIF locations against the repository root, so scan the repository root when you rely on code scanning alerts. Annotations handle subdirectories.

## GitLab CI

Include `integrations/gitlab-ci/crab.gitlab-ci.yml` and override its variables.

```yaml
include:
  - remote: https://raw.githubusercontent.com/jarhu/crab-risk-scan/v0.3.0/integrations/gitlab-ci/crab.gitlab-ci.yml
variables:
  CRAB_POLICY: .crab/policy.json
  CRAB_EXCEPTIONS: .crab/exceptions.json
  CRAB_UPDATE_DB: "true"
```

| Job | Behaviour |
|---|---|
| `crab-scan` | Runs `ci --no-fail` and always exits 0 when a report exists. Publishes `artifacts:reports:codequality` and `artifacts:reports:sarif` plus the results folder. |
| `crab-gate` | Runs `crab-risk-scan gate crab-results/report.json` with the same policy and exceptions. Fails the pipeline on exit 1 or 2. |

| Tier | Result |
|---|---|
| Free and Premium | The Code Quality report appears in merge request widgets and the pipeline. The SARIF report is stored as a job artifact only. |
| Ultimate | The SARIF report also feeds the Security tab, the vulnerability report and security policies (GitLab 18.11 and later). GitLab ingests SARIF only from a job that succeeds, which is why the scan and the gate are separate jobs. |

Set `CRAB_TOKEN` as a masked CI/CD variable and `CRAB_SERVER_URL` and `CRAB_PROJECT` for connected mode. The scanner image runs as uid 10001. The GitLab Docker executor's default umask makes the checkout writable for it.

The cache key includes `CI_COMMIT_REF_PROTECTED`. Only branch pipelines on protected branches push the cache (`policy: pull-push`); merge request, unprotected and tag pipelines only pull it. `crab-scan` refuses to run when `CRAB_CACHE_DIR` is a symlink, is tracked by git or is not a directory, because the scanned repository would then supply the vulnerability databases.

## Azure Pipelines

`integrations/azure-devops/crab-scan.yml` is a steps template for Linux agents with Docker.

```yaml
resources:
  repositories:
    - repository: crab
      type: github
      name: jarhu/crab-risk-scan
      ref: refs/tags/v0.3.0
      endpoint: github-connection
steps:
  - checkout: self
  - task: Cache@2
    inputs:
      key: crab-db | "$(Agent.OS)"
      path: $(Pipeline.Workspace)/crab-cache
  - template: integrations/azure-devops/crab-scan.yml@crab
    parameters:
      policy: .crab/policy.json
      cacheDir: crab-cache
      updateDb: true
```

The scan step publishes `report.sarif` as the `CodeAnalysisLogs` build artifact, which the SARIF SAST Scans Tab extension displays, and the full folder as the `crab-results` pipeline artifact. The gate step runs `crab-risk-scan gate`. Set `gate: false` to skip it. Relative `cacheDir` paths resolve against `$(Pipeline.Workspace)`; without `cacheDir` the step uses an empty cache in `$(Agent.TempDirectory)`. The sources are mounted read-only; only the results folder and the cache are writable. For connected mode, set `serverUrl` and `project` and define the secret variable named by `tokenVariable` (default `CRAB_TOKEN`).

## Jenkins

`integrations/jenkins/Jenkinsfile` needs the Docker Pipeline plugin and a Linux agent with Docker. The scan stage removes any stale results folder, runs `ci --no-fail`, archives the folder and records the SARIF findings with the Warnings Next Generation plugin. The gate stage runs `crab-risk-scan gate`. The console shows the runner summary. An empty `CRAB_CACHE_DIR` uses `$WORKSPACE_TMP/crab-cache`. For connected mode, set `CRAB_SERVER_URL` and `CRAB_PROJECT` and store the token as a Secret text credential named by `CRAB_TOKEN_CREDENTIAL`.

## pre-commit

`.pre-commit-hooks.yaml` provides two hooks. Both scan the whole working tree and print the Markdown report.

| Hook | Runs |
|---|---|
| `crab-risk-scan` | The Python package with the engines installed on the developer machine |
| `crab-risk-scan-docker` | The scanner image with its pinned engines |

```yaml
repos:
  - repo: https://github.com/jarhu/crab-risk-scan
    rev: v0.3.0
    hooks:
      - id: crab-risk-scan-docker
        args: [., --fail-on, high]
```

## Offline databases in CI

Trivy and OSV-Scanner read local databases. `crab-risk-scan db update` is the only networked step. Choose one approach:

| Approach | How |
|---|---|
| Prefetched image | Build with `PREFETCH_DB=true` and rebuild on a schedule. Scans need no cache and no network. |
| CI cache | Restore a cache directory, run `db update` into it with network access, then scan offline with `--cache-dir`. The templates do this with `update-db`, `CRAB_UPDATE_DB` and `updateDb`. |
| Air-gapped | Run `db update` on a connected host, copy the cache directory into the CI environment and pass `--cache-dir` or set `CRAB_CACHE_DIR` |

The cache must be outside the scanned directory. CRAB refuses a cache inside the target, because the target would control the vulnerability databases. GitLab caches only paths inside the checkout, so its template moves `.crab-cache` to `/tmp/crab-cache` for the scan and back afterwards, after checking that the folder is neither tracked nor a symlink. Keep GitLab's default of separate caches for protected and unprotected branches.

The results folder is written after the scan. In persistent workspaces, delete an old results folder before scanning or keep it outside the target.

[Architecture](architecture.md) · [Reports](reporting.md) · [Scanner integrations](integrations.md) · [Roadmap](roadmap.md) · [GitHub workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands) · [Azure logging commands](https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands) · [GitLab SARIF reports](https://docs.gitlab.com/user/application_security/detect/sarif/) · [GitLab Code Quality](https://docs.gitlab.com/ci/testing/code_quality.html)
