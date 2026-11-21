# Scanner integrations and policy

`crab-risk-scan scan DIRECTORY` runs the built-in rules, runs the installed engines that apply to the snapshot, imports saved reports and evaluates the policy. It writes one schema-3 report. Every engine and import appears in `imports` with its origin, status, version and rule pack.

```sh
crab-risk-scan engines install --dest /opt/crab/engines      # pinned engines, SHA-256 verified
export CRAB_ENGINE_DIR=/opt/crab/engines/bin
crab-risk-scan db update                                      # the only networked step
crab-risk-scan scan "$TARGET" --sbom --output-dir results --policy policy.json --exceptions exceptions.json
crab-risk-scan scan "$TARGET" --engines none --bandit bandit.json --sarif codeql.sarif   # imports only
```

## Engine selection

| `--engines` | Behaviour |
|---|---|
| `auto` (default) | Runs installed engines whose file types are present. A missing engine is recorded as `skipped` with reason `not_installed`. |
| `all` | Same selection. A missing engine is recorded as `failed`, which makes the exit status 2. |
| `none` | Built-in rules and saved-report imports only. |
| `NAME[,NAME]` | Runs only the named engines. A missing engine is `failed`. `trivy-image` requires `--image`. |

An engine without matching files is `skipped` with reason `not_applicable` in every mode.

| Status | Meaning | Reasons |
|---|---|---|
| `complete` | The engine finished and its report was imported | |
| `partial` | The engine or its report flagged unparsed files. Findings are kept. The report lists a `producer_partial` error. | |
| `failed` | No usable report. The report lists a `producer_failed` or `invalid_report` error. | `not_installed`, `invalid_engine_path`, `exit_status`, `timeout`, `launch_failed`, `missing_report`, `invalid_report`, `database_missing`, `cache_inside_target`, `work_dir_inside_target` |
| `skipped` | The engine did not run, and no error is recorded | `not_applicable`, `not_installed` (auto), `no_packages` (OSV exit 128) |

## Engines

| Engine | Producer | Pinned | Runs when the target has | Offline and isolation flags | Exit status classification |
|---|---|---|---|---|---|
| opengrep | opengrep | 2.0.0 | Files in the languages of the packaged `opengrep-v1.yml` pack | `--no-git-ignore`, `--disable-nosem`, `--x-ignore-semgrepignore-files`. The pack is copied into the private cwd. | 0 complete, any other value failed |
| bandit | bandit | 1.9.4 | `.py`, `.pyw` | `--ini` with an empty private file (ignores the target `.bandit`), `--ignore-nosec` | 0 or 1 complete, other failed |
| gitleaks | gitleaks | 8.28.0 | Any file | `dir` mode, `--redact`, `--config` with a private `[extend] useDefault = true` file (ignores the target `.gitleaks.toml`), `--ignore-gitleaks-allow`, `--exit-code 99` | 0 or 99 complete, other failed |
| checkov | checkov | 3.2.495 | Terraform, Bicep, Dockerfile, GitHub Actions, YAML or JSON; Helm charts only with `--online` | `--directory=DIR` as one token plus an empty private `--config-file`, so Checkov does not load the target `.checkov.yaml`. Also `--skip-download`, `--skip-results-upload`, `--download-external-modules false`, `--compact`, `--soft-fail`, and `--framework` limited to the file types present. The `helm` framework runs `helm template --dependency-update`, which downloads chart dependencies and writes them into the target, so it is selected only with `--online`. | 0 complete, other failed |
| shellcheck | shellcheck | 0.11.0 | `.sh`, `.bash`, `.ksh`, `.bats` | `--norc`, explicit file list in batches of 200, no `-x` | 0 or 1 complete, 2 partial, other failed |
| psscriptanalyzer | psscriptanalyzer | 1.24.0 (module) | `.ps1`, `.psm1`, `.psd1` | `pwsh -NoProfile -NonInteractive` runs the packaged [`engines/psscriptanalyzer.ps1`](../crab_risk_scan/engines/psscriptanalyzer.ps1) with explicit settings (ignores the target `PSScriptAnalyzerSettings.psd1`) | 0 complete, other failed |
| trivy | trivy | 0.76.2 | A lockfile or manifest | `filesystem --scanners vuln --pkg-types library --skip-db-update --skip-java-db-update --offline-scan --skip-version-check --disable-telemetry --cache-dir CACHE/trivy`, empty private `--config` and `--ignorefile` | 0 complete, other failed |
| trivy-image | trivy-image | 0.76.2 | `--image REF` | `image --pkg-types os,library` with the same offline flags plus `--image-src docker,containerd,podman` (no registry pulls) | 0 complete, other failed |
| osv-scanner | osv | 2.7.1 | A lockfile or manifest | `scan source --recursive --offline-vulnerabilities --no-resolve`, empty private `--config` (ignores the target `osv-scanner.toml`), `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=CACHE/osv` | 0 to 126 complete, 128 skipped (no packages), other failed |
| syft | (inventory) | 1.32.0 | `--sbom`, or a `.cdx.json` or `.spdx.json` output | `--source-name` set to the folder name, `SYFT_CHECK_FOR_APP_UPDATE=false` | 0 complete, other failed |

`--online` drops the Trivy offline flags, drops the OSV `--offline-vulnerabilities --no-resolve` flags and passes proxy variables through. Rule packs are recorded per engine. Trivy records the database date as `trivy-db@YYYY-MM-DD`.

Every engine run uses these controls:

| Control | Implementation |
|---|---|
| Executable | Found through `--engine-path NAME=/abs/path`, then `CRAB_ENGINE_DIR`, then absolute `PATH` entries. An executable inside the scanned directory is always rejected. On Windows only `.exe` files are accepted. |
| Environment | Allow-list of system variables. `PATH` loses relative entries and entries inside the target. `HOME`, `USERPROFILE`, `XDG_*`, `APPDATA`, `LOCALAPPDATA`, `TMP` and `TEMP` point into a private directory. Telemetry and update checks are off. |
| Working directory | A fresh private directory outside the target, so engines never load configuration from the target as their cwd |
| Input and output | stdin is closed. stderr is discarded because diagnostics can quote source. Reports are written to the private directory. |
| Limits | `--engine-timeout` (default 900 seconds) is one deadline for all of an engine's commands, including ShellCheck batches. Expiry kills the process tree. On POSIX, CPU time, core dumps (0) and file size (4 GiB) are also limited. |

`crab-risk-scan engines` lists each engine with its pinned version, resolved path, detected version and status (`ok`, `version_mismatch`, `not_installed`). `--json` prints the same records.

## Installing engines

`crab-risk-scan engines install --dest DIR [--engine NAME ...] [--platform PLATFORM]` reads [`engines.lock.json`](../crab_risk_scan/engines.lock.json).

| Install type | Engines | Result |
|---|---|---|
| download | opengrep, gitleaks, shellcheck, trivy, osv-scanner, syft | Release asset downloaded with urllib and checked against the locked SHA-256 before use. Archives are extracted member by member. Absolute paths, `..`, drive letters and links are rejected. Executables go to `DIR/bin`. |
| pip | bandit, checkov | A venv per engine in `DIR/venvs/<engine>` with a shim in `DIR/bin`. Packages come from the hash-locked requirement file named in the lock file ([`engines/`](../crab_risk_scan/engines)), installed with `--require-hashes --no-deps --only-binary :all:`. `python -I` and a private working directory keep the current directory off `sys.path`. Shims are a `#!/bin/sh` exec script on POSIX and a console launcher on Windows. |
| module | psscriptanalyzer | Nupkg verified and extracted to `DIR/modules/PSScriptAnalyzer/1.24.0`. Scans add `CRAB_ENGINE_DIR/../modules` to `PSModulePath`. PowerShell 7 (`pwsh`) must be installed separately. |

Platforms: `linux-x86_64`, `linux-aarch64`, `darwin-x86_64`, `darwin-arm64`, `windows-x86_64`. Digests come from the GitHub release asset `digest` metadata. The PSScriptAnalyzer nupkg has no GitHub digest. Its SHA-256 was recorded after the file matched the PowerShell Gallery SHA-512 package hash.

Pip engine requirement files pin every transitive dependency with SHA-256 hashes for all published wheels, so one file serves every platform and Python 3.11 or newer. To update an engine, change its `version` and `package` in the lock file, then regenerate its file from a one-line input holding the package pin:

```sh
uv pip compile --universal --generate-hashes --python-version 3.11 --only-binary :all: --no-header checkov.in \
  -o crab_risk_scan/engines/checkov-requirements.txt
```

## Offline databases

`crab-risk-scan db update [--cache-dir DIR] [DIRECTORY]` is the only networked step. The cache defaults to `CRAB_CACHE_DIR`, otherwise to the platform user cache folder (`%LOCALAPPDATA%\crab-risk-scan`, `~/Library/Caches/crab-risk-scan` or `$XDG_CACHE_HOME/crab-risk-scan`).

| Database | Location | Source |
|---|---|---|
| Trivy vulnerability and Java index | `CACHE/trivy/db`, `CACHE/trivy/java-db` | `trivy image --download-db-only` and `--download-java-db-only` |
| OSV per ecosystem | `CACHE/osv/osv-scalibr/<ecosystem>/all.zip` | `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` |

With DIRECTORY, OSV downloads only the ecosystems whose lockfiles are present. Without it, the defaults are npm, PyPI, crates.io, Go, Maven, NuGet, RubyGems, Packagist, Pub and Hex. Copy the cache folder to air-gapped hosts. An offline scan without the needed database records the engine as `failed` with reason `database_missing`. The cache must not be inside the scanned directory.

## Saved-report imports

Flags are repeatable and keep their command-line order. Imports have origin `report` and status `imported` unless the report exposes a problem. Keep report files outside the scanned directory.

Paths in imported reports are checked without touching the file system. An absolute path must lie inside the scanned directory, as given or fully resolved, and is turned into a relative path. UNC and device paths (`\\server\share`, `//server/share`, `\\?\`, `\\.\`) are rejected before any file access, because opening one makes Windows authenticate to the named host. NaN and Infinity constants in any JSON input are rejected.

| Flag | Expected producer output | Notes |
|---|---|---|
| `--bandit` | Bandit JSON with results and errors | Keeps test_id, confidence and byte extent |
| `--opengrep` | Opengrep native JSON with version, results and errors | Use the packaged pack (`crab-risk-scan rules`) or a trusted external pack |
| `--osv` | OSV-Scanner JSON with lockfile sources | Keeps advisory IDs and aliases |
| `--trivy` | Trivy schema 2 filesystem JSON with language-package results | Use `--scanners vuln --pkg-types library` |
| `--trivy-image` | Trivy schema 2 `container_image` JSON | Requires one manifest digest in `Metadata.RepoDigests` |
| `--gitleaks` | Gitleaks v8 JSON array | Secret values, matches and commit metadata are discarded |
| `--checkov` | Checkov JSON block or array of framework blocks | Imports failed_checks and flags parsing errors |
| `--shellcheck` | ShellCheck JSON array | Imports a security-relevant subset |
| `--psscriptanalyzer` | JSON from the packaged exporter | `pwsh -NoProfile -File "$(dirname "$(crab-risk-scan rules)")/engines/psscriptanalyzer.ps1" "$TARGET" ps.json` |
| `--sarif` | SARIF 2.1.0 from any producer | Normalized into findings by rule ID, level and location |

A malformed or out-of-scope report produces an `invalid_report` error for that input and keeps results from the others.

## Run manifest

`--run-manifest run.json` lists reports produced elsewhere (schema: [run-manifest-v1](../crab_risk_scan/schemas/run-manifest-v1.schema.json)). Files are relative to the manifest folder. Status is complete, partial or failed. A failed producer can be listed without a file. Inputs from the manifest have origin `manifest`.

```json
{"version": 1, "revision": "example-commit", "reports": [
  {"producer": "bandit", "version": "1.9.4", "rule_pack": "bandit-default", "status": "complete", "file": "bandit.json"},
  {"producer": "opengrep", "version": "2.0.0", "rule_pack": "crab-opengrep-v1", "status": "complete", "file": "opengrep.json"}
]}
```

## Policy, exceptions and gates

| File | Schema | Purpose |
|---|---|---|
| `--policy` | [policy-v1](../crab_risk_scan/schemas/policy-v1.schema.json) | Severity threshold, gates (secrets, malicious, KEV, EPSS, licenses, counts), new-only mode, disabled rules, severity overrides, license allow and deny lists |
| `--exceptions` | [exceptions-v2](../crab_risk_scan/schemas/exceptions-v2.schema.json) | Per-fingerprint `accepted`, `false_positive` or `not_affected` status with reviewer, reason, optional expiry and ticket |
| `--epss`, `--kev` | Offline EPSS CSV (optionally gzip) and CISA KEV JSON | Enrichment that drives the `epss` and `kev` gates |
| `--new-since` | A previous schema-3 report | Marks new and fixed findings |

`--fail-on LEVEL|none` overrides the policy threshold. Without a policy file every unsuppressed finding fails. `crab-risk-scan gate REPORT.json [--policy ...]` re-evaluates a saved report and prints the policy result. Exit status is 2 when the report has errors, 1 when the policy fails and 0 otherwise.

## Outputs and SBOMs

`--output FILE` is repeatable, and the format follows the file name. `--output-dir DIR` writes `report.json`, `report.sarif`, `report.md`, `report.html` and `report.csv`, plus `sbom.cdx.json` with `--sbom`. Without either flag, `--format` (default json) goes to stdout. A `.cdx.json` or `.spdx.json` output triggers Syft. One Syft run emits every requested format, and the CycloneDX document becomes the report inventory. `crab-risk-scan report REPORT.json --output FILE` re-renders a saved report. `crab-risk-scan sbom DIRECTORY [--format cyclonedx-json|spdx-json]` writes one inventory.

## Pinch parsers

Install `python -m pip install '.[pinch]'` from the trusted scanner checkout. PostgreSQL parsing uses SQLFluff 3.4.2. For Mojo, pass the absolute path to a compiled trusted grammar with `--mojo-grammar`. CI builds commit `99fe918e69f087f910ef3b11eba31eb0d7e54edf` of HerringtonDarkholme/tree-sitter-mojo and uses py-tree-sitter 0.25.2. Keep the library outside the scanned snapshot. A missing parser, a missing grammar or unsupported syntax gives exit 2 for eligible files.

```sh
cc -O2 -fPIC -Isrc -c src/parser.c -o parser.o
c++ -O2 -fPIC -Isrc -c src/scanner.cc -o scanner.o
c++ -shared parser.o scanner.o -o mojo.so
```

## Residual risks

| Risk | Detail |
|---|---|
| Inline suppressions | ShellCheck `# shellcheck disable=`, Checkov `checkov:skip=` comments and PowerShell `SuppressMessageAttribute` in the target still suppress results. None of these engines has a flag to ignore them. Bandit `# nosec`, Opengrep `nosemgrep` and `gitleaks:allow` are ignored. |
| Ignore files in the target | Gitleaks reads `.gitleaksignore` from the scanned directory. It can drop findings by Gitleaks fingerprint. |
| Directory-scoped configuration | Checkov 3.2.495 adds `DIR/.checkov.yaml` to its config search only when `--directory` appears as a separate argument. CRAB passes `--directory=DIR` instead. This relies on Checkov internals. Review this, and any new configuration discovery in other engines, before updating the lock file. |
| Engine parsers | Engines parse untrusted files. Process isolation limits configuration, environment and time. It does not sandbox file system or network access. Use the container image with `--network none` for strong isolation. |
| Pip engine supply chain | bandit and checkov install only the hash-locked wheels in their requirement files. A compromised release cannot change them, but the locked set must be reviewed when it is regenerated. |
| Images | `trivy-image` reads local images when offline. Pulling from a registry needs `--online`. |
| Windows process trees | Timeouts use `taskkill /T`. POSIX resource limits do not apply on Windows. |

[Bandit JSON](https://bandit.readthedocs.io/en/latest/formatters/json.html) · [Opengrep](https://github.com/opengrep/opengrep) · [OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/) · [Trivy air-gapped use](https://trivy.dev/docs/latest/advanced/air-gap/) · [Gitleaks](https://github.com/gitleaks/gitleaks) · [Architecture](architecture.md) · [Reporting](reporting.md) · [CI](ci.md) · [Language coverage](coverage.md)
