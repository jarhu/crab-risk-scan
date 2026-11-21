# CRAB — Code Risk Analysis Bot

**The open-source security scanner with claws.**

CRAB is an offline-first security scanning platform. One scanning core runs source-code checks, secret detection, infrastructure checks, dependency and container advisories, and SBOM generation for a local repository snapshot. It ranks findings, removes repeated observations, preserves their origin and applies a reviewed policy. The same core serves three interfaces: a local CLI, a CI runner and a self-hosted WebUI. None of them needs a hosted service or sends source code out of your environment.

## Quick start

Use Python 3.11 or newer. From this checkout:

```sh
python -m pip install .
crab-risk-scan scan examples/demo --engines none
crab-risk-scan scan examples/demo --engines none --trivy examples/trivy-fs.json --output report.md --output report.sarif
```

The first scan reports two medium review findings from the built-in rules. The second imports a saved Trivy report, ranks its synthetic high-severity advisory first and writes Markdown and SARIF files. Both exit 1 because the default policy fails on any finding. For scanning another checkout, run the installed command from a trusted working directory.

To run the external engines as well, install the pinned versions once, prepare the offline vulnerability databases and scan:

```sh
crab-risk-scan engines install --dest ~/.crab/engines
export CRAB_ENGINE_DIR=~/.crab/engines/bin
crab-risk-scan db update
crab-risk-scan scan /path/to/checkout --sbom --output-dir crab-results
```

`engines install` verifies every download against the SHA-256 digests in `crab_risk_scan/engines.lock.json`. `db update` is the only networked step. Scans run engines with offline flags, and engines that are not installed are recorded as skipped.

## Execution modes

| Mode | Command | Use |
|---|---|---|
| CLI | `crab-risk-scan scan DIRECTORY` | Local and air-gapped assessments, consultant reports |
| Runner | `crab-risk-scan ci DIRECTORY` | GitHub Actions, GitLab CI, Azure Pipelines and Jenkins. Writes an artifact folder, job summary and annotations, and can upload results to a CRAB server. |
| Server | `crab-risk-scan serve` and `crab-risk-scan worker`, or `docker compose up -d` | Self-hosted WebUI and API with projects, scan history, triage, comparison, jobs, schedules, dashboards and role-based access |

| Command | Purpose | Exit status |
|---|---|---|
| `scan DIRECTORY [options]` | Run built-in rules and installed engines, import saved reports, link or generate an SBOM, apply the policy, write reports | 0 policy passed, 1 policy failed, 2 incomplete |
| `report REPORT.json --output FILE` | Render a saved report in another format | 0 success, 2 failure |
| `gate REPORT.json [--policy FILE] [--exceptions FILE]` | Re-evaluate the policy for a saved report | 0, 1 or 2 as for `scan` |
| `engines` and `engines install --dest DIR` | List engines and versions, or install the pinned engines | 0 success, 2 failure |
| `db update` | Prepare the Trivy and OSV-Scanner offline databases | 0 success, 2 failure |
| `sbom DIRECTORY [--format cyclonedx-json\|spdx-json]` | Generate an inventory with Syft | 0 success, 2 failure |
| `rules` | Print the path of the packaged Opengrep rule pack | 0 |

## Reports

The output format follows the file name. Repeat `--output`, or use `--output-dir` for the standard set.

| Format | File name | Use |
|---|---|---|
| JSON | `report.json` | Schema 3, validated by `crab_risk_scan/schemas/report-v3.schema.json`. Automation and the server. |
| SARIF 2.1.0 | `report.sarif` | GitHub code scanning, GitLab, Azure DevOps and IDEs |
| Markdown | `report.md` | Pull request summaries and audit notes |
| HTML | `report.html` | Standalone interactive report |
| CSV | `report.csv` | Spreadsheets and data analysis |
| Word | `report.docx` | Technical or executive deliverables. Requires `pip install 'crab-risk-scan[docx]'`. Custom templates are supported. |
| GitLab Code Quality | `gl-code-quality-report.json` | Merge request widget on every GitLab tier |
| CycloneDX VEX | `report.vex.json` | Vulnerability status statements from reviewed exceptions |
| CycloneDX and SPDX | `sbom.cdx.json`, `sbom.spdx.json` | Software bill of materials |

## Policy and exceptions

A versioned policy file sets the severity threshold and gates for secrets, malicious packages, known exploited vulnerabilities, EPSS scores, denied licenses, per-severity counts and new findings only. It can disable rules and override severities. A versioned exceptions file records reviewed findings as accepted, false positive or not affected, with a reviewer, reason, optional ticket and optional expiry. Fingerprints do not depend on line numbers, so an exception survives unrelated edits. Expired and unmatched exceptions are reported. See [integrations and policy](docs/integrations.md).

```sh
crab-risk-scan scan . --policy crab-policy.json --exceptions crab-exceptions.json --new-since main-report.json --epss epss.csv.gz --kev kev.json
```

## The CRAB ecosystem

| Feature | Name | Implemented |
|---|---|---|
| SAST | Claws | Runs or imports Bandit, Opengrep, ShellCheck and PSScriptAnalyzer, and imports any SARIF 2.1.0 producer |
| SCA and SBOM | Shell | Trivy and OSV-Scanner advisories with CVSS, CWE, fixed versions, EPSS and KEV, malicious-package detection, license policy, CycloneDX and SPDX inventories from Syft |
| Secrets | Sniffer | Gitleaks with severity per rule. Secret values, snippets and commit metadata are discarded. |
| IaC | Burrow | Dockerfile USER check and Checkov resource findings |
| Container security | Exoskeleton | Trivy image vulnerabilities scoped to the image manifest digest |
| Rule engine | Pinch | Rules for Python, Dockerfile, HTML, PostgreSQL and experimental Mojo, plus an Opengrep pack |
| Reporting | Crab Trap | Correlation, policy gates, exceptions, comparison and every report format above |

[Roadmap](docs/roadmap.md) · [Gap analysis](docs/gap-analysis.md) · [Architecture](docs/architecture.md) · [Integrations](docs/integrations.md) · [Reporting](docs/reporting.md) · [CI](docs/ci.md) · [Server](docs/server.md) · [API](docs/api.md) · [WebUI](docs/webui.md) · [Language coverage](docs/coverage.md) · [Contributor workflows](AGENTS.md) · [Apache-2.0 license](LICENSE)
