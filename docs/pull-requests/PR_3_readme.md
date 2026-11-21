# PR #3: offline-first CRAB platform

Delivery report for [PR #3](https://github.com/jarhu/crab-risk-scan/pull/3), written after CI passed on commit `9852163`.

Your design is implemented and up for review as PR #3: https://github.com/jarhu/crab-risk-scan/pull/3. All six CI jobs pass on the latest commit ([run](https://github.com/gepardjaro/crab-risk-scan/actions/runs/44893781773)).

**The two documents**
- `docs/gap-analysis.md` is the SonarQube comparison you asked to save. I added a section 7 recording which gaps this work closes and which stay open.
- `docs/roadmap.md` is your ChatGPT design written up as a plan. All four phases are built, under the `crab-risk-scan` command name you chose.

| Area | What it does now |
|---|---|
| Scanning | `crab-risk-scan scan` runs nine pinned scanners offline. `engines install` downloads them and checks each checksum, and `db update` is the only step that needs the network. Saved reports and any SARIF file can be imported too. |
| Findings | Line edits no longer change a finding's identity, so reviewed exceptions survive them. CVSS, CWE and fix versions are kept, leaked secrets and malicious packages are rated critical, and EPSS, CISA KEV and license data are added. |
| Policy | A policy file sets the severity threshold, gates (secrets, malicious packages, KEV, EPSS, licenses, finding counts, new findings only) and rule overrides. An exceptions file records reviewed findings with status, expiry and ticket. |
| Reports | JSON, SARIF, Markdown, HTML, CSV, Word (technical, executive or your own template), GitLab Code Quality, CycloneDX VEX, and CycloneDX and SPDX SBOMs. |
| CI runner | `crab-risk-scan ci` works in GitHub Actions, GitLab CI, Azure Pipelines and Jenkins. Templates for each, a pre-commit hook and a scanner container image are included. It can upload results to a CRAB server. |
| Server and WebUI | `serve` and `worker`, or `docker compose up`: projects, scan history, triage, scan comparison, scheduled and queued scans, dashboards, and admin/maintainer/viewer roles. |

**Verification**
- **Tests:** 200 local tests pass. On the fork's CI they pass on Ubuntu (Python 3.11), Windows and macOS (Python 3.13), alongside jobs for the real scanners, the WebUI build and the installed package.
- **Real scanners:** a scan of a mixed-language test repo gave 81 findings with no errors. The report and the SARIF file both validate against their schemas, and no host paths or secret values leak.
- **Server, worker and WebUI:**
  - Runner upload, triage, every report download, a queued scan run by a worker, scan comparison, schedules and permission checks all worked end to end.
  - I went through every page in a browser and fixed three small UI bugs it turned up.
- **CI fixes:** the first CI run failed four jobs on three bugs, all fixed in the last commit:
  - OSV-Scanner lockfile paths were rejected on macOS and Windows runners.
  - The worker crashed on Python 3.11.
  - Generated SBOMs contained the full host path of the scanned folder.

**Not tested:** the Docker images, `compose.yaml` and the release workflow never ran, because Docker isn't installed here. I did check that the pinned base image and every pinned GitHub Action exist.

**Breaking changes**
- `scan` now runs the full pipeline and replaces `collect`; use `--engines none` for import only.
- Reports move to schema 3. Old baseline files must be regenerated in the new exceptions format.
- Python 3.11 or newer is required.
- Bandit moves to 1.9.4, because 1.8.6 silently drops findings on Python 3.14.

**Three things I did on your GitHub account that you didn't explicitly ask for**
- Your account has no push access to jarhu/crab-risk-scan, so I forked it to gepardjaro/crab-risk-scan and opened the PR from there.
- GitHub's email-privacy setting blocked your Outlook address, so the commits use your GitHub noreply address.
- I turned on Actions on the fork so CI could run.

**What you need to do**
1. As jarhu, approve the PR's workflow run. GitHub holds runs from a first-time contributor's fork until a maintainer approves them.
2. Before the first release tag, create a `pypi` environment in the repo settings and register the repo as a trusted publisher on PyPI.

The installed scanners, their database cache and the test repo are still in the Temp folder (`crab-engines`, `crab-cache`, `crab-synth`) so the scanner runs can be repeated.
