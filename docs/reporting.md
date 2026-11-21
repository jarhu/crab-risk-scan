# Report formats

CRAB renders one schema-3 report into every export format. The `scan`, `report` and `ci` commands and the server download endpoint all use `crab_risk_scan.reports.render`. Pick the format with `--format` or with the output file name.

| Format | File name | Content | Template |
|---|---|---|---|
| json | `*.json` | The schema-3 report, unchanged | none |
| sarif | `*.sarif`, `*.sarif.json` | SARIF 2.1.0 with rule metadata, suppressions and provenance | none |
| markdown | `*.md`, `*.markdown` | GitHub-flavoured report | technical, executive |
| html | `*.html`, `*.htm` | One self-contained file with filter, sort and search | technical, executive |
| csv | `*.csv` | One row per finding | none |
| docx | `*.docx` | Word document; needs the `docx` extra | technical, executive, custom `.docx` |
| codequality | `*.codequality.json`, `gl-code-quality-report.json` | GitLab Code Quality JSON | none |
| vex | `*.vex.json` | CycloneDX 1.6 VEX for dependency and container vulnerabilities | none |
| CycloneDX SBOM | `*.cdx.json` | Inventory generated with `--sbom` | none |
| SPDX SBOM | `*.spdx.json` | Inventory generated with `--sbom` | none |

Machine formats are deterministic. Markdown, HTML, DOCX and VEX print a generation time only when the caller passes one. DOCX core properties and archive entry times use that time, or 1980-01-01 when none is given.

## Shared content

Every human-readable format uses the same summary model.

| Element | Rule |
|---|---|
| Counts | Open (unsuppressed) findings by severity, category and kind |
| Policy status | `incomplete` when the report has errors, else `passed` or `failed` |
| Coverage | One row per import, with the findings that cite it |
| Prioritization | KEV and malicious findings first, then severity, EPSS score and CVSS score |
| Titles | `<advisory> in <package> <version>`, `Malicious package ...`, `Denied license ...`, or `producer/rule` |
| Recommendations | Written by CRAB per category and signal; producer descriptions are never used |

Posture rating, first match wins:

| Rating | Condition |
|---|---|
| Critical | An open finding is critical, is listed in CISA KEV or is a malicious package |
| High | An open finding is high severity |
| Moderate | An open finding is medium or of unknown severity |
| Low | Open findings are low or informational only |
| Minimal | No open findings |

When a scanner was skipped for a reason other than `not_applicable`, failed or ran partially, or the report has errors, the rating is a lower bound and the report says so. A scanner skipped as `not_applicable` had nothing to scan and leaves coverage complete.

## Templates

`--template technical` is the default. `--template executive` produces a short summary: posture, key metrics, top risks, recommendations and policy. A `.docx` path selects a custom DOCX template.

| Template | Markdown and HTML | DOCX |
|---|---|---|
| technical | Metadata, policy banner, severity and category tables, coverage, comparison, prioritized findings, recommendations, findings by category, exceptions, expired and stale exceptions, errors, inventory and licenses | Cover, executive summary, scope and coverage, policy, findings by severity, detailed findings, exceptions, methodology appendix |
| executive | Posture, key metrics, top 10 risks, recommendations, policy | The same, with a cover block |

`render` rejects an executive template for machine formats and a `.docx` template for anything but DOCX. With several outputs, `write_outputs` applies the template only to the formats that support it.

The DOCX technical report details the first 200 findings by risk and lists the rest in one table. The JSON report has every field.

## Custom DOCX templates

Install the extra first: `pip install 'crab-risk-scan[docx]'`. Without it, DOCX output fails with that instruction.

1. Create a document in Word with your cover, styles, header and footer.
2. Add placeholders anywhere in the body, tables, headers or footers.
3. Add a paragraph whose only text is `{{CRAB_REPORT}}` where the report content goes.
4. Render: `crab-risk-scan report report.json --output report.docx --template brand.docx`.

| Placeholder | Value |
|---|---|
| `{{TARGET}}` | Scanned directory name |
| `{{REVISION}}` | Revision, or `not recorded` |
| `{{BRANCH}}` | Branch, or `not recorded` |
| `{{DATE}}` | Date of the generation time (`YYYY-MM-DD`), or `not recorded` |
| `{{TOOL_VERSION}}` | CRAB version |

- Placeholders split across runs are merged into the first run of the paragraph, which keeps that run's formatting.
- Placeholders are replaced before the report content is inserted, so finding text is never substituted.
- Without a `{{CRAB_REPORT}}` paragraph, the content is appended at the end.
- Content uses the template's `Heading 1-3`, `List Bullet`, `List Number` and `Light Grid Accent 1` or `Table Grid` styles when they exist, and plain formatting otherwise.
- Templates larger than 25 MiB, expanding beyond 100 MiB or 2000 parts, or that python-docx cannot open are rejected.
- Templates with macros (`vbaProject.bin`), ActiveX controls or embedded objects are rejected, and so are external relationships other than hyperlinks. External templates, frames and images load when a document opens, which would turn every generated report into a beacon or, with a UNC target, an NTLM credential leak.

## SARIF details

| Field | Value |
|---|---|
| `tool.driver` | `CRAB`, `version` and `semanticVersion` from the report |
| `rules[].id` | `producer/rule`; every result has `ruleId` and `ruleIndex` |
| `rules[].properties.tags` | `security`, the category, `cve-YYYY-N`, `external/cwe/cwe-N` and `cwe-N`, at most 10 |
| `rules[].properties.security-severity` | The highest CVSS score in the rule's severity band, else critical 9.5, high 8.0, medium 5.5, unknown 5.0, low 3.0, info 1.0 |
| `level` | critical and high `error`, medium and unknown `warning`, low and info `note` |
| `partialFingerprints` | `crab/v2`: the CRAB fingerprint |
| `suppressions` | `external`, `accepted`, the exception reason as justification, and `exceptionStatus` in properties |
| `versionControlProvenance` | When the report has a repository and a revision |
| `automationDetails.id` | `crab-risk-scan/` |
| `invocations` | `executionSuccessful` is false when the report has errors; errors and skipped scanners become notifications |

Findings without a checkout location are image-internal packages and inventory license findings. GitHub rejects the whole SARIF file when one result lacks a physical location ([codeql-action#1738](https://github.com/github/codeql-action/issues/1738)), and GitLab drops such results. CRAB therefore gives them a synthetic, repository-relative location:

| Finding | `artifactLocation.uri` |
|---|---|
| Image package | `crab-image/sha256-<digest>/<ecosystem>/<name>/<version>` |
| Inventory package | `crab-inventory/<ecosystem>/<name>/<version>` |

The region is line 1. A `logicalLocations` entry names the package and its purl, prefixed with the image digest. `properties.syntheticLocation` is `true`. Results with a checkout file but no line also use line 1 and carry `properties.lineUnknown`.

| Consumer | Behaviour for synthetic locations |
|---|---|
| GitHub code scanning | Accepts the file and shows an alert on a path that does not exist in the repository. The alert cannot annotate a pull request diff. |
| GitLab SARIF ingestion (Ultimate) | Ingests the finding with the synthetic path. The package segment keeps identities distinct, because GitLab builds finding identity from file, start line and end line. |
| GitLab Code Quality | Excludes them; Code Quality needs a file in the merge request |

## Security notes

| Format | Protection |
|---|---|
| All | Reports contain CRAB-curated messages and structured fields only. Producer descriptions, source fragments and secret values are never copied. |
| Markdown | Untrusted values are on one line, Markdown punctuation is backslash-escaped (pipes, backticks, brackets, `@`), and `&`, `<`, `>` and `"` become entities. A crafted path cannot break a table, open a code span, inject HTML or mention a user. Link targets, including SARIF `help.markdown`, are percent-encoded except for URL delimiters, so a crafted `help_uri` cannot close the link, add an image or split a table cell. |
| HTML | Data is JSON in a non-executable `<script type="application/json">` block with `<`, `>` and `&` written as `\u003c`, `\u003e` and `\u0026`. The page is built with DOM APIs and `textContent`; it never assigns data to `innerHTML`. Links are created only for `http` and `https` URLs. |
| HTML | A Content-Security-Policy meta tag sets `default-src 'none'` and allows the inline script and stylesheet only by SHA-256 hash. Images, forms, frames and network requests are blocked. |
| CSV | Text cells that start with `=`, `+`, `-`, `@`, tab or carriage return get a leading apostrophe, so spreadsheets do not evaluate them as formulas. Numbers are written as numbers. |
| DOCX | XML-illegal control characters are replaced. python-docx is imported only when a DOCX is rendered. |

## Code Quality and VEX

Code Quality contains open findings with a checkout path. Severity: critical `blocker`, high `critical`, medium and unknown `major`, low `minor`, info `info`. The fingerprint is the CRAB fingerprint, and the line is 1 when unknown.

VEX contains sca and container findings with a package. License findings are policy results and are excluded. Each vulnerability affects its component by purl, and its `bom-ref` is `crab-<fingerprint>`. The serial number is a UUIDv5 over the target, revision and the finding states.

| Exception | `analysis` |
|---|---|
| None, or an expired exception | `state: in_triage` |
| accepted | `state: exploitable`, `response: [will_not_fix]` |
| false_positive | `state: false_positive` |
| not_affected | `state: not_affected` with the exception's justification |

Ratings come from the CVSS score and vector (`CVSSv4`, `CVSSv31`, `CVSSv3`, `CVSSv2` or `other`). Without CVSS, one rating carries the CRAB severity. CWE identifiers become numbers.

## Consumer notes

| Platform | Use |
|---|---|
| GitHub | Upload `report.sarif` with `github/codeql-action/upload-sarif`. The upload needs `security-events: write`. GitHub's SARIF reference does not list `suppressions`, so dismiss alerts in GitHub as well (not tested). Append `report.md` to `GITHUB_STEP_SUMMARY`; the step summary limit is 1 MiB. |
| GitLab | Publish `gl-code-quality-report.json` as `artifacts:reports:codequality` (all tiers). On Ultimate, publish `report.sarif` as `artifacts:reports:sarif`. GitLab ingests SARIF only from a job that succeeds, so run the gate in a separate job with `crab-risk-scan gate`. GitLab skips suppressed results and classifies results with a CVE tag as dependency scanning, CWE-798 and other secret CWEs as secret detection, and the rest as SAST. |
| Azure DevOps | Publish `report.sarif` in a build artifact named `CodeAnalysisLogs` for the SARIF SAST Scans Tab extension. With GitHub Advanced Security for Azure DevOps, publish it with the `AdvancedSecurity-Publish@1` task (not tested). Upload `report.md` with `##vso[task.uploadsummary]`, and publish `report.html` as an artifact. |
| Dependency-Track and VEX consumers | Import `report.vex.json` next to the CycloneDX SBOM from the same scan. |

[Architecture](architecture.md) · [Scanner integrations](integrations.md) · [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) · [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) · [GitLab SARIF reports](https://docs.gitlab.com/user/application_security/detect/sarif/) · [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)
