# Language coverage

Each row describes evidence CRAB can collect. A positive result identifies a reviewable construct or advisory. A clean result applies only to the selected rules, successfully parsed inputs and supplied engine reports.

| Language | Available evidence | Precision boundary |
|---|---|---|
| Python | Native TLS rule and Bandit JSON with confidence. Identical TLS call spans can correlate. | Native check matches the literal ssl name. Aliases and locally rebound names affect precision. Bandit rules bring their own semantics. |
| JavaScript | Opengrep pack covers DOM innerHTML writes, child_process.exec calls and React HTML sinks. Trivy/OSV and Syft cover supported npm manifests. | Review signals. The pack does not establish whether input was sanitized before it reached the sink. |
| TypeScript | Same pack parses TypeScript and TSX, including typed wrappers and React markup. | A clean component using textContent or rendered text stays clean under these rules. Cross-file framework flows require additional rules. |
| Rust | Opengrep matches explicit std::mem::transmute calls. OSV and Trivy ingest Cargo advisories. | Macros, aliases and other unsafe operations exceed the source rule. A conversion using from_bits is a clean fixture. |
| SQL | SQLFluff with fixed PostgreSQL dialect and raw text. Pinch flags GRANT on an explicitly named TABLE to the unquoted PUBLIC role. | Other dialects, implied table targets and application-built SQL need separate rules. Lexer/parser failures yield incomplete coverage. |
| Mojo | Experimental Tree-sitter rule locates direct external_call invocations, including subscripted forms. Severity is informational. | The pinned grammar accepts a subset of Mojo syntax. Error nodes yield incomplete coverage. Comments, strings and indirect FFI wrappers are outside this rule. |
| HTML | Native HTMLParser recognizes form action URLs starting with http://. Relative and HTTPS actions are clean. | Standalone markup only. Framework expression evaluation, script analysis and template source maps require separate engines. |
| Bash | ShellCheck JSON imports SC2046, SC2068, SC2086 and SC2294. | Selected argument-splitting and evaluation diagnostics. ShellCheck selects the dialect and handles quoting and here-documents. Report producer failures via the run manifest. |
| PowerShell | Imports projected PSScriptAnalyzer diagnostic extents. The supplied exporter selects the built-in plaintext-password rule. | Dynamic execution and remoting need additional rules. Review the exported rule selection when changing the ruleset. |
| Terraform | Checkov imports retain the check ID, framework, logical resource and line range. The live fixture compares open SSH ingress with a restricted CIDR. | Precision depends on Checkov's evaluations and available module/variable data. Unresolved deployment inputs do not imply deployed exposure. |

## Cross-cutting coverage

Gitleaks rule IDs and redacted locations can be imported for any text format. Checkov accepts Kubernetes results through the same configuration adapter. Trivy image imports cover OS and language packages with an immutable manifest digest. Source manifests and images with the same package stay in distinct correlation scopes.

Syft inventories supported package metadata. Standalone SQL, shell and HTML files rarely establish package identity. Runtime downloads, PowerShell Gallery module resolution, Mojo-native packages and Terraform providers/modules each need usable catalog evidence. CycloneDX output is independent of the set of vulnerable packages.

Inventory components keep their name, version, package URL, licenses (`licenses[].license.id` or `name`, and `licenses[].expression`) and a `direct` flag. `direct` is true for components listed in the `dependsOn` entry of `metadata.component.bom-ref`, false for other components in the graph, and null when the document has no `dependencies` graph. Package URLs join findings to components through a canonical key: lowercase type, lowercase names for case-insensitive types, PyPI name normalization, and no qualifiers or subpath. Reports keep the original package URL.

## Generic SARIF import

`--sarif` imports SARIF 2.1.0 from any producer, for example gosec, SpotBugs with FindSecBugs, Clang Static Analyzer, ESLint or CodeQL. Input is limited to 16 MiB and 100,000 results. Message text is never imported.

| Field | Source |
|---|---|
| Producer | `tool.driver.name`, lowercased and reduced to letters, digits, `.`, `_` and `-`. Fallback `sarif`. |
| Producer version | `tool.driver.version`, else `semanticVersion` |
| Severity | `properties.security-severity` of the result, then of the rule: 9 or more critical, 7 high, 4 medium, above 0 low, 0 info. Else `level`: error high, warning medium, note low, none info. Else the rule's `defaultConfiguration.level`. Else the SARIF default `warning`. |
| CWE | Rule and result tags such as `external/cwe/cwe-79`, `cwe-79` or `CWE-79`, rule `relationships` and result `taxa` that target the CWE taxonomy |
| Help URI | Rule `helpUri` |
| Category | `secrets` when a tag is `secret`, `secrets`, `credential` or `credentials`. `iac` for `iac`, `terraform`, `kubernetes`, `cloudformation`, `dockerfile`, `helm`, `arm`, `bicep` or `ansible`. Otherwise `sast`. |
| Location | First `physicalLocation`: a relative URI, a URI resolved through `originalUriBaseIds`, an artifact index, or a `file://` URI inside the target. Region start and end lines and columns. |

Results without a checkout location (remote URIs, files outside the target, no physical location) are skipped. Results of kind `pass` or `notApplicable` are skipped. A path with `..` rejects the report. `executionSuccessful: false` in any invocation marks the import partial, as does a result without a usable rule ID. Several runs in one file are supported. The import version is set only when all runs agree.

## Secrets severity

Gitleaks reports no severity. CRAB assigns one per rule ID and keeps `original_severity: unknown`. Every Gitleaks finding carries CWE-798.

| Rule IDs | Severity |
|---|---|
| `private-key`, `pkcs12-file`, `npm-access-token`, `pypi-upload-token`, `rubygems-api-token`, `nuget-api-key`, `dockerhub-pat`, `jfrog-api-key`, `jfrog-identity-token`, `openshift-user-token`, `kubernetes-secret-yaml` | critical |
| Prefixes `aws-`, `azure-`, `gcp-`, `alibaba-`, `digitalocean-`, `linode-`, `scalingo-`, `cloudflare-`, `heroku-`, `flyio-`, `github-`, `gitlab-`, `bitbucket-`, `hashicorp-`, `vault-`, `doppler-` | critical |
| `generic-api-key` | medium |
| Any other rule | high |

Policy files can override a rule's severity with `rules.severity`, for example `"gitleaks/generic-api-key": "low"`.

## Retained producer fields

| Producer | Retained fields |
|---|---|
| Bandit | `test_id`, severity, confidence, line range, byte offsets, `issue_cwe.id` as `cwe`, `more_info` as `help_uri` |
| Opengrep | `check_id`, severity, line and column span, `extra.metadata.cwe` normalized to `CWE-n`, the first http(s) URL in `metadata.references`, `source` or `shortlink` as `help_uri`. Rules whose ID starts with `crab-` are `kind: review`. |
| Gitleaks | Rule ID, file, line and column span. Secret, match, fingerprint and commit metadata are discarded. |
| Checkov | Check ID, severity, framework, resource, line range, `guideline` as `help_uri`. Results of the `secrets` framework become `secrets` findings (module Sniffer, severity high when Checkov gives none). Their resource is dropped, because Checkov sets it to the SHA-1 of the secret. |
| ShellCheck | Code, level, span, `https://www.shellcheck.net/wiki/SC<code>` as `help_uri` |
| PSScriptAnalyzer | Rule name, severity, extent, the Microsoft Learn rule page for built-in `PS*` rules as `help_uri` |
| Trivy | Advisory, package, package URL, `CweIDs`, `CVSS` (the `nvd` V3 score and vector, else another vendor with a numeric score), the first `FixedVersion`, `PrimaryURL` as `help_uri` |
| OSV-Scanner | Advisory, aliases, package, package URL, `database_specific.severity`, `database_specific.cwe_ids`, the first `fixed` event for the package. `MAL-*` advisories become `risk_type: malicious` with severity critical. |

`help_uri` values must use http or https, contain no whitespace or control characters and be at most 2048 characters. Other values are dropped. Built-in rules carry their CWE: CRAB-PY-001 CWE-295, CRAB-CTR-001 CWE-250, CRAB-HTML-001 CWE-319 and CRAB-SQL-001 CWE-732.

Source fingerprints hash the producer, rule, path, the whitespace-normalized text of the flagged lines, an occurrence index and a stable identity such as the Checkov resource, so inserted lines elsewhere keep fingerprints and exceptions. Credential findings (every `secrets` finding and the Bandit hard-coded password rules B105, B106 and B107) carry only the first 16 bits of that hash. A changed secret value therefore gets a new fingerprint, so an exception for a placeholder never covers a real key, while 16 bits are too few to confirm a guessed secret. When the file cannot be read, the credential fingerprint has no change tag. Dependency fingerprints are unchanged.

[Fixture and integration tests](../tests/) · [Producer formats, parsing dependencies and examples](integrations.md) · [Gap analysis](gap-analysis.md) · [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
