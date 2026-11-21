---
name: verify-scan
description: Verify a CRAB scanner or reporting change at the CLI boundary, including coverage, privacy and CI exit status.
---
Read the change and identify affected file types and contracts. Run python -m unittest discover -s tests -v. Run `python -m crab_risk_scan scan examples/demo --engines none` twice, capture stdout and status separately, compare the JSON and validate it against crab_risk_scan/schemas/report-v3.schema.json.

Use temporary clean, finding and malformed inputs to confirm statuses 0, 1 and 2. Combine a finding with a malformed file and confirm both survive in the report with status 2. For traversal changes include a symlink and an oversized supported file. For fingerprint or exception changes insert a line above a suppressed finding and confirm it stays suppressed. For reporting changes place a synthetic canary in a comment, render every format with `crab-risk-scan report`, and confirm the value is absent from diagnostics, findings and exports.

Report the exact command, expected and observed status, coverage counts and discrepancies. Turn a newly discovered failure into a focused regression fixture.
