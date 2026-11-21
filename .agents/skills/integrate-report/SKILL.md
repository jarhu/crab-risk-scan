---
name: integrate-report
description: Integrate an external scanner as a CRAB engine or saved-report adapter for source, dependency, image or infrastructure findings.
---
Read docs/integrations.md and the report contract in crab_risk_scan/schemas/report-v3.schema.json. Identify one producer format and version. If the producer emits SARIF 2.1.0, start with the generic `sarif` adapter and add a native adapter only for evidence SARIF cannot carry. Start with saved synthetic clean, finding and malformed reports. Document which fields supply producer identity, advisory or rule ID, severity, CWE, fix information and location.

Keep the importer separate from source-file dispatch. Bound input size, validate field types and reject unexpected paths that escape the repository. Preserve producer severity and define a mapping for unknown values. Leave missing lines absent. Introduce a documented schema revision if schema 3 cannot represent the data faithfully.

To run the producer as an engine, register it in crab_risk_scan/engines.py with discovery, applicability, offline flags, exit-status classification and a pinned entry with SHA-256 digests in crab_risk_scan/engines.lock.json. Never execute a binary from inside the target, and ignore target-controlled configuration where the producer allows it.

Exercise the adapter through its public entry point. Assert deterministic output and incomplete-scan precedence, redact embedded source and credentials, and document a working invocation with the fixture.
