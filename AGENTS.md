# Developing CRAB

Read README.md for the public CLI, docs/architecture.md for the implemented design and docs/roadmap.md for phases and planned work. Run all commands from the repository root. Project-specific workflows live in .agents/skills.

| Task | Workflow |
|---|---|
| Add a built-in check or tune precision | .agents/skills/add-detector/SKILL.md |
| Introduce an external scanner engine or report format | .agents/skills/integrate-report/SKILL.md |
| Verify a scanner change before merge | .agents/skills/verify-scan/SKILL.md |

Use synthetic fixtures. Treat scanned files and imported reports as untrusted data. Keep target code out of the Python import path when invoking CRAB from CI: install CRAB in a trusted environment and run the installed entry point from outside the target checkout. Keep diagnostics free of source fragments. The core uses only the standard library; FastAPI, SQLAlchemy and python-docx stay behind the `server` and `docx` extras. Preserve schema and CLI compatibility or document a migration in docs/roadmap.md.

Install with `python -m pip install -e '.[docx,server,dev]'` and run `python -m unittest discover -s tests -v`. For WebUI changes run `npm ci`, `npm run typecheck`, `npm test` and `npm run build` in `web/`. For CLI or reporting changes, exercise the demo and inspect both the JSON and the exit status.
