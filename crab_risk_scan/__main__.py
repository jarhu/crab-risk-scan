import argparse
import json
import sys
from pathlib import Path

from . import engines, pipeline, runner
from .evidence import INVALID, LEVELS, load_json
from .policy import exit_status, reevaluate
from .reports import atomic_write
from .sbom import SBOM_FORMATS, SbomError, generate
from .server import cli as server_cli

REPORT_LIMIT = 64 * 1024 * 1024


def fail(command, message):
    print(f"crab-risk-scan {command}: error: {message}", file=sys.stderr)
    return 2


def run_rules(args):
    print(engines.RULE_PACK)
    return 0


def run_scan(args):
    try:
        options = pipeline.options_from_args(args)
    except ValueError as exc:
        return fail("scan", exc)
    result = pipeline.execute(options)
    try:
        pipeline.write_scan_outputs(result, args)
    except (OSError, ValueError) as exc:
        return fail("scan", f"cannot write outputs: {exc}")
    return result.exit_code


def load_report(path):
    report = load_json(path, REPORT_LIMIT)
    if not isinstance(report, dict) or report.get("schema_version") != 3:
        raise ValueError("expected a schema 3 CRAB report")
    return report


def run_report(args):
    try:
        report = load_report(args.report)
    except INVALID as exc:
        return fail("report", f"cannot read {args.report.name}: {exc}")
    try:
        pipeline.write_report_outputs(report, args)
    except (OSError, ValueError) as exc:
        return fail("report", f"cannot write outputs: {exc}")
    return 0


def run_gate(args):
    try:
        report = load_report(args.report)
    except INVALID as exc:
        return fail("gate", f"cannot read {args.report.name}: {exc}")
    report = reevaluate(report, policy=args.policy, exceptions=args.exceptions, fail_on=args.fail_on,
                        new_since=args.new_since, epss=args.epss, kev=args.kev)
    print(json.dumps(report["policy"], indent=2))
    return exit_status(report)


def run_engines_list(args):
    try:
        paths = dict(args.engine_path)
        rows = engines.describe(paths)
    except (engines.EngineError, OSError, ValueError) as exc:
        return fail("engines", exc)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    width = max(len(row["name"]) for row in rows)
    for row in rows:
        print(f"{row['name']:<{width}}  pinned {row['pinned'] or '-':<8}  found {row['version'] or '-':<8}  "
              f"{row['status']:<16}  {row['path'] or '-'}")
    return 0


def run_engines_install(args):
    try:
        results = engines.install(args.dest, args.engine or None, args.platform)
    except (engines.EngineError, OSError) as exc:
        return fail("engines install", exc)
    return 2 if any(status != "installed" for _, status, _ in results) else 0


def run_db_update(args):
    if args.directory is not None and args.cache_dir is not None and \
            args.cache_dir.resolve().is_relative_to(args.directory.resolve()):
        return fail("db update", "--cache-dir must be outside DIRECTORY")
    try:
        results = engines.update_databases(args.cache_dir, args.directory, engine_paths=dict(args.engine_path))
    except (engines.EngineError, OSError) as exc:
        return fail("db update", exc)
    return 2 if any(status != "updated" for _, status, _ in results) else 0


def run_sbom(args):
    fmt = args.format
    if fmt is None and args.output and args.output.name.lower().endswith(".spdx.json"):
        fmt = "spdx-json"
    fmt = fmt or "cyclonedx-json"
    try:
        document = generate(args.directory, args.syft, [fmt], timeout=args.engine_timeout)[fmt]
        data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        if args.output:
            atomic_write(args.output, data)
        else:
            sys.stdout.buffer.write(data)
    except SbomError as exc:
        return fail("sbom", f"SBOM generation failed: {exc}")
    except OSError as exc:
        return fail("sbom", f"SBOM generation failed: {type(exc).__name__}")
    return 0


def add_policy_arguments(parser):
    parser.add_argument("--policy", type=Path, metavar="FILE", help="policy v1 JSON file")
    parser.add_argument("--exceptions", type=Path, metavar="FILE", help="exceptions v2 JSON file")
    parser.add_argument("--fail-on", choices=LEVELS + ("none",), help="minimum severity that fails the policy")
    parser.add_argument("--new-since", type=Path, metavar="BASE_REPORT.json", help="mark new and fixed findings")
    parser.add_argument("--epss", type=Path, metavar="FILE", help="offline EPSS CSV (optionally .gz)")
    parser.add_argument("--kev", type=Path, metavar="FILE", help="offline CISA KEV JSON")


def build_parser():
    parser = argparse.ArgumentParser(prog="crab-risk-scan", description="CRAB — Code Risk Analysis Bot")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a repository snapshot with built-in rules, engines and imports")
    pipeline.add_scan_arguments(scan)
    scan.set_defaults(handler=run_scan)

    report = sub.add_parser("report", help="re-render a saved schema-3 report")
    report.add_argument("report", type=Path, metavar="REPORT.json")
    pipeline.add_output_arguments(report)
    report.set_defaults(handler=run_report)

    gate = sub.add_parser("gate", help="re-evaluate the policy of a saved report; prints the policy result")
    gate.add_argument("report", type=Path, metavar="REPORT.json")
    add_policy_arguments(gate)
    gate.set_defaults(handler=run_gate)

    tools = sub.add_parser("engines", help="list engines, resolved paths, versions and pinned versions")
    tools.add_argument("--json", action="store_true", help="print JSON")
    tools.add_argument("--engine-path", type=pipeline.engine_path, action="append", default=[],
                       metavar="NAME=/abs/path", help="trusted executable for an engine (repeatable)")
    tools.set_defaults(handler=run_engines_list)
    tool_commands = tools.add_subparsers(dest="engines_command")
    install = tool_commands.add_parser("install", help="download pinned engines with SHA-256 verification")
    install.add_argument("--dest", type=Path, required=True, metavar="DIR", help="installation folder")
    install.add_argument("--engine", action="append", choices=engines.TOOLS, metavar="NAME",
                         help=f"engine to install (repeatable; default all): {', '.join(engines.TOOLS)}")
    install.add_argument("--platform", choices=engines.PLATFORMS, help="target platform (default: this host)")
    install.set_defaults(handler=run_engines_install)

    db = sub.add_parser("db", help="manage offline vulnerability databases")
    db_commands = db.add_subparsers(dest="db_command", required=True)
    update = db_commands.add_parser("update", help="download the Trivy and OSV databases (networked)")
    update.add_argument("directory", type=Path, nargs="?", metavar="DIRECTORY",
                        help="download OSV databases only for the ecosystems found here")
    update.add_argument("--cache-dir", type=Path, metavar="DIR",
                        help="database cache (default: CRAB_CACHE_DIR or the user cache dir)")
    update.add_argument("--engine-path", type=pipeline.engine_path, action="append", default=[],
                        metavar="NAME=/abs/path", help="trusted executable for an engine (repeatable)")
    update.set_defaults(handler=run_db_update)

    inventory = sub.add_parser("sbom", help="catalog a local repository with Syft")
    inventory.add_argument("directory", type=Path)
    inventory.add_argument("--format", choices=SBOM_FORMATS,
                           help="cyclonedx-json (default) or spdx-json; inferred from a .spdx.json output")
    inventory.add_argument("--output", type=Path, help="write the SBOM atomically to a file")
    inventory.add_argument("--syft", type=Path, help="absolute path to a trusted Syft binary")
    inventory.add_argument("--engine-timeout", type=pipeline.positive_int, default=900, metavar="SECONDS")
    inventory.set_defaults(handler=run_sbom)

    sub.add_parser("rules", help="print the installed Opengrep rule-pack path").set_defaults(handler=run_rules)
    # Optional interfaces register their own subcommands. Their modules import only the
    # standard library at import time; server dependencies load inside the handlers.
    runner.add_cli(sub)
    server_cli.add_cli(sub)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
