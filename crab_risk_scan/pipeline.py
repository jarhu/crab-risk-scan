"""One scan pipeline shared by the CLI, the CI runner and the workers."""
import argparse
import os
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import engines, reports
from .evidence import LEVELS, token
from .pinch import html, mojo, postgres
from .policy import exit_status
from .reporting import collect
from .rules import detector
from .sbom import SbomError, generate

EXCLUDE = {".git", ".venv", "__pycache__", "node_modules"}
LIMIT = 1024 * 1024
IMPORT_PRODUCERS = ("bandit", "opengrep", "gitleaks", "checkov", "shellcheck", "psscriptanalyzer",
                    "trivy", "trivy-image", "osv", "sarif")
DIRECTORY_OUTPUTS = ("report.json", "report.sarif", "report.md", "report.html", "report.csv")
SBOM_OUTPUT = "sbom.cdx.json"
TEMPLATES = ("technical", "executive")


@dataclass
class ScanOptions:
    directory: Path
    engines: str = "auto"
    imports: list[tuple[str, Path]] = field(default_factory=list)
    run_manifest: Path | None = None
    revision: str | None = None
    branch: str | None = None
    repository: str | None = None
    image: str | None = None
    inventory: Path | None = None
    sbom_formats: list[str] = field(default_factory=list)
    policy: Path | None = None
    exceptions: Path | None = None
    fail_on: str | None = None
    new_since: Path | None = None
    epss: Path | None = None
    kev: Path | None = None
    offline: bool = True
    cache_dir: Path | None = None
    engine_paths: dict[str, Path] = field(default_factory=dict)
    engine_timeout: int = 900
    mojo_grammar: Path | None = None


@dataclass
class ScanResult:
    report: dict
    sboms: dict[str, dict]
    exit_code: int


def scan(root, *, grammar=None):
    """Run the trusted built-in rules. Target files are read as text and never executed."""
    findings = []
    errors = []
    scanned = 0

    def walk_error(exc):
        errors.append({"path": Path(exc.filename).relative_to(root).as_posix(), "reason": "walk_error"})

    if root.is_symlink() or not root.is_dir():
        errors.append({"path": ".", "reason": "expected_directory"})
    else:
        for folder, dirs, files in os.walk(root, onerror=walk_error):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDE and not (Path(folder) / d).is_symlink())
            for name in sorted(files):
                path = Path(folder) / name
                check = {".html": html, ".htm": html, ".sql": postgres,
                         ".mojo": lambda source: mojo(source, grammar),
                         ".🔥": lambda source: mojo(source, grammar)}.get(path.suffix.lower(), detector(path))
                if check is None:
                    continue
                rel = path.relative_to(root).as_posix()
                try:
                    if not stat.S_ISREG(path.lstat().st_mode):
                        continue
                    with path.open("rb") as stream:
                        raw = stream.read(LIMIT + 1)
                    if len(raw) > LIMIT:
                        errors.append({"path": rel, "reason": "size_limit"})
                        continue
                    for hit in list(check(raw.decode("utf-8-sig"))):
                        fields = {k: v for k, v in asdict(hit).items()
                                  if v is not None or k not in ("byte_offset", "end_byte_offset", "end_line")}
                        findings.append(dict(path=rel, **fields))
                    scanned += 1
                except (SyntaxError, ValueError, RecursionError, OSError, ImportError, AttributeError) as exc:
                    errors.append({"path": rel, "reason": type(exc).__name__})
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    return {"files_scanned": scanned, "findings": findings, "errors": sorted(errors, key=lambda e: e["path"])}


class _Import(argparse.Action):
    """Keep saved-report imports in command-line order across producers."""

    def __call__(self, parser, namespace, values, option_string=None):
        items = list(getattr(namespace, self.dest) or [])
        items.append((self.metavar_producer, values))
        setattr(namespace, self.dest, items)


def _import_action(producer):
    return type("Import_" + producer.replace("-", "_"), (_Import,), {"metavar_producer": producer})


def repository_url(value):
    parts = urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password
            or len(value) > 2048 or any(ord(c) < 33 for c in value)):
        raise argparse.ArgumentTypeError("expected an http(s) repository URL without credentials")
    return value


def engine_path(value):
    name, sep, location = value.partition("=")
    if not sep or name not in engines.TOOLS:
        raise argparse.ArgumentTypeError(f"expected NAME=PATH with NAME in {', '.join(engines.TOOLS)}")
    path = Path(location)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("engine paths must be absolute")
    return name, path


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def image_reference(value):
    try:
        token(value)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid image reference") from None
    if value.startswith("-"):
        raise argparse.ArgumentTypeError("invalid image reference")
    return value


def identifier(value):
    try:
        return token(value)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid identifier") from None


def add_output_arguments(parser):
    parser.add_argument("--output", type=Path, action="append", default=[], metavar="FILE",
                        help="write a report file; the format follows the file name (repeatable)")
    parser.add_argument("--output-dir", type=Path, metavar="DIR",
                        help="write report.json, .sarif, .md, .html and .csv (and sbom.cdx.json with --sbom)")
    parser.add_argument("--format", choices=reports.FORMATS,
                        help="stdout format when no output file is given (default json); also used for "
                             "output files whose name has no known extension")
    parser.add_argument("--template", metavar="technical|executive|PATH.docx",
                        help="DOCX template for docx outputs")


def add_scan_arguments(parser):
    """Register every `scan` flag. The runner and workers reuse this parser surface."""
    parser.add_argument("directory", type=Path, help="local repository snapshot")
    parser.add_argument("--engines", default="auto", metavar="auto|all|none|NAME[,NAME]",
                        help="engines to run (default auto: installed engines whose file types are present)")
    imports = parser.add_argument_group("saved reports")
    for producer in IMPORT_PRODUCERS:
        imports.add_argument("--" + producer, dest="imports", type=Path, action=_import_action(producer),
                             default=[], metavar="REPORT", help=f"import a saved {producer} report (repeatable)")
    imports.add_argument("--run-manifest", type=Path, metavar="FILE", help="versioned scanner inputs and status")
    parser.add_argument("--revision", type=identifier, help="snapshot identity for correlation")
    parser.add_argument("--branch", type=identifier, help="branch name")
    parser.add_argument("--repository", type=repository_url, help="repository URL (http/https)")
    parser.add_argument("--image", type=image_reference, metavar="REF",
                        help="run the trivy-image engine against an image reference")
    inventory = parser.add_mutually_exclusive_group()
    inventory.add_argument("--inventory", type=Path, metavar="FILE", help="link an existing CycloneDX JSON SBOM")
    inventory.add_argument("--sbom", action="store_true", help="generate CycloneDX with Syft and link it")
    gate = parser.add_argument_group("policy")
    gate.add_argument("--policy", type=Path, metavar="FILE", help="policy v1 JSON file")
    gate.add_argument("--exceptions", type=Path, metavar="FILE", help="exceptions v2 JSON file")
    gate.add_argument("--fail-on", choices=LEVELS + ("none",), help="minimum severity that fails the policy")
    gate.add_argument("--new-since", type=Path, metavar="BASE_REPORT.json", help="mark new and fixed findings")
    gate.add_argument("--epss", type=Path, metavar="FILE", help="offline EPSS CSV (optionally .gz)")
    gate.add_argument("--kev", type=Path, metavar="FILE", help="offline CISA KEV JSON")
    run = parser.add_argument_group("engine execution")
    network = run.add_mutually_exclusive_group()
    network.add_argument("--offline", dest="offline", action="store_true", default=True,
                         help="run engines with offline flags and local databases (default)")
    network.add_argument("--online", dest="offline", action="store_false",
                         help="let engines update their databases during the scan")
    run.add_argument("--cache-dir", type=Path, metavar="DIR",
                     help="engine database cache (default: CRAB_CACHE_DIR or the user cache dir)")
    run.add_argument("--engine-path", type=engine_path, action="append", default=[], metavar="NAME=/abs/path",
                     help="trusted executable for an engine (repeatable)")
    run.add_argument("--engine-timeout", type=positive_int, default=900, metavar="SECONDS",
                     help="per-engine timeout (default 900)")
    run.add_argument("--mojo-grammar", type=Path, metavar="PATH",
                     help="absolute path to a trusted Mojo grammar library")
    add_output_arguments(parser)


def output_paths(args, sboms=()):
    """Output files requested by --output and --output-dir."""
    paths = list(getattr(args, "output", None) or [])
    folder = getattr(args, "output_dir", None)
    if folder:
        paths.extend(folder / name for name in DIRECTORY_OUTPUTS)
        if "cyclonedx-json" in sboms:
            paths.append(folder / SBOM_OUTPUT)
    return paths


def _sbom_formats(args):
    formats = set()
    if args.sbom:
        formats.add("cyclonedx-json")
    for path in args.output:
        try:
            kind = reports.format_for_path(path)
        except ValueError:
            continue
        if kind.startswith("sbom:"):
            formats.add(kind.removeprefix("sbom:"))
    if formats:
        # The CycloneDX document is always produced because it becomes the linked inventory.
        formats.add("cyclonedx-json")
    return sorted(formats)


def options_from_args(args):
    """Convert parsed scan arguments. Raises ValueError for inconsistent options."""
    directory = args.directory
    selection = engines.parse_selection(args.engines, image=args.image)
    grammar = args.mojo_grammar
    if grammar and (not grammar.is_absolute() or not grammar.is_file()
                    or grammar.resolve().is_relative_to(directory.resolve())):
        raise ValueError("--mojo-grammar requires a trusted library outside the scanned directory")
    paths = dict(args.engine_path)
    if len(paths) != len(args.engine_path):
        raise ValueError("--engine-path lists an engine more than once")
    if args.cache_dir and args.cache_dir.resolve().is_relative_to(directory.resolve()):
        raise ValueError("--cache-dir must be outside the scanned directory")
    return ScanOptions(
        directory=directory, engines=selection, imports=list(args.imports), run_manifest=args.run_manifest,
        revision=args.revision, branch=args.branch, repository=args.repository, image=args.image,
        inventory=args.inventory, sbom_formats=_sbom_formats(args), policy=args.policy,
        exceptions=args.exceptions, fail_on=args.fail_on, new_since=args.new_since, epss=args.epss,
        kev=args.kev, offline=args.offline, cache_dir=args.cache_dir, engine_paths=paths,
        engine_timeout=args.engine_timeout, mojo_grammar=grammar)


def execute(options):
    """Run built-in checks, engines and imports for one snapshot and evaluate the policy."""
    root = options.directory
    local = scan(root, grammar=options.mojo_grammar)
    sboms = {}
    inventory = options.inventory
    with tempfile.TemporaryDirectory(prefix="crab-run-") as work:
        work = Path(work)
        inputs = []
        if not local["errors"] or local["errors"][0]["reason"] != "expected_directory":
            inputs.extend(engines.run_engines(options, work))
            if options.sbom_formats:
                try:
                    sboms = generate(root, options.engine_paths.get("syft"), options.sbom_formats,
                                     timeout=options.engine_timeout, revision=options.revision)
                    inventory = sboms["cyclonedx-json"]
                except SbomError as exc:
                    local["errors"].append({"reason": exc.reason, "producer": "syft"})
        inputs.extend((producer, path, {"origin": "report"}) for producer, path in options.imports)
        report = collect(local, root=root, inputs=inputs, run_manifest=options.run_manifest,
                         revision=options.revision, branch=options.branch, repository=options.repository,
                         inventory=inventory, policy=options.policy, exceptions=options.exceptions,
                         fail_on=options.fail_on, new_since=options.new_since, epss=options.epss,
                         kev=options.kev)
    return ScanResult(report=report, sboms=sboms, exit_code=exit_status(report))


def _template(value):
    if value is None or value in TEMPLATES:
        return value
    path = Path(value)
    if path.suffix.lower() != ".docx" or not path.is_file():
        raise ValueError("--template expects technical, executive or an existing .docx file")
    return path


def write_report_outputs(report, args, sboms=None):
    """Write --output/--output-dir files, or the --format rendering to stdout. Returns written paths."""
    sboms = sboms or {}
    template = _template(getattr(args, "template", None))
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    paths = output_paths(args, sboms)
    explicit = getattr(args, "format", None)
    if not paths:
        sys.stdout.buffer.write(reports.render(report, explicit or "json", template=template,
                                               generated_at=generated_at))
        sys.stdout.buffer.flush()
        return []
    known, other = [], []
    for path in paths:
        try:
            reports.format_for_path(path)
            known.append(path)
        except ValueError:
            if explicit is None:
                raise
            other.append(path)
    for path in {path.parent for path in paths}:
        path.mkdir(parents=True, exist_ok=True)
    written = reports.write_outputs(report, known, sboms=sboms, template=template, generated_at=generated_at)
    for path in other:
        reports.atomic_write(path, reports.render(report, explicit, template=template, generated_at=generated_at))
        written.append(path)
    return written


def write_scan_outputs(result, args):
    """Honour --output, --output-dir, --format/stdout and --template for a scan result."""
    return write_report_outputs(result.report, args, result.sboms)
