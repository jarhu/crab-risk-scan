"""Discover, install and run pinned third-party engines in a restricted subprocess.

Engines parse untrusted repositories. Every run gets an allow-listed environment, a private
working directory and HOME, closed stdin, a timeout, POSIX resource limits where available,
and writes its report to a private directory outside the scanned tree.
"""
import contextlib
import io
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

from .evidence import token

PACKAGE = Path(__file__).resolve().parent
LOCK_FILE = PACKAGE / "engines.lock.json"
RULE_PACK = PACKAGE / "opengrep-v1.yml"
PSSA_SCRIPT = PACKAGE / "engines" / "psscriptanalyzer.ps1"

# Lock entries and --engine-path keys. psscriptanalyzer runs through PowerShell 7 (pwsh).
TOOLS = ("opengrep", "bandit", "gitleaks", "checkov", "shellcheck", "psscriptanalyzer", "trivy",
         "osv-scanner", "syft")
EXECUTABLES = {"psscriptanalyzer": "pwsh"}
# Runnable engines in report order. trivy and trivy-image share the trivy executable.
ENGINES = ("opengrep", "bandit", "gitleaks", "checkov", "shellcheck", "psscriptanalyzer", "trivy",
           "trivy-image", "osv-scanner")
PLATFORMS = ("linux-x86_64", "linux-aarch64", "darwin-x86_64", "darwin-arm64", "windows-x86_64")
EXCLUDE = {".git", ".hg", ".svn"}
FILE_LIMIT = 200_000
DOWNLOAD_LIMIT = 2 * 1024 * 1024 * 1024
WRITE_LIMIT = 4 * 1024 * 1024 * 1024
SHELLCHECK_BATCH = 200

PASS_ENV = {"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "LANG", "LC_ALL", "TZ",
            "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROGRAMFILES", "PROGRAMFILES(X86)",
            "PROGRAMW6432", "PROGRAMDATA", "COMMONPROGRAMFILES"}
NETWORK_ENV = {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"}
QUIET_ENV = {"POWERSHELL_TELEMETRY_OPTOUT": "1", "POWERSHELL_UPDATECHECK": "Off",
             "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1", "SEMGREP_SEND_METRICS": "off",
             "OPENGREP_SEND_METRICS": "off", "SYFT_CHECK_FOR_APP_UPDATE": "false",
             "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false", "PYTHONDONTWRITEBYTECODE": "1",
             "NO_COLOR": "1"}

LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
    "bun.lock": "npm", "Pipfile.lock": "PyPI", "poetry.lock": "PyPI", "pdm.lock": "PyPI", "uv.lock": "PyPI",
    "pylock.toml": "PyPI", "Cargo.lock": "crates.io", "go.mod": "Go", "Gemfile.lock": "RubyGems",
    "gems.locked": "RubyGems", "composer.lock": "Packagist", "pom.xml": "Maven", "gradle.lockfile": "Maven",
    "buildscript-gradle.lockfile": "Maven", "verification-metadata.xml": "Maven",
    "packages.lock.json": "NuGet", "packages.config": "NuGet", "mix.lock": "Hex", "pubspec.lock": "Pub",
    "renv.lock": "CRAN", "Package.resolved": "SwiftURL", "conan.lock": "ConanCenter",
    "cabal.project.freeze": "Hackage", "stack.yaml.lock": "Hackage",
}
OSV_DEFAULT_ECOSYSTEMS = ("npm", "PyPI", "crates.io", "Go", "Maven", "NuGet", "RubyGems", "Packagist",
                          "Pub", "Hex")
OSV_DATABASE_URL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"
LANGUAGE_SUFFIXES = {
    "python": (".py", ".pyw", ".pyi"), "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx", ".mts", ".cts"), "rust": (".rs",), "go": (".go",), "java": (".java",),
    "kotlin": (".kt", ".kts"), "ruby": (".rb",), "php": (".php",), "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hh"), "csharp": (".cs",), "bash": (".sh", ".bash"),
    "sh": (".sh",), "scala": (".scala",), "swift": (".swift",), "terraform": (".tf",), "hcl": (".hcl", ".tf"),
    "yaml": (".yml", ".yaml"), "json": (".json",), "dockerfile": ("Dockerfile",), "html": (".html", ".htm"),
}
PSSA_RULES = ("PSAvoidUsingPlainTextForPassword", "PSAvoidUsingConvertToSecureStringWithPlainText",
              "PSAvoidUsingUsernameAndPasswordParams", "PSUsePSCredentialType", "PSAvoidUsingInvokeExpression",
              "PSAvoidUsingComputerNameHardcoded", "PSAvoidUsingAllowUnencryptedAuthentication",
              "PSAvoidUsingBrokenHashAlgorithms")


class EngineError(Exception):
    """A user-facing engine management failure."""


# ---------------------------------------------------------------------------
# Locations, lock file and discovery


def default_cache_dir():
    if os.environ.get("CRAB_CACHE_DIR"):
        return Path(os.environ["CRAB_CACHE_DIR"])
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "crab-risk-scan"


def load_lock(path=LOCK_FILE):
    with open(path, "rb") as stream:
        lock = json.load(stream)
    if lock.get("version") != 1 or not isinstance(lock.get("engines"), dict):
        raise EngineError("unsupported engine lock file")
    return lock


def current_platform():
    system = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(platform.system())
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "x64": "x86_64", "aarch64": "aarch64",
            "arm64": "arm64" if system == "darwin" else "aarch64"}.get(machine)
    key = f"{system}-{arch}"
    if key not in PLATFORMS:
        raise EngineError(f"unsupported platform {platform.system()} {platform.machine()}")
    return key


def executable_name(tool):
    name = EXECUTABLES.get(tool, tool)
    return name + ".exe" if os.name == "nt" else name


def _inside(path, target):
    if target is None:
        return False
    with contextlib.suppress(OSError):
        if Path(path).resolve().is_relative_to(target):
            return True
    return Path(os.path.abspath(path)).is_relative_to(target)


def _usable(path, target):
    path = Path(path)
    try:
        if not path.is_absolute() or not path.is_file() or _inside(path, target):
            return False
    except OSError:
        return False
    return os.name == "nt" and path.suffix.lower() == ".exe" or os.name != "nt" and os.access(path, os.X_OK)


def engine_dirs():
    """CRAB_ENGINE_DIR, then absolute PATH entries."""
    dirs = []
    configured = os.environ.get("CRAB_ENGINE_DIR")
    if configured and Path(configured).is_absolute():
        dirs.append(Path(configured))
    dirs.extend(Path(p) for p in os.get_exec_path() if p and Path(p).is_absolute())
    return dirs


def discover(tool, explicit=None, target=None):
    """Return (path, None) or (None, reason). Executables inside the target are always rejected."""
    target = Path(target).resolve() if target is not None else None
    if explicit is not None:
        return (Path(explicit), None) if _usable(explicit, target) else (None, "invalid_engine_path")
    name = executable_name(tool)
    for folder in engine_dirs():
        candidate = folder / name
        if _usable(candidate, target):
            return candidate, None
    return None, "not_installed"


def module_paths():
    """PowerShell module folders: engines installed next to CRAB_ENGINE_DIR, then the user's modules."""
    paths = []
    configured = os.environ.get("CRAB_ENGINE_DIR")
    if configured and Path(configured).is_absolute():
        paths.append(Path(configured).parent / "modules")
    if os.name == "nt":
        paths.append(Path.home() / "Documents" / "PowerShell" / "Modules")
    else:
        data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        paths.append(Path(data) / "powershell" / "Modules")
    inherited = os.environ.get("PSMODULEPATH", "")
    paths.extend(Path(p) for p in inherited.split(os.pathsep) if p and Path(p).is_absolute())
    return [p for p in dict.fromkeys(paths) if p.is_dir()]


# ---------------------------------------------------------------------------
# Isolated execution


@dataclass
class Workspace:
    root: Path

    @property
    def home(self):
        return self.root / "home"

    @property
    def tmp(self):
        return self.root / "tmp"

    @property
    def cwd(self):
        return self.root / "cwd"

    @property
    def output(self):
        return self.root / "out"


@contextlib.contextmanager
def private_workspace(target=None, parent=None):
    """A private directory tree outside the target for one engine run."""
    root = Path(tempfile.mkdtemp(prefix="crab-engine-", dir=parent))
    try:
        if target is not None and _inside(root, Path(target).resolve()):
            raise EngineError("the temporary directory is inside the scanned directory")
        work = Workspace(root)
        for folder in (work.home, work.tmp, work.cwd, work.output):
            folder.mkdir(mode=0o700)
        yield work
    finally:
        shutil.rmtree(root, ignore_errors=True)


@dataclass
class Outcome:
    returncode: int | None
    timed_out: bool = False


def isolated_env(work, *, target=None, online=False, extra=None):
    env = {}
    allowed = PASS_ENV | (NETWORK_ENV if online else set())
    for key, value in os.environ.items():
        if key.upper() in allowed:
            env[key] = value
    for key in [k for k in env if k.upper() == "PATH"]:
        target_root = Path(target).resolve() if target is not None else None
        env[key] = os.pathsep.join(p for p in env[key].split(os.pathsep)
                                   if p and Path(p).is_absolute() and not _inside(p, target_root))
    home, tmp = str(work.home), str(work.tmp)
    env.update({"HOME": home, "USERPROFILE": home, "XDG_CONFIG_HOME": home, "XDG_CACHE_HOME": home,
                "XDG_DATA_HOME": home, "APPDATA": home, "LOCALAPPDATA": home, "TMP": tmp, "TEMP": tmp,
                "TMPDIR": tmp})
    env.update(QUIET_ENV)
    env.update(extra or {})
    return env


def _limits(cpu_seconds, write_limit):
    def apply():
        import resource

        def lower(kind, soft, hard):
            # Never raise an inherited hard limit; an unprivileged process cannot.
            current = resource.getrlimit(kind)[1]
            if current != resource.RLIM_INFINITY:
                soft, hard = min(soft, current), min(hard, current)
            resource.setrlimit(kind, (soft, hard))

        lower(resource.RLIMIT_CORE, 0, 0)
        lower(resource.RLIMIT_CPU, cpu_seconds, cpu_seconds + 5)
        if write_limit:
            lower(resource.RLIMIT_FSIZE, write_limit, write_limit)
    return apply


def _kill_tree(process):
    if os.name == "nt":
        taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    else:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        process.kill()


def run_isolated(command, work, *, timeout, target=None, env=None, stdout=None, online=False,
                 write_limit=WRITE_LIMIT):
    """Run one engine command. Diagnostics are discarded because they can quote target source."""
    options = {"cwd": work.cwd, "env": isolated_env(work, target=target, online=online, extra=env),
               "stdin": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        options["start_new_session"] = True
        options["preexec_fn"] = _limits(timeout + 30, write_limit)
    with contextlib.ExitStack() as stack:
        options["stdout"] = stack.enter_context(open(stdout, "wb")) if stdout else subprocess.DEVNULL
        process = subprocess.Popen(command, **options)
        try:
            return Outcome(process.wait(timeout=timeout))
        except subprocess.TimeoutExpired:
            _kill_tree(process)
            process.wait()
            return Outcome(None, timed_out=True)


def probe(command, *, target=None, env=None, timeout=60):
    """Run a version command in isolation and return its stdout text, or None."""
    with private_workspace(target) as work:
        out = work.output / "version.txt"
        try:
            outcome = run_isolated(command, work, timeout=timeout, target=target, env=env, stdout=out)
        except OSError:
            return None
        if outcome.returncode != 0:
            return None
        with out.open("rb") as stream:
            return stream.read(64 * 1024).decode("utf-8", "replace")


def _first_version(text):
    match = re.search(r"\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?", text or "")
    if not match:
        return None
    try:
        return token(match[0])
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Target inventory and applicability


@dataclass
class Files:
    paths: list = field(default_factory=list)
    names: set = field(default_factory=set)
    suffixes: set = field(default_factory=set)
    truncated: bool = False

    def has_suffix(self, *suffixes):
        return any(s in self.suffixes for s in suffixes)

    def matching(self, *suffixes):
        return [p for p in self.paths if PurePosixPath(p).suffix.lower() in suffixes]


def inventory(root):
    files = Files()
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE and not (Path(folder) / d).is_symlink())
        for name in sorted(names):
            path = Path(folder) / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            files.paths.append(rel)
            files.names.add(name)
            files.suffixes.add(PurePosixPath(name).suffix.lower())
            if name.startswith("Dockerfile") or name.endswith(".Dockerfile"):
                files.names.add("Dockerfile")
            if len(files.paths) >= FILE_LIMIT:
                files.truncated = True
                return files
    return files


def ecosystems(files):
    found = {LOCKFILES[name] for name in files.names if name in LOCKFILES}
    if any(re.fullmatch(r"requirements.*\.txt", name) for name in files.names):
        found.add("PyPI")
    if any(name.endswith(".deps.json") for name in files.names):
        found.add("NuGet")
    return found


def rule_pack_suffixes(path=RULE_PACK):
    suffixes = set()
    text = Path(path).read_text(encoding="utf-8")
    for match in re.finditer(r"^\s*languages:\s*\[([^\]]*)\]", text, re.M):
        for language in match[1].split(","):
            suffixes.update(LANGUAGE_SUFFIXES.get(language.strip().strip("'\"").lower(), ()))
    return suffixes


def checkov_frameworks(files, *, online=False):
    frameworks = []
    if files.has_suffix(".tf") or any(p.endswith(".tf.json") for p in files.paths):
        frameworks.append("terraform")
    if files.has_suffix(".bicep"):
        frameworks.append("bicep")
    if "Dockerfile" in files.names:
        frameworks.append("dockerfile")
    if online and "Chart.yaml" in files.names:
        # Checkov renders charts with `helm template --dependency-update`, which downloads chart
        # dependencies from repositories the chart names and writes them into the target.
        frameworks.append("helm")
    if any(re.match(r"\.github/workflows/[^/]+\.ya?ml$", p) for p in files.paths):
        frameworks.append("github_actions")
    if files.has_suffix(".yml", ".yaml"):
        frameworks.extend(["kubernetes", "cloudformation"])
    elif files.has_suffix(".json"):
        frameworks.append("cloudformation")
    if files.has_suffix(".json"):
        frameworks.append("arm")
    return frameworks


# ---------------------------------------------------------------------------
# Engine definitions


@dataclass
class Context:
    engine: str
    executable: Path
    target: Path
    work: Workspace
    report: Path
    files: Files
    cache_dir: Path
    offline: bool
    image: str | None
    version: str | None


@dataclass
class Command:
    argv: list
    stdout: Path | None = None


def _shellcheck_files(files):
    return files.matching(".sh", ".bash", ".ksh", ".bats")


def _powershell_files(files):
    return files.matching(".ps1", ".psm1", ".psd1")


def _trivy_common(ctx):
    # Empty configuration files in the private cwd replace any trivy.yaml or .trivyignore.
    config, ignore = ctx.work.cwd / "trivy.yaml", ctx.work.cwd / ".trivyignore"
    config.write_text("{}\n", encoding="utf-8")
    ignore.write_text("", encoding="utf-8")
    argv = ["--scanners", "vuln", "--format", "json", "--output", str(ctx.report),
            "--cache-dir", str(ctx.cache_dir / "trivy"), "--quiet", "--skip-version-check",
            "--disable-telemetry", "--config", str(config), "--ignorefile", str(ignore)]
    if ctx.offline:
        argv += ["--skip-db-update", "--skip-java-db-update", "--offline-scan"]
    return argv


def build_opengrep(ctx):
    # Opengrep prefixes rule IDs with the config file's folder relative to cwd, so the pack is copied into cwd.
    shutil.copyfile(RULE_PACK, ctx.work.cwd / RULE_PACK.name)
    return [Command([str(ctx.executable), "scan", "--config", RULE_PACK.name, "--json",
                     "--output", str(ctx.report), "--no-git-ignore", "--disable-nosem",
                     "--x-ignore-semgrepignore-files", "--quiet", str(ctx.target)])]


def build_bandit(ctx):
    ini = ctx.work.cwd / "bandit.ini"
    ini.write_text("[bandit]\n", encoding="utf-8")
    return [Command([str(ctx.executable), "-r", str(ctx.target), "-f", "json", "-o", str(ctx.report), "-q",
                     "--ini", str(ini), "--ignore-nosec"])]


def build_gitleaks(ctx):
    config = ctx.work.cwd / "gitleaks.toml"
    config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    return [Command([str(ctx.executable), "dir", str(ctx.target), "--config", str(config), "--redact",
                     "--no-banner", "--no-color", "--log-level", "error", "--ignore-gitleaks-allow",
                     "--gitleaks-ignore-path", str(ctx.work.cwd), "--exit-code", "99",
                     "--report-format", "json", "--report-path", str(ctx.report)])]


def build_checkov(ctx):
    # Checkov adds DIR/.checkov.yaml to its default config files only when it sees a separate
    # "--directory" token. The single "--directory=DIR" form keeps the target's config file out.
    config = ctx.work.cwd / "checkov.yaml"
    config.write_text("{}\n", encoding="utf-8")
    return [Command([str(ctx.executable), f"--directory={ctx.target}", "--config-file", str(config),
                     "--framework", *checkov_frameworks(ctx.files, online=not ctx.offline), "--output", "json",
                     "--quiet", "--compact", "--soft-fail", "--skip-download", "--skip-results-upload",
                     "--download-external-modules", "false"], stdout=ctx.report)]


def build_shellcheck(ctx):
    paths = [str(ctx.target / p) for p in _shellcheck_files(ctx.files)]
    commands = []
    for index in range(0, len(paths), SHELLCHECK_BATCH):
        commands.append(Command([str(ctx.executable), "--norc", "--format=json", "--", *paths[index:index + SHELLCHECK_BATCH]],
                                stdout=ctx.work.output / f"shellcheck-{index // SHELLCHECK_BATCH}.json"))
    return commands


def build_psscriptanalyzer(ctx):
    argv = [str(ctx.executable), "-NoLogo", "-NoProfile", "-NonInteractive"]
    if os.name == "nt":
        argv += ["-ExecutionPolicy", "Bypass"]
    return [Command(argv + ["-File", str(PSSA_SCRIPT), str(ctx.target), str(ctx.report), ",".join(PSSA_RULES)])]


def build_trivy(ctx):
    return [Command([str(ctx.executable), "filesystem", *_trivy_common(ctx), "--pkg-types", "library",
                     str(ctx.target)])]


def build_trivy_image(ctx):
    argv = [str(ctx.executable), "image", *_trivy_common(ctx), "--pkg-types", "os,library"]
    if ctx.offline:
        argv += ["--image-src", "docker,containerd,podman"]
    return [Command(argv + ["--", ctx.image])]


def build_osv(ctx):
    config = ctx.work.cwd / "osv-scanner.toml"
    config.write_text("", encoding="utf-8")
    argv = [str(ctx.executable), "scan", "source", "--recursive", "--format", "json",
            "--output-file", str(ctx.report), "--config", str(config)]
    if ctx.offline:
        argv += ["--offline-vulnerabilities", "--no-resolve"]
    return [Command(argv + [str(ctx.target)])]


def exit_zero(code):
    return "complete" if code == 0 else "failed"


def exit_findings(code):
    # Bandit, ShellCheck and Checkov: 0 clean, 1 findings reported.
    return "complete" if code in (0, 1) else "failed"


def exit_gitleaks(code):
    # Leaks use the --exit-code value 99; Gitleaks reports errors with status 1.
    return "complete" if code in (0, 99) else "failed"


def exit_shellcheck(code):
    # 2 means some files could not be processed; the others were checked.
    return {0: "complete", 1: "complete", 2: "partial"}.get(code, "failed")


def exit_osv(code):
    # 0 clean, 1-126 vulnerabilities found, 128 no packages found, 127 and 129-255 errors.
    if code == 128:
        return "skipped"
    return "complete" if 0 <= code <= 126 else "failed"


def env_osv(ctx):
    # OSV-Scanner reads and stores its offline databases under this folder.
    return {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(ctx.cache_dir / "osv")}


def env_pwsh(ctx):
    return pwsh_env()


@dataclass(frozen=True)
class Engine:
    name: str
    producer: str
    tool: str
    rule_pack: str
    build: object
    classify: object
    applicable: object
    env: object = None


def _applicable_opengrep(files, options):
    suffixes = rule_pack_suffixes()
    return any(s in files.suffixes or s in files.names for s in suffixes)


REGISTRY = {
    "opengrep": Engine("opengrep", "opengrep", "opengrep", "crab-opengrep-v1", build_opengrep, exit_zero,
                       _applicable_opengrep),
    "bandit": Engine("bandit", "bandit", "bandit", "bandit-default", build_bandit, exit_findings,
                     lambda files, options: files.has_suffix(".py", ".pyw")),
    "gitleaks": Engine("gitleaks", "gitleaks", "gitleaks", "gitleaks-default", build_gitleaks, exit_gitleaks,
                       lambda files, options: bool(files.paths)),
    "checkov": Engine("checkov", "checkov", "checkov", "checkov-default", build_checkov, exit_zero,
                      lambda files, options: bool(checkov_frameworks(files, online=not options.offline))),
    "shellcheck": Engine("shellcheck", "shellcheck", "shellcheck", "shellcheck-default", build_shellcheck,
                         exit_shellcheck, lambda files, options: bool(_shellcheck_files(files))),
    "psscriptanalyzer": Engine("psscriptanalyzer", "psscriptanalyzer", "psscriptanalyzer", "crab-pssa-v1",
                               build_psscriptanalyzer, exit_zero,
                               lambda files, options: bool(_powershell_files(files)), env_pwsh),
    "trivy": Engine("trivy", "trivy", "trivy", "trivy-db", build_trivy, exit_zero,
                    lambda files, options: bool(ecosystems(files))),
    "trivy-image": Engine("trivy-image", "trivy-image", "trivy", "trivy-db", build_trivy_image, exit_zero,
                          lambda files, options: bool(options.image)),
    "osv-scanner": Engine("osv-scanner", "osv", "osv-scanner", "osv-offline", build_osv, exit_osv,
                          lambda files, options: bool(ecosystems(files)), env_osv),
}


def parse_selection(value, *, image=None):
    """Validate --engines. Returns auto, all, none or a normalized comma-separated list."""
    value = (value or "auto").strip()
    if value in ("auto", "all", "none"):
        return value
    names = [part.strip() for part in value.split(",") if part.strip()]
    unknown = [n for n in names if n not in REGISTRY]
    if not names or unknown:
        raise ValueError(f"unknown engine {', '.join(unknown) or value!r}; choose from {', '.join(ENGINES)}")
    if "trivy-image" in names and not image:
        raise ValueError("the trivy-image engine requires --image")
    return ",".join(dict.fromkeys(names))


def selected(selection):
    if selection == "none":
        return []
    if selection in ("auto", "all"):
        return list(ENGINES)
    return [name for name in ENGINES if name in selection.split(",")]


def pwsh_env():
    paths = module_paths()
    return {"PSModulePath": os.pathsep.join(map(str, paths))} if paths else {}


def tool_version(tool, executable, *, target=None, cache_dir=None):
    """Detected version of an installed tool, or None."""
    if tool == "psscriptanalyzer":
        script = ("$m = Get-Module -ListAvailable -Name PSScriptAnalyzer | Sort-Object Version -Descending | "
                  "Select-Object -First 1; if ($m) { $m.Version.ToString() } else { exit 3 }")
        return _first_version(probe([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                                     script], target=target, env=pwsh_env()))
    command = {"gitleaks": ["version"], "syft": ["version"]}.get(tool, ["--version"])
    return _first_version(probe([str(executable), *command], target=target))


def trivy_rule_pack(executable, cache_dir, target):
    text = probe([str(executable), "version", "--format", "json", "--cache-dir", str(cache_dir / "trivy")],
                 target=target)
    try:
        updated = json.loads(text)["VulnerabilityDB"]["UpdatedAt"][:10]
        return token("trivy-db@" + updated) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", updated) else "trivy-db"
    except (TypeError, KeyError, ValueError):
        return "trivy-db"


def trivy_database_present(cache_dir):
    return (cache_dir / "trivy" / "db" / "trivy.db").is_file()


def osv_database_present(cache_dir, files):
    wanted = ecosystems(files)
    return bool(wanted) and all((osv_database_dir(cache_dir) / eco / "all.zip").is_file() for eco in wanted)


def osv_database_dir(cache_dir):
    """OSV-Scanner 2.7 stores offline databases in OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scalibr/<ecosystem>."""
    return cache_dir / "osv" / "osv-scalibr"


def _merge_shellcheck(ctx, commands):
    rows = []
    for command in commands:
        with command.stdout.open("rb") as stream:
            data = json.loads(stream.read(16 * 1024 * 1024 + 1))
        if not isinstance(data, list):
            raise ValueError("unexpected ShellCheck output")
        rows.extend(data)
    ctx.report.write_text(json.dumps(rows), encoding="utf-8")


def _normalize_checkov(ctx):
    """Checkov prints a bare summary object when no framework found resources. Treat it as no results."""
    with ctx.report.open("rb") as stream:
        data = json.loads(stream.read(16 * 1024 * 1024 + 1))
    if isinstance(data, dict) and "results" not in data and "check_type" not in data:
        count = data.get("parsing_errors", 0)
        ctx.report.write_text("[]", encoding="utf-8")
        return "partial" if type(count) is int and count > 0 else None
    return None


def run_engine(engine, ctx, timeout):
    """Run one engine. Returns (status, reason). `timeout` bounds all of the engine's commands together."""
    commands = engine.build(ctx)
    env = engine.env(ctx) if engine.env else None
    deadline = time.monotonic() + timeout
    statuses = []
    for command in commands:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "failed", "timeout"
        try:
            outcome = run_isolated(command.argv, ctx.work, timeout=max(1, int(remaining)), target=ctx.target,
                                   env=env, stdout=command.stdout, online=not ctx.offline)
        except OSError:
            return "failed", "launch_failed"
        if outcome.timed_out:
            return "failed", "timeout"
        statuses.append(engine.classify(outcome.returncode))
    if "failed" in statuses:
        return "failed", "exit_status"
    if "skipped" in statuses:
        return "skipped", "no_packages"
    try:
        if engine.name == "shellcheck":
            _merge_shellcheck(ctx, commands)
        if not ctx.report.is_file():
            return "failed", "missing_report"
        if engine.name == "checkov" and _normalize_checkov(ctx) == "partial":
            statuses.append("partial")
    except (OSError, ValueError, RecursionError):
        return "failed", "invalid_report"
    return ("partial" if "partial" in statuses else "complete"), None


def _prepare(engine, options, target, files, cache_dir):
    """Resolve one engine. Returns (meta, executable) or (meta with status and reason, None)."""
    meta = {"origin": "engine", "version": None, "rule_pack": engine.rule_pack}
    if not engine.applicable(files, options):
        return dict(meta, status="skipped", reason="not_applicable"), None
    executable, reason = discover(engine.tool, options.engine_paths.get(engine.tool), target)
    version = tool_version(engine.tool, executable, target=target) if executable else None
    if version is None:
        # `auto` records missing engines as skipped; `all` and explicit names treat them as failures.
        status = "skipped" if options.engines == "auto" else "failed"
        return dict(meta, status=status, reason=reason or "not_installed"), None
    meta["version"] = version
    if _inside(cache_dir, target):
        return dict(meta, status="failed", reason="cache_inside_target"), None
    if engine.tool == "trivy":
        if options.offline and not trivy_database_present(cache_dir):
            return dict(meta, status="failed", reason="database_missing"), None
        meta["rule_pack"] = trivy_rule_pack(executable, cache_dir, target)
    if engine.name == "osv-scanner":
        meta["rule_pack"] = "osv-offline" if options.offline else "osv-online"
        if options.offline and not osv_database_present(cache_dir, files):
            return dict(meta, status="failed", reason="database_missing"), None
    return meta, executable


def run_engines(options, work_root):
    """Run the selected engines for a scan. Returns collect() inputs with origin "engine"."""
    names = selected(options.engines)
    if not names:
        return []
    target = Path(options.directory).resolve()
    files = inventory(target)
    cache_dir = Path(options.cache_dir or default_cache_dir()).resolve()
    unsafe = _inside(work_root, target)
    results = []
    for name in names:
        engine = REGISTRY[name]
        meta, executable = _prepare(engine, options, target, files, cache_dir)
        if executable is not None and unsafe:
            meta, executable = dict(meta, status="failed", reason="work_dir_inside_target"), None
        if executable is None:
            results.append((engine.producer, None, meta))
            continue
        work = Workspace(Path(tempfile.mkdtemp(prefix=name + "-", dir=work_root)))
        for sub in (work.home, work.tmp, work.cwd, work.output):
            sub.mkdir(mode=0o700)
        ctx = Context(name, executable, target, work, work.root / "report.json", files, cache_dir,
                      options.offline, options.image, meta["version"])
        status, reason = run_engine(engine, ctx, options.engine_timeout)
        meta["status"] = status
        if reason:
            meta["reason"] = reason
        results.append((engine.producer, ctx.report if status in ("complete", "partial") else None, meta))
    return results


# ---------------------------------------------------------------------------
# Listing


def describe(engine_paths=None):
    """One record per tool: pinned version, resolved path and detected version."""
    lock = load_lock()["engines"]
    rows = []
    for tool in TOOLS:
        entry = lock.get(tool, {})
        path, reason = discover(tool, (engine_paths or {}).get(tool))
        version = tool_version(tool, path) if path else None
        if path is None:
            status = reason
        elif version is None:
            status = "not_installed" if tool == "psscriptanalyzer" else "version_unknown"
        else:
            status = "ok" if version == entry.get("version") else "version_mismatch"
        rows.append({"name": tool, "pinned": entry.get("version"), "path": str(path) if path else None,
                     "version": version, "status": status,
                     "engines": [name for name in ENGINES if REGISTRY[name].tool == tool]
                     or (["sbom"] if tool == "syft" else [])})
    return rows


# ---------------------------------------------------------------------------
# Installation of pinned engines


def _safe_name(name):
    """Reject absolute, drive-qualified and parent-traversing archive member names."""
    if not name or "\x00" in name:
        raise EngineError("unsafe archive member")
    posix = PurePosixPath(name.replace("\\", "/"))
    if posix.is_absolute() or PureWindowsPath(name).drive or ".." in posix.parts or name.startswith(("/", "\\")):
        raise EngineError(f"unsafe archive member: {name}")
    return posix


def download(url, sha256, destination, *, limit=DOWNLOAD_LIMIT, opener=urllib.request.urlopen):
    """Download to `destination` and verify SHA-256 before the file is used."""
    if not url.startswith(("https://", "http://")):
        raise EngineError(f"unsupported URL scheme: {url}")
    digest = hashlib.sha256()
    size = 0
    try:
        with opener(url, timeout=120) as response, open(destination, "wb") as stream:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise EngineError(f"download exceeds the size limit: {url}")
                digest.update(chunk)
                stream.write(chunk)
    except OSError as exc:
        raise EngineError(f"download failed: {url} ({type(exc).__name__})") from None
    if digest.hexdigest() != sha256.lower():
        Path(destination).unlink(missing_ok=True)
        raise EngineError(f"SHA-256 mismatch for {url}")
    return destination


def _archive_members(archive, fmt):
    """Yield (name, reader) for regular files after validating every member of the archive."""
    if fmt == "zip":
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            for info in infos:
                _safe_name(info.filename)
                if stat.S_ISLNK(info.external_attr >> 16):
                    raise EngineError(f"archive member is a link: {info.filename}")
            for info in infos:
                if not info.is_dir():
                    with bundle.open(info) as stream:
                        yield _safe_name(info.filename).as_posix(), stream
        return
    mode = {"tar.gz": "r:gz", "tar.xz": "r:xz"}.get(fmt)
    if mode is None:
        raise EngineError(f"unsupported archive format {fmt}")
    with tarfile.open(archive, mode) as bundle:
        members = bundle.getmembers()
        for member in members:
            _safe_name(member.name)
            if not (member.isfile() or member.isdir()):
                raise EngineError(f"archive member is not a regular file: {member.name}")
        for member in members:
            if member.isfile():
                with bundle.extractfile(member) as stream:
                    yield _safe_name(member.name).as_posix(), stream


def _write_file(path, stream, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix=".crab-")
    try:
        with os.fdopen(handle, "wb") as out:
            shutil.copyfileobj(stream, out)
        os.chmod(temp, mode)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def extract(archive, fmt, wanted, destination):
    """Extract `wanted` {member name: destination file name}, or every file when wanted is None."""
    found = set()
    for name, stream in _archive_members(archive, fmt):
        if wanted is None:
            _write_file(destination / PurePosixPath(name), stream, 0o644)
            found.add(name)
        elif name in wanted:
            _write_file(destination / wanted[name], stream, 0o755)
            found.add(name)
    missing = set(wanted or ()) - found
    if missing:
        raise EngineError(f"archive is missing {', '.join(sorted(missing))}")


def _install_download(tool, entry, asset, dest, opener):
    binary = dest / "bin" / executable_name(tool)
    fmt = asset.get("format", "binary")
    with tempfile.TemporaryDirectory(dir=dest) as scratch:
        archive = download(asset["url"], asset["sha256"], Path(scratch) / "download", opener=opener)
        if fmt == "binary":
            with open(archive, "rb") as stream:
                _write_file(binary, stream, 0o755)
        else:
            wanted = {asset["member"]: binary.name}
            wanted.update({name: PurePosixPath(name).name for name in asset.get("files", [])})
            extract(archive, fmt, wanted, dest / "bin")
    return binary


def _install_module(tool, entry, asset, dest, opener):
    folder = dest / "modules" / entry["module"] / entry["version"]
    with tempfile.TemporaryDirectory(dir=dest) as scratch:
        archive = download(asset["url"], asset["sha256"], Path(scratch) / "download", opener=opener)
        staging = Path(scratch) / "module"
        extract(archive, asset.get("format", "zip"), None, staging)
        if folder.exists():
            shutil.rmtree(folder)
        folder.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staging), str(folder))
    return folder


def pip_requirements(entry):
    """The packaged hash-locked requirement set for a pip engine. Every pin carries SHA-256 hashes."""
    path = Path(__file__).with_name("engines") / entry["requirements"]
    if path.parent != Path(__file__).with_name("engines") or not path.is_file():
        raise ValueError(f"missing requirement lock for {entry['package']}")
    return path


def _install_pip(tool, entry, dest):
    requirements = pip_requirements(entry)
    venv = dest / "venvs" / tool
    if venv.exists():
        shutil.rmtree(venv)
    # -I and a private working directory keep a checkout in the current directory off sys.path,
    # so its venv/, pip/ or ensurepip/ folders cannot replace the standard modules.
    subprocess.run([sys.executable, "-I", "-m", "venv", str(venv)], check=True, stdin=subprocess.DEVNULL, cwd=dest)
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    # Hash-locked wheels only: a compromised index or transitive release cannot change what runs.
    subprocess.run([str(python), "-I", "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--no-input",
                    "--require-hashes", "--no-deps", "--only-binary", ":all:", "-r", str(requirements)],
                   check=True, stdin=subprocess.DEVNULL, cwd=dest)
    shim = dest / "bin" / executable_name(tool)
    shim.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        launcher = scripts / executable_name(tool)
        if launcher.is_file():
            # pip's console-script launchers embed the absolute interpreter path, so a copy stays bound to the venv.
            with open(launcher, "rb") as stream:
                _write_file(shim, stream, 0o755)
        else:
            _write_file(shim, io.BytesIO(_windows_launcher(venv, python, scripts / tool)), 0o755)
    else:
        script = f"#!/bin/sh\nexec '{scripts / tool}' \"$@\"\n"
        if "'" in str(scripts):
            raise EngineError("the destination path must not contain single quotes")
        _write_file(shim, io.BytesIO(script.encode()), 0o755)
    return shim


def _windows_launcher(venv, python, script):
    """Build a console launcher for a plain Python script, the same way pip builds console-script .exe files:
    distlib's launcher stub, a shebang naming the venv interpreter and a zip archive with __main__.py."""
    machine = platform.machine().lower()
    stub = venv / "Lib" / "site-packages" / "pip" / "_vendor" / "distlib" / (
        "t64-arm.exe" if machine in ("arm64", "aarch64") else "t64.exe")
    main = f"import runpy\nrunpy.run_path({str(script)!r}, run_name='__main__')\n"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("__main__.py", main)
    return stub.read_bytes() + f'#!"{python}"\r\n'.encode() + archive.getvalue()


def install(dest, names=None, platform_key=None, *, lock=None, opener=urllib.request.urlopen, log=print):
    """Install pinned engines into DEST. Returns a list of (tool, status, detail)."""
    dest = Path(dest).resolve()
    lock = (lock or load_lock())["engines"]
    platform_key = platform_key or current_platform()
    if platform_key not in PLATFORMS:
        raise EngineError(f"unknown platform {platform_key}; choose from {', '.join(PLATFORMS)}")
    names = list(names or TOOLS)
    unknown = [n for n in names if n not in lock]
    if unknown:
        raise EngineError(f"unknown engine {', '.join(unknown)}")
    (dest / "bin").mkdir(parents=True, exist_ok=True)
    results = []
    for tool in names:
        entry = lock[tool]
        try:
            kind = entry["install"]
            if kind == "pip":
                if platform_key != current_platform():
                    raise EngineError("pip engines install only for the current platform")
                path = _install_pip(tool, entry, dest)
            else:
                asset = entry["assets"].get(platform_key) or entry["assets"].get("any")
                if asset is None:
                    raise EngineError(f"no {platform_key} release asset")
                installer = _install_module if kind == "module" else _install_download
                path = installer(tool, entry, asset, dest, opener)
            detail = f"{entry['version']} -> {path}"
            if entry.get("requires") and discover(entry["requires"])[0] is None:
                detail += f" (requires {entry['requires']} on PATH)"
            results.append((tool, "installed", detail))
        except (EngineError, OSError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile,
                tarfile.TarError) as exc:
            results.append((tool, "failed", str(exc) or type(exc).__name__))
        log(f"{results[-1][0]}: {results[-1][1]} {results[-1][2]}")
    return results


# ---------------------------------------------------------------------------
# Offline databases


def update_databases(cache_dir=None, directory=None, *, engine_paths=None, timeout=1800,
                     opener=urllib.request.urlopen, log=print):
    """Download the Trivy and OSV databases into the cache. This is the only networked step."""
    cache_dir = Path(cache_dir or default_cache_dir()).resolve()
    target = Path(directory).resolve() if directory else None
    if target is not None and (not target.is_dir() or _inside(cache_dir, target)):
        raise EngineError("DIRECTORY must be a directory that does not contain the cache")
    results = []
    trivy, reason = discover("trivy", (engine_paths or {}).get("trivy"), target)
    if trivy is None:
        results.append(("trivy", "failed", reason))
    else:
        (cache_dir / "trivy").mkdir(parents=True, exist_ok=True)
        status = "updated"
        for flag in ("--download-db-only", "--download-java-db-only"):
            with private_workspace(target) as work:
                outcome = run_isolated([str(trivy), "image", flag, "--cache-dir", str(cache_dir / "trivy"),
                                        "--quiet", "--skip-version-check", "--disable-telemetry"],
                                       work, timeout=timeout, target=target, online=True, write_limit=None)
            if outcome.timed_out or outcome.returncode != 0:
                status = "failed"
        results.append(("trivy", status, str(cache_dir / "trivy")))
    wanted = sorted(ecosystems(inventory(target))) if target else list(OSV_DEFAULT_ECOSYSTEMS)
    failed = []
    for eco in wanted:
        folder = osv_database_dir(cache_dir) / eco
        folder.mkdir(parents=True, exist_ok=True)
        handle, temp = tempfile.mkstemp(dir=folder, prefix=".crab-")
        os.close(handle)
        try:
            _download_unverified(OSV_DATABASE_URL.format(urllib.request.quote(eco)), Path(temp), opener)
            if not zipfile.is_zipfile(temp):
                raise EngineError("not a zip archive")
            os.replace(temp, folder / "all.zip")
        except (EngineError, OSError):
            failed.append(eco)
        finally:
            Path(temp).unlink(missing_ok=True)
    detail = f"{len(wanted) - len(failed)}/{len(wanted)} ecosystems ({', '.join(wanted) or 'none'})"
    results.append(("osv", "failed" if failed else "updated", detail))
    for name, status, info in results:
        log(f"{name}: {status} {info}")
    return results


def _download_unverified(url, destination, opener):
    """OSV publishes rolling database archives without fixed digests; the content is validated as a zip."""
    size = 0
    with opener(url, timeout=300) as response, open(destination, "wb") as stream:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > DOWNLOAD_LIMIT:
                raise EngineError("download exceeds the size limit")
            stream.write(chunk)
