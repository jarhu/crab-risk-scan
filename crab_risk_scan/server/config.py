"""Server settings from command-line arguments and the environment. Standard library only."""
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

UPLOAD_LIMIT = 32 * 1024 * 1024
STATIC_DIR = Path(__file__).with_name("static")
HOST_NAME = re.compile(r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.?")
IPV6 = re.compile(r"[0-9a-f:.]+")


def default_data_dir():
    """Platform user data directory for the server database."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "crab-risk-scan"


def parse_scan_roots(value):
    """Split an os.pathsep-separated list of absolute directories."""
    roots = []
    for part in (value or "").split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        path = Path(part)
        if not path.is_absolute():
            raise ValueError(f"scan roots must be absolute paths: {part}")
        # Keep the configured form: containment also compares against the resolved form.
        roots.append(Path(os.path.normpath(path)))
    return tuple(roots)


def parse_git_host(entry):
    """`host`, `host:port`, `[v6]` or `[v6]:port` as a lowercase (host, port-or-None) pair."""
    text = entry.strip().lower()
    port = None
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"git host entries must be host or host:port: {entry.strip()}")
            port = rest[1:]
        valid = bool(IPV6.fullmatch(host)) and ":" in host
    else:
        host, sep, port_text = text.rpartition(":") if text.count(":") == 1 else (text, "", "")
        if sep:
            port = port_text
        valid = bool(HOST_NAME.fullmatch(host))
    if not valid or (port is not None and not (port.isdigit() and 0 < int(port) < 65536)):
        raise ValueError(f"git host entries must be host or host:port: {entry.strip()}")
    return host.rstrip("."), None if port is None else int(port)


def parse_git_hosts(value):
    """Comma-separated CRAB_GIT_HOSTS list; empty means git sources are rejected."""
    return tuple(parse_git_host(part) for part in (value or "").split(",") if part.strip())


def _number(environ, name, default, kind=int, minimum=1):
    raw = environ.get(name)
    if raw in (None, ""):
        return default
    try:
        value = kind(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number") from None
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _flag(environ, name, default):
    raw = environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


@dataclass
class Settings:
    database_url: str
    data_dir: Path
    scan_roots: tuple = ()
    git_hosts: tuple = ()
    admin_username: str = "admin"
    admin_password: str | None = None
    session_hours: float = 12.0
    lease_seconds: int = 300
    max_attempts: int = 3
    scheduler: bool = True
    scheduler_interval: float = 30.0
    login_max_failures: int = 5
    login_max_failures_per_client: int = 100
    login_lockout_seconds: int = 900
    password_hash_concurrency: int = 4
    upload_limit: int = UPLOAD_LIMIT
    api_docs: bool = False
    static_dir: Path = field(default=STATIC_DIR)

    @classmethod
    def from_env(cls, *, database=None, data_dir=None, environ=None):
        environ = os.environ if environ is None else environ
        data = Path(data_dir or environ.get("CRAB_DATA_DIR") or default_data_dir())
        url = database or environ.get("CRAB_DATABASE_URL") or f"sqlite:///{(data / 'crab.db').as_posix()}"
        return cls(
            database_url=url,
            data_dir=data,
            scan_roots=parse_scan_roots(environ.get("CRAB_SCAN_ROOTS")),
            git_hosts=parse_git_hosts(environ.get("CRAB_GIT_HOSTS")),
            admin_username=(environ.get("CRAB_ADMIN_USERNAME") or "admin").strip().lower(),
            admin_password=environ.get("CRAB_ADMIN_PASSWORD") or None,
            session_hours=_number(environ, "CRAB_SESSION_HOURS", 12.0, float, 0.05),
            lease_seconds=_number(environ, "CRAB_LEASE_SECONDS", 300, int, 10),
            max_attempts=_number(environ, "CRAB_JOB_MAX_ATTEMPTS", 3, int, 1),
            scheduler=_flag(environ, "CRAB_SCHEDULER", True),
            scheduler_interval=_number(environ, "CRAB_SCHEDULER_INTERVAL", 30.0, float, 1),
            login_max_failures_per_client=_number(environ, "CRAB_LOGIN_MAX_FAILURES_PER_CLIENT", 100, int, 0),
            password_hash_concurrency=_number(environ, "CRAB_PASSWORD_HASH_CONCURRENCY", 4, int, 1),
            api_docs=_flag(environ, "CRAB_API_DOCS", False),
        )
