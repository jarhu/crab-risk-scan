"""Server subcommands (`serve`, `worker`, `admin`). Only the standard library loads at import time."""
import getpass
import sys
from pathlib import Path

from .. import worker

MISSING = "The CRAB server needs optional dependencies. Install them with: pip install 'crab-risk-scan[server]'"


def _settings(args):
    """Load server dependencies and settings, or explain how to install them."""
    try:
        import fastapi  # noqa: F401
        import jsonschema  # noqa: F401
        import sqlalchemy  # noqa: F401
        from .config import Settings
    except ImportError as exc:
        print(f"{MISSING} (missing module: {exc.name})", file=sys.stderr)
        return None
    try:
        return Settings.from_env(database=args.database, data_dir=args.data_dir)
    except ValueError as exc:
        print(f"Invalid server configuration: {exc}", file=sys.stderr)
        return None


def run_serve(args):
    settings = _settings(args)
    if settings is None:
        return 2
    try:
        import uvicorn
    except ImportError:
        print(f"{MISSING} (missing module: uvicorn)", file=sys.stderr)
        return 2
    from .app import create_app
    if args.no_scheduler:
        settings.scheduler = False
    try:
        app = create_app(settings)
    except RuntimeError as exc:
        print(f"Server start failed: {exc}", file=sys.stderr)
        return 2
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level,
                forwarded_allow_ips=args.forwarded_allow_ips)
    return 0


def _password(args):
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    elif sys.stdin.isatty():
        password = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != password:
            print("Passwords do not match.", file=sys.stderr)
            return None
    else:
        print("Use --password-stdin when standard input is not a terminal.", file=sys.stderr)
        return None
    return password


def run_admin(args):
    settings = _settings(args)
    if settings is None:
        return 2
    from . import admin
    try:
        if args.admin_command == "create-user":
            password = _password(args)
            if password is None:
                return 2
            print(f"Created user {admin.create_user(settings, args.username, password, args.role)}.")
        elif args.admin_command == "set-password":
            password = _password(args)
            if password is None:
                return 2
            print(f"Password updated for {admin.set_password(settings, args.username, password)}; sessions revoked.")
        elif args.admin_command == "unlock":
            name, removed = admin.unlock(settings, args.username)
            print(f"Sign-in lockout cleared for {name}." if removed else f"{name} had no recorded sign-in failures.")
        elif args.admin_command == "create-token":
            print(admin.create_token(settings, args.name, args.scope, args.project))
            print("Store this token now. It is not shown again.", file=sys.stderr)
        else:
            rows = admin.list_tokens(settings, args.project)
            print(f"{'ID':>4}  {'NAME':<24} {'PREFIX':<13} {'SCOPES':<26} {'PROJECT':<20} LAST USED")
            for row in rows:
                print(f"{row['id']:>4}  {row['name'][:24]:<24} {row['prefix']:<13} {','.join(row['scopes']):<26} "
                      f"{(row['project'] or '-')[:20]:<20} {row['last_used_at'] or 'never'}")
    except admin.AdminError as exc:
        print(f"admin: {exc}", file=sys.stderr)
        return 2
    return 0


def _storage_options(parser):
    parser.add_argument("--database", metavar="URL",
                        help="SQLAlchemy URL (default: CRAB_DATABASE_URL or SQLite in the data directory)")
    parser.add_argument("--data-dir", type=Path, metavar="DIR",
                        help="server data directory (default: CRAB_DATA_DIR or the platform user data directory)")


def add_cli(subparsers):
    """Register the server subcommands on the top-level parser."""
    serve = subparsers.add_parser("serve", help="run the self-hosted API and WebUI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    _storage_options(serve)
    serve.add_argument("--log-level", default="info", choices=("critical", "error", "warning", "info", "debug"))
    serve.add_argument("--no-scheduler", action="store_true",
                       help="do not run the schedule and lease-expiry loop in this instance")
    serve.add_argument("--forwarded-allow-ips", metavar="ADDRESSES",
                       help="comma-separated reverse proxy addresses trusted for X-Forwarded-For and "
                            "X-Forwarded-Proto, or '*' (default: FORWARDED_ALLOW_IPS or 127.0.0.1). Sign-in "
                            "throttling per client relies on it behind a proxy")
    serve.set_defaults(handler=run_serve)

    command = subparsers.add_parser("worker", help="claim and run scan jobs from a CRAB server")
    worker.add_arguments(command)
    command.set_defaults(handler=worker.run)

    admin = subparsers.add_parser("admin", help="manage server users and API tokens")
    actions = admin.add_subparsers(dest="admin_command", required=True)
    create_user = actions.add_parser("create-user", help="create a user")
    create_user.add_argument("username")
    create_user.add_argument("--role", choices=("admin", "member"), default="member")
    create_user.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    set_password = actions.add_parser("set-password", help="set a user's password and revoke their sessions")
    set_password.add_argument("username")
    set_password.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    unlock = actions.add_parser("unlock", help="clear a user's failed sign-in counter and lockout")
    unlock.add_argument("username")
    create_token = actions.add_parser("create-token", help="create an API token and print it once")
    create_token.add_argument("name")
    create_token.add_argument("--scope", action="append", required=True, choices=("scan:upload", "worker", "read"))
    create_token.add_argument("--project", metavar="KEY", help="bind the token to one project")
    list_tokens = actions.add_parser("list-tokens", help="list API tokens without their secrets")
    list_tokens.add_argument("--project", metavar="KEY")
    for parser in (create_user, set_password, unlock, create_token, list_tokens):
        _storage_options(parser)
    admin.set_defaults(handler=run_admin)
