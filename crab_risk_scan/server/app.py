"""FastAPI application factory."""
import sys
import threading
from contextlib import asynccontextmanager

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .. import __version__
from . import api_auth, api_jobs, api_projects, api_scans, webui
from .config import Settings
from .db import User, initialize, make_engine
from .scheduler import Scheduler
from .security import generated_password, hash_password, normalize_username, validate_password
from .service import ApiError

API_PREFIX = "/api/v1"
BODY_PARSE_SLOTS = 2
SPA_POLICY = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
              "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def bootstrap_admin(sessions, settings, stream=None):
    """Create the first administrator when the user table is empty. A generated password is
    printed once to stderr; it is never stored in clear text."""
    with sessions() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return None
        username = normalize_username(settings.admin_username)
        password = settings.admin_password
        generated = password is None
        if generated:
            password = generated_password()
        else:
            try:
                validate_password(password)
            except ValueError as exc:
                raise RuntimeError(f"CRAB_ADMIN_PASSWORD is not acceptable: {exc}") from None
        db.add(User(username=username, password_hash=hash_password(password), role="admin", active=True))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return None
    if generated:
        print(f"CRAB created the administrator account '{username}'. Initial password (shown once): {password}",
              file=stream or sys.stderr, flush=True)
    return username


def create_app(settings=None):
    settings = settings or Settings.from_env()
    engine = make_engine(settings.database_url)
    sessions = initialize(engine)
    bootstrap_admin(sessions, settings)

    @asynccontextmanager
    async def lifespan(app):
        scheduler = Scheduler(sessions, settings) if settings.scheduler else None
        if scheduler is not None:
            scheduler.start()
        try:
            yield
        finally:
            if scheduler is not None:
                scheduler.stop()
            engine.dispose()

    docs = settings.api_docs
    app = FastAPI(title="CRAB", version=__version__, lifespan=lifespan, docs_url="/api/docs" if docs else None,
                  openapi_url="/api/openapi.json" if docs else None, redoc_url=None)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessions = sessions
    app.state.hash_slots = threading.BoundedSemaphore(settings.password_hash_concurrency)
    app.state.body_slots = anyio.Semaphore(BODY_PARSE_SLOTS)

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError):
        headers = dict(exc.headers or {})
        if exc.status == 401:
            headers.setdefault("WWW-Authenticate", "Bearer")
        return JSONResponse({"detail": exc.detail}, status_code=exc.status, headers=headers)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.path != "/api/docs":
            response.headers.setdefault("Content-Security-Policy", SPA_POLICY)
        return response

    for module in (api_auth, api_projects, api_scans, api_jobs):
        app.include_router(module.router, prefix=API_PREFIX)
    webui.register(app, settings.static_dir)
    return app
