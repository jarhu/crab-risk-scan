"""SQLAlchemy 2 persistence: SQLite by default, PostgreSQL through postgresql+psycopg:// URLs."""
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String, Text,
                        UniqueConstraint, create_engine, event, select)
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

SCHEMA_VERSION = 1


def utcnow():
    """Naive UTC timestamp, the storage convention for every DateTime column."""
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


class Base(DeclarativeBase):
    pass


class SchemaInfo(Base):
    __tablename__ = "crab_schema"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    applied_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="member")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class SessionToken(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class LoginFailure(Base):
    """Failed sign-in counter. `kind` separates account buckets ("user") from client buckets
    ("client"), so a username can never collide with a client address."""
    __tablename__ = "login_failures"
    kind: Mapped[str] = mapped_column(String(8), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    first_failure_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    repository_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    default_branch: Mapped[str | None] = mapped_column(String(256), nullable=True)
    scan_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))
    scopes: Mapped[list] = mapped_column(JSON)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("project_id", "user_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    revision: Mapped[str | None] = mapped_column(String(256), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(256), nullable=True)
    source: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    target: Mapped[str] = mapped_column(Text)
    tool_version: Mapped[str] = mapped_column(String(64))
    policy_passed: Mapped[bool] = mapped_column(Boolean)
    violations: Mapped[list] = mapped_column(JSON)
    finding_total: Mapped[int] = mapped_column(Integer)
    new_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    report_gz: Mapped[bytes] = mapped_column(LargeBinary)
    sbom_gz: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    ci: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_project_fingerprint", "project_id", "fingerprint"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    position: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(16))
    producer: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16))
    rule: Mapped[str] = mapped_column(Text)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    package_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    package_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    package_purl: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_new: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    embedded_suppressed: Mapped[bool] = mapped_column(Boolean)
    embedded_expires: Mapped[str | None] = mapped_column(String(10), nullable=True)
    data: Mapped[str] = mapped_column(Text)


class ProjectException(Base):
    __tablename__ = "exceptions"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    justification: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(String(1000))
    reviewer: Mapped[str] = mapped_column(String(64))
    expires: Mapped[str | None] = mapped_column(String(10), nullable=True)
    ticket: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[dict] = mapped_column(JSON)
    options: Mapped[dict] = mapped_column(JSON)
    requires_git: Mapped[bool] = mapped_column(Boolean, default=False)
    worker: Mapped[str | None] = mapped_column(String(64), nullable=True)
    token_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    log: Mapped[str | None] = mapped_column(Text, nullable=True)
    schedule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Worker(Base):
    __tablename__ = "workers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    current_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    capabilities: Mapped[dict] = mapped_column(JSON)
    token_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    cron: Mapped[str] = mapped_column(String(128))
    source: Mapped[dict] = mapped_column(JSON)
    # True when an admin set the source: path sources then need only the scan roots, otherwise
    # they must stay inside the project's scan_path at every run.
    admin_source: Mapped[bool] = mapped_column(Boolean, default=False)
    options: Mapped[dict] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


def make_engine(url):
    """Create an engine. SQLite gets WAL, foreign keys, a busy timeout and immediate transactions
    so that read-then-write sequences (claims, schedule enqueues) serialize instead of failing."""
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        return create_engine(url, pool_pre_ping=True)
    if parsed.database and parsed.database != ":memory:":
        Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

    @event.listens_for(engine, "connect")
    def _connect(dbapi_connection, _record):
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _begin(connection):
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def initialize(engine):
    """Create missing tables and record the schema version. Refuses newer databases."""
    try:
        Base.metadata.create_all(engine)
    except OperationalError:
        # Another instance created the tables concurrently; a second pass sees them.
        Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as session:
        info = session.get(SchemaInfo, 1)
        if info is None:
            session.add(SchemaInfo(id=1, version=SCHEMA_VERSION))
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                info = session.get(SchemaInfo, 1)
        if info is not None and info.version > SCHEMA_VERSION:
            raise RuntimeError(f"database schema {info.version} is newer than this CRAB release "
                               f"(schema {SCHEMA_VERSION}); upgrade crab-risk-scan")
    return factory


def schema_version(factory):
    with factory() as session:
        return session.scalar(select(SchemaInfo.version).where(SchemaInfo.id == 1))
