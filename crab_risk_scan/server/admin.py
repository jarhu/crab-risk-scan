"""Administrative operations behind `crab-risk-scan admin`."""
from sqlalchemy import delete, select

from .auth import SCOPES
from .db import ApiToken, LoginFailure, Project, SessionToken, User, initialize, make_engine, utcnow
from .security import TOKEN_PREFIX, digest, hash_password, new_secret, normalize_username, validate_password
from .service import iso


class AdminError(Exception):
    pass


def _sessions(settings):
    return initialize(make_engine(settings.database_url))


def create_user(settings, username, password, role="member"):
    if role not in ("admin", "member"):
        raise AdminError("role must be admin or member")
    try:
        name = normalize_username(username)
        validate_password(password)
    except ValueError as exc:
        raise AdminError(str(exc)) from None
    with _sessions(settings)() as db:
        if db.scalar(select(User).where(User.username == name)):
            raise AdminError(f"user {name} already exists")
        db.add(User(username=name, password_hash=hash_password(password), role=role, active=True))
        db.commit()
    return name


def set_password(settings, username, password):
    try:
        name = normalize_username(username)
        validate_password(password)
    except ValueError as exc:
        raise AdminError(str(exc)) from None
    with _sessions(settings)() as db:
        user = db.scalar(select(User).where(User.username == name))
        if user is None:
            raise AdminError(f"user {name} does not exist")
        user.password_hash = hash_password(password)
        user.updated_at = utcnow()
        db.execute(delete(SessionToken).where(SessionToken.user_id == user.id))
        db.execute(delete(LoginFailure).where(LoginFailure.kind == "user", LoginFailure.key == name))
        db.commit()
    return name


def unlock(settings, username):
    """Clear the sign-in failure counter and lockout of one account. Returns whether one existed."""
    name = (username or "").strip().lower()[:64]
    if not name:
        raise AdminError("username is required")
    with _sessions(settings)() as db:
        removed = db.execute(delete(LoginFailure).where(LoginFailure.kind == "user",
                                                        LoginFailure.key == name)).rowcount
        db.commit()
    return name, bool(removed)


def create_token(settings, name, scopes, project=None):
    scopes = sorted(set(scopes))
    if not scopes or any(scope not in SCOPES for scope in scopes):
        raise AdminError("scopes must be scan:upload, worker or read")
    if not name or len(name) > 100:
        raise AdminError("token name must be 1 to 100 characters")
    if "worker" in scopes and project:
        raise AdminError("worker tokens cannot be bound to a project")
    with _sessions(settings)() as db:
        project_id = None
        if project:
            row = db.scalar(select(Project).where(Project.key == project))
            if row is None:
                raise AdminError(f"project {project} does not exist")
            project_id = row.id
        secret = new_secret(TOKEN_PREFIX)
        db.add(ApiToken(name=name, token_hash=digest(secret), prefix=secret[:12], scopes=scopes,
                        project_id=project_id, created_at=utcnow()))
        db.commit()
    return secret


def list_tokens(settings, project=None):
    with _sessions(settings)() as db:
        stmt = select(ApiToken, Project.key).outerjoin(Project, Project.id == ApiToken.project_id).order_by(ApiToken.id)
        if project:
            stmt = stmt.where(Project.key == project)
        return [{"id": token.id, "name": token.name, "prefix": token.prefix, "scopes": token.scopes, "project": key,
                 "created_at": iso(token.created_at), "last_used_at": iso(token.last_used_at)}
                for token, key in db.execute(stmt)]
