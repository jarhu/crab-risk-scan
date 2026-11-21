"""Request authentication and role checks."""
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, Query, Request
from sqlalchemy import func, select

from .db import ApiToken, Membership, Project, SessionToken, User, utcnow
from .security import TOKEN_PREFIX, digest, same
from .service import ApiError

ROLE_RANK = {"viewer": 1, "maintainer": 2, "admin": 3}
SCOPES = ("scan:upload", "worker", "read")


@dataclass
class Principal:
    user: User | None = None
    token: ApiToken | None = None
    session: SessionToken | None = None

    @property
    def is_admin(self):
        return self.token is None and self.user is not None and self.user.role == "admin"

    def scope(self, name):
        return self.token is not None and name in self.token.scopes


def get_db(request: Request):
    db = request.app.state.sessions()
    try:
        yield db
    finally:
        db.close()


def creator_still_entitled(db, token):
    """Tokens created through the API stay valid only while their creator could create them now:
    the creator is active, and a non-admin creator still maintains the token's project. Global
    tokens need an admin creator. CLI-created tokens have no creator and are unaffected."""
    if token.created_by_id is None:
        return True
    creator = db.get(User, token.created_by_id)
    if creator is None or not creator.active:
        return False
    if creator.role == "admin":
        return True
    if token.project_id is None:
        return False
    return db.scalar(select(Membership.role).where(Membership.project_id == token.project_id,
                                                   Membership.user_id == creator.id)) == "maintainer"


def get_principal(request: Request, db=Depends(get_db)):
    """Resolve the bearer secret to a user session or an API token. The transaction ends before
    returning so long request bodies never hold a database lock."""
    scheme, _, secret = request.headers.get("authorization", "").partition(" ")
    secret = secret.strip()
    if scheme.lower() != "bearer" or not secret or len(secret) > 256:
        raise ApiError(401, "authentication required")
    hashed = digest(secret)
    now = utcnow()
    principal = None
    if secret.startswith(TOKEN_PREFIX):
        token = db.scalar(select(ApiToken).where(ApiToken.token_hash == hashed))
        if token is not None and same(token.token_hash, hashed) and creator_still_entitled(db, token):
            if token.last_used_at is None or now - token.last_used_at > timedelta(minutes=1):
                token.last_used_at = now
            principal = Principal(token=token)
    else:
        row = db.execute(select(SessionToken, User).join(User, User.id == SessionToken.user_id)
                         .where(SessionToken.token_hash == hashed)).first()
        if row is not None and same(row[0].token_hash, hashed) and row[0].expires_at > now and row[1].active:
            principal = Principal(user=row[1], session=row[0])
    db.commit()
    if principal is None:
        raise ApiError(401, "invalid or expired credentials")
    return principal


def require_session(principal):
    if principal.user is None:
        raise ApiError(403, "this action requires a signed-in user")
    return principal.user


def require_admin(principal):
    require_session(principal)
    if principal.user.role != "admin":
        raise ApiError(403, "this action requires the admin role")
    return principal.user


def require_worker(principal):
    if not principal.scope("worker"):
        raise ApiError(403, "this action requires a token with the worker scope")
    return principal.token


def project_role(db, principal, project):
    if principal.token is not None:
        if principal.token.project_id not in (None, project.id):
            return None
        return "viewer" if "read" in principal.token.scopes else None
    if principal.user.role == "admin":
        return "admin"
    return db.scalar(select(Membership.role).where(Membership.project_id == project.id,
                                                   Membership.user_id == principal.user.id))


def load_project(db, principal, key, need="viewer", *, upload=False):
    """Project by key with at least role `need`. Invisible projects answer 404."""
    project = db.scalar(select(Project).where(Project.key == key))
    if project is None:
        raise ApiError(404, "project not found")
    if upload and principal.scope("scan:upload") and principal.token.project_id in (None, project.id):
        return project
    role = project_role(db, principal, project)
    if role is None:
        raise ApiError(404, "project not found")
    if ROLE_RANK[role] < ROLE_RANK[need]:
        raise ApiError(403, f"this action requires the {need} role on the project")
    return project


def visible_projects(principal):
    """SELECT of the projects this principal may read."""
    if principal.is_admin:
        return select(Project)
    if principal.token is not None:
        if "read" not in principal.token.scopes:
            raise ApiError(403, "this token lacks the read scope")
        if principal.token.project_id is None:
            return select(Project)
        return select(Project).where(Project.id == principal.token.project_id)
    return select(Project).join(Membership, Membership.project_id == Project.id) \
        .where(Membership.user_id == principal.user.id)


class Paging:
    def __init__(self, page: int = Query(1, ge=1, le=100000), page_size: int = Query(50, ge=1, le=500)):
        self.page = page
        self.size = page_size

    def apply(self, db, stmt, scalars=True):
        total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))
        stmt = stmt.offset((self.page - 1) * self.size).limit(self.size)
        rows = db.scalars(stmt).all() if scalars else db.execute(stmt).all()
        return rows, total
