"""Health, authentication, users and API tokens."""
from contextlib import contextmanager
from datetime import timedelta

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from .. import __version__
from .auth import (SCOPES, Paging, Principal, get_db, get_principal, load_project, project_role, require_admin,
                   require_session)
from .db import ApiToken, LoginFailure, Membership, Project, SessionToken, User, utcnow
from .security import (TOKEN_PREFIX, burn_password_check, digest, hash_password, new_secret, normalize_username,
                       validate_password, verify_password)
from .service import ApiError, iso

HASH_WAIT_SECONDS = 5

router = APIRouter()


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginBody(Body):
    username: str = Field(max_length=256)
    password: str = Field(max_length=4096)


class UserCreate(Body):
    username: str
    password: str
    role: str = "member"
    active: bool = True


class UserPatch(Body):
    username: str | None = None
    password: str | None = None
    role: str | None = None
    active: bool | None = None


class TokenCreate(Body):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1, max_length=3)
    project: str | None = None


def user_item(user):
    return {"id": user.id, "username": user.username, "role": user.role, "active": user.active,
            "created_at": iso(user.created_at)}


def me_item(db, user):
    item = user_item(user)
    rows = db.execute(select(Project.key, Membership.role).join(Project, Project.id == Membership.project_id)
                      .where(Membership.user_id == user.id).order_by(Project.key)).all()
    item["memberships"] = [{"project": key, "role": role} for key, role in rows]
    return item


def token_item(db, token):
    project = db.get(Project, token.project_id) if token.project_id else None
    creator = db.get(User, token.created_by_id) if token.created_by_id else None
    return {"id": token.id, "name": token.name, "scopes": token.scopes, "project": project.key if project else None,
            "prefix": token.prefix, "created_by": creator.username if creator else None,
            "created_at": iso(token.created_at), "last_used_at": iso(token.last_used_at)}


def checked(function, value):
    try:
        return function(value)
    except ValueError as exc:
        raise ApiError(422, str(exc)) from None


@router.get("/health")
def health():
    return {"status": "ok", "version": __version__}


@contextmanager
def hashing_slot(request):
    """Bound concurrent scrypt computations. A request that cannot get a slot within a few
    seconds is answered 503 instead of queueing without limit."""
    slots = request.app.state.hash_slots
    if not slots.acquire(timeout=HASH_WAIT_SECONDS):
        raise ApiError(503, "the server is busy; try again shortly", {"Retry-After": str(HASH_WAIT_SECONDS)})
    try:
        yield
    finally:
        slots.release()


def login_buckets(settings, name, client):
    """(kind, key, limit) per throttling bucket: the account, and the client address unless disabled."""
    buckets = [("user", name, settings.login_max_failures)]
    if settings.login_max_failures_per_client and client:
        buckets.append(("client", client[:64], settings.login_max_failures_per_client))
    return buckets


def locked_row(db, kind, key):
    """Failure row under a row lock (SELECT ... FOR UPDATE; SQLite transactions are immediate)."""
    return db.get(LoginFailure, (kind, key), with_for_update=True, populate_existing=True)


def reserve_attempt(db, buckets, now, window):
    """Count the attempt in every bucket before the password check, in one transaction, so
    concurrent requests can never run more checks than the limit allows. Raises 429 when a
    bucket is locked or already at its limit."""
    for _ in range(3):
        refused = None
        try:
            for kind, key, limit in buckets:
                row = locked_row(db, kind, key)
                if row is None:
                    row = LoginFailure(kind=kind, key=key, failures=0, first_failure_at=now)
                    db.add(row)
                    db.flush()
                if row.locked_until is not None and row.locked_until > now:
                    refused = row.locked_until
                elif now - row.first_failure_at > window:
                    row.failures, row.first_failure_at, row.locked_until = 0, now, None
                if refused is None and row.failures >= limit:
                    refused = row.first_failure_at + window
                if refused is not None:
                    break
                row.failures += 1
        except IntegrityError:  # a concurrent request created the same row first
            db.rollback()
            continue
        if refused is not None:
            db.rollback()
            retry = max(1, int((refused - now).total_seconds()) + 1)
            raise ApiError(429, "too many failed sign-in attempts; try again later", {"Retry-After": str(retry)})
        db.commit()
        return
    raise ApiError(503, "the server is busy; try again shortly", {"Retry-After": "1"})


def settle_attempt(db, buckets, now, window, outcome):
    """Resolve a reserved attempt. "failure" keeps the count and locks buckets at their limit;
    "success" clears the account bucket and returns the client reservation; "release" returns
    both reservations (the check never ran). The caller commits."""
    for kind, key, limit in buckets:
        row = locked_row(db, kind, key)
        if row is None:
            continue
        if outcome == "failure":
            if row.failures >= limit:
                row.locked_until = now + window
        elif outcome == "success" and kind == "user":
            db.delete(row)
        else:
            row.failures = max(0, row.failures - 1)


@router.post("/auth/login")
def login(body: LoginBody, request: Request, db=Depends(get_db)):
    settings = request.app.state.settings
    name = body.username.strip().lower()[:64]
    window = timedelta(seconds=settings.login_lockout_seconds)
    buckets = login_buckets(settings, name, request.client.host if request.client else "")
    reserve_attempt(db, buckets, utcnow(), window)
    user = db.scalar(select(User).where(User.username == name))
    db.commit()
    try:
        with hashing_slot(request):
            if user is None:
                burn_password_check(body.password)
                valid = False
            else:
                valid = verify_password(body.password, user.password_hash) and user.active
    except ApiError:
        settle_attempt(db, buckets, utcnow(), window, "release")
        db.commit()
        raise
    now = utcnow()
    if not valid:
        settle_attempt(db, buckets, now, window, "failure")
        db.commit()
        raise ApiError(401, "invalid username or password")
    settle_attempt(db, buckets, now, window, "success")
    db.execute(delete(SessionToken).where(SessionToken.expires_at <= now))
    secret = new_secret()
    expires = now + timedelta(hours=settings.session_hours)
    db.add(SessionToken(token_hash=digest(secret), user_id=user.id, created_at=now, expires_at=expires))
    db.commit()
    return {"token": secret, "expires_at": iso(expires), "user": me_item(db, user)}


@router.post("/auth/logout", status_code=204)
def logout(db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_session(principal)
    db.execute(delete(SessionToken).where(SessionToken.id == principal.session.id))
    db.commit()
    return Response(status_code=204)


@router.get("/auth/me")
def me(db=Depends(get_db), principal: Principal = Depends(get_principal)):
    return me_item(db, require_session(principal))


# Users ----------------------------------------------------------------------------------------

def other_active_admins(db, user_id):
    return db.scalar(select(func.count()).select_from(User).where(
        User.role == "admin", User.active.is_(True), User.id != user_id))


@router.get("/users")
def list_users(paging: Paging = Depends(), db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_admin(principal)
    users, total = paging.apply(db, select(User).order_by(User.username))
    return {"items": [user_item(user) for user in users], "total": total}


@router.post("/users", status_code=201)
def create_user(body: UserCreate, request: Request, db=Depends(get_db),
                principal: Principal = Depends(get_principal)):
    require_admin(principal)
    name = checked(normalize_username, body.username)
    checked(validate_password, body.password)
    if body.role not in ("admin", "member"):
        raise ApiError(422, "role must be admin or member")
    with hashing_slot(request):
        password_hash = hash_password(body.password)
    if db.scalar(select(User).where(User.username == name)):
        raise ApiError(409, "username already exists")
    user = User(username=name, password_hash=password_hash, role=body.role, active=body.active)
    db.add(user)
    db.commit()
    return user_item(user)


def clear_login_failures(db, *usernames):
    db.execute(delete(LoginFailure).where(LoginFailure.kind == "user", LoginFailure.key.in_(set(usernames))))


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, db=Depends(get_db),
                principal: Principal = Depends(get_principal)):
    require_admin(principal)
    password_hash = None
    if body.password is not None:
        checked(validate_password, body.password)
        with hashing_slot(request):
            password_hash = hash_password(body.password)
    user = db.get(User, user_id)
    if user is None:
        raise ApiError(404, "user not found")
    previous_name = user.username
    revoke = False
    if body.username is not None:
        name = checked(normalize_username, body.username)
        if name != user.username and db.scalar(select(User).where(User.username == name)):
            raise ApiError(409, "username already exists")
        user.username = name
    if body.role is not None:
        if body.role not in ("admin", "member"):
            raise ApiError(422, "role must be admin or member")
        if user.role == "admin" and body.role != "admin" and not other_active_admins(db, user.id):
            raise ApiError(409, "cannot remove the last active admin")
        user.role = body.role
    if body.active is not None:
        if not body.active and user.role == "admin" and not other_active_admins(db, user.id):
            raise ApiError(409, "cannot deactivate the last active admin")
        revoke = revoke or not body.active
        user.active = body.active
    if password_hash is not None:
        user.password_hash = password_hash
        revoke = True
    if revoke:
        keep = principal.session.id if user.id == principal.user.id and user.active else None
        db.execute(delete(SessionToken).where(SessionToken.user_id == user.id, SessionToken.id != (keep or -1)))
    clear_login_failures(db, previous_name, user.username)
    user.updated_at = utcnow()
    db.commit()
    return user_item(user)


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    require_admin(principal)
    user = db.get(User, user_id)
    if user is None:
        raise ApiError(404, "user not found")
    if user.id == principal.user.id:
        raise ApiError(409, "cannot delete your own account")
    if user.role == "admin" and not other_active_admins(db, user.id):
        raise ApiError(409, "cannot delete the last active admin")
    db.execute(delete(User).where(User.id == user.id))
    db.commit()
    return Response(status_code=204)


# API tokens -----------------------------------------------------------------------------------

def maintained_project_ids(db, user):
    return set(db.scalars(select(Membership.project_id).where(Membership.user_id == user.id,
                                                              Membership.role == "maintainer")))


@router.get("/tokens")
def list_tokens(project: str | None = Query(None, max_length=64), paging: Paging = Depends(), db=Depends(get_db),
                principal: Principal = Depends(get_principal)):
    user = require_session(principal)
    stmt = select(ApiToken).order_by(ApiToken.id)
    if project is not None:
        stmt = stmt.where(ApiToken.project_id == load_project(db, principal, project, "maintainer").id)
    elif user.role != "admin":
        stmt = stmt.where(ApiToken.project_id.in_(maintained_project_ids(db, user)))
    tokens, total = paging.apply(db, stmt)
    return {"items": [token_item(db, token) for token in tokens], "total": total}


@router.post("/tokens", status_code=201)
def create_token(body: TokenCreate, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    user = require_session(principal)
    scopes = sorted(set(body.scopes))
    if any(scope not in SCOPES for scope in scopes):
        raise ApiError(422, "scopes must be scan:upload, worker or read")
    project = load_project(db, principal, body.project, "viewer") if body.project else None
    if "worker" in scopes and (user.role != "admin" or project is not None):
        raise ApiError(403 if user.role != "admin" else 422,
                       "worker tokens are global and only admins can create them")
    if user.role != "admin":
        if project is None or project_role(db, principal, project) != "maintainer":
            raise ApiError(403, "maintainers can create only tokens bound to their project")
    secret = new_secret(TOKEN_PREFIX)
    token = ApiToken(name=body.name.strip() or "token", token_hash=digest(secret), prefix=secret[:12], scopes=scopes,
                     project_id=project.id if project else None, created_by_id=user.id, created_at=utcnow())
    db.add(token)
    db.commit()
    item = token_item(db, token)
    item["token"] = secret
    return item


@router.delete("/tokens/{token_id}", status_code=204)
def delete_token(token_id: int, db=Depends(get_db), principal: Principal = Depends(get_principal)):
    user = require_session(principal)
    token = db.get(ApiToken, token_id)
    if token is None or (user.role != "admin" and token.project_id not in maintained_project_ids(db, user)):
        raise ApiError(404, "token not found")
    db.execute(delete(ApiToken).where(ApiToken.id == token.id))
    db.commit()
    return Response(status_code=204)
