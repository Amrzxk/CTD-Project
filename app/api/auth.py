"""Auth HTTP surface: login / logout / me / change-password.

Cookie-based session — the JWT lives in an httpOnly, SameSite=Strict
cookie set on POST /auth/login. There is no Authorization-header path
by design (the dashboard is the only client).
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import REVOKED_JTI_PREFIX, get_current_user
from app.auth.schemas import ChangePasswordRequest, LoginRequest, UserOut
from app.auth.security import (
    SESSION_COOKIE_NAME,
    create_session_token,
    decode_session_token,
    hash_password,
    needs_rehash,
    revocation_ttl_seconds,
    verify_password,
)
from app.db import get_session
from app.db.models import User
from app.db.repositories import users as users_repo

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# --- Login rate-limiting -------------------------------------------------
# Redis-backed sliding-ish window: count failed logins per client IP and
# lock the IP out for the remainder of the window once it crosses the cap.
# Tunable via env so a NAT'd office can loosen it. Pure Redis — no new dep.
_LOGIN_FAIL_WINDOW_S = int(os.getenv("LOGIN_FAIL_WINDOW_S", "900"))   # 15 min
_LOGIN_FAIL_MAX = int(os.getenv("LOGIN_FAIL_MAX", "10"))
_LOGIN_FAIL_PREFIX = "login_fail:"


def _client_ip(request: Request) -> str:
    """Best-effort client IP. Behind Caddy/nginx the real address is in
    X-Forwarded-For (first hop); fall back to the socket peer."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _login_throttle_check(request: Request) -> None:
    """Raise 429 if this IP has too many recent failed logins."""
    redis = getattr(request.app.state, "redis_pool", None)
    if redis is None:
        return
    key = f"{_LOGIN_FAIL_PREFIX}{_client_ip(request)}"
    try:
        count = await redis.get(key)
    except Exception:
        return  # fail open — never lock out on a Redis blip
    if count is not None and int(count) >= _LOGIN_FAIL_MAX:
        ttl = await redis.ttl(key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(max(1, ttl))},
        )


async def _login_record_failure(request: Request) -> None:
    """Increment the failed-login counter for this IP, (re)setting the TTL."""
    redis = getattr(request.app.state, "redis_pool", None)
    if redis is None:
        return
    key = f"{_LOGIN_FAIL_PREFIX}{_client_ip(request)}"
    try:
        n = await redis.incr(key)
        if n == 1:
            await redis.expire(key, _LOGIN_FAIL_WINDOW_S)
    except Exception:
        log.debug("login throttle: incr failed", exc_info=True)


async def _login_clear_failures(request: Request) -> None:
    """Drop the failed-login counter after a successful auth."""
    redis = getattr(request.app.state, "redis_pool", None)
    if redis is None:
        return
    try:
        await redis.delete(f"{_LOGIN_FAIL_PREFIX}{_client_ip(request)}")
    except Exception:
        log.debug("login throttle: clear failed", exc_info=True)


def _cookie_secure() -> bool:
    """True when the deployment is TLS-fronted. Plain-http local dev
    needs this off or the browser silently drops the cookie."""
    return os.getenv("COOKIE_SECURE", "0") == "1"


def _set_session_cookie(response: Response, token: str, max_age_seconds: int = 8 * 3600) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=max_age_seconds,
        path="/",
        httponly=True,
        secure=_cookie_secure(),
        samesite="strict",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=_cookie_secure(),
        samesite="strict",
    )


@router.post("/login")
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    """Verify credentials, issue session cookie.

    Constant-time-ish failure delay on bad credentials so an attacker
    can't easily distinguish "unknown user" from "wrong password" by
    timing. We don't reveal which side failed in the error body either.
    Repeated failures from one IP are rate-limited (429) to blunt
    brute-force attempts against a public endpoint.
    """
    await _login_throttle_check(request)

    user = await users_repo.get_by_username(session, body.username)
    ok = False
    if user is not None and user.is_active:
        ok = verify_password(body.password, user.password_hash)

    if not ok:
        await _login_record_failure(request)
        # Sleep ~250ms ± jitter so a successful and a failed login take
        # comparable wall time. Cheap user-enumeration defence.
        await asyncio.sleep(0.2 + secrets.randbelow(100) / 1000.0)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    await _login_clear_failures(request)

    assert user is not None  # narrowed by `ok`
    # Upgrade the stored hash if argon2 parameters have changed since
    # the password was last stored. Transparent rehash on next login.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    await users_repo.update_last_login(session, user.id)
    token = create_session_token(
        user_id=user.id, role=user.role, token_version=user.token_version
    )
    _set_session_cookie(response, token)
    log.info("auth: %s logged in (role=%s)", user.username, user.role)

    return UserOut.model_validate(user)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    hids_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    """Clear the session cookie AND revoke this token server-side.

    Beyond deleting the cookie, the token's ``jti`` is added to a Redis
    denylist for the rest of its lifetime so a copy of the cookie captured
    before logout can't be replayed. Best-effort: if the token is already
    expired/garbage or Redis is down, we still clear the cookie.
    """
    _clear_session_cookie(response)
    if hids_session:
        try:
            claims = decode_session_token(hids_session)
            jti = claims.get("jti")
            redis = getattr(request.app.state, "redis_pool", None)
            if jti and redis is not None:
                await redis.setex(
                    f"{REVOKED_JTI_PREFIX}{jti}",
                    revocation_ttl_seconds(claims),
                    "1",
                )
        except Exception:
            log.debug("logout: could not denylist token", exc_info=True)
    return {"ok": True}


@router.get("/me")
async def me(response: Response, user: User = Depends(get_current_user)) -> UserOut:
    """Current session's identity. Used by the dashboard's AuthContext
    on app-load to decide between the login screen and the queue."""
    # Identity must never be served from a cache — a logged-out user could
    # otherwise see a stale "still logged in" view.
    response.headers["Cache-Control"] = "no-store"
    return UserOut.model_validate(user)


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    response: Response,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Old password is incorrect",
        )
    user.password_hash = hash_password(body.new_password)
    # A user who just set their own password has satisfied any forced-change
    # requirement (new SOC account / admin reset), so clear the flag.
    user.must_change_password = False
    # Invalidate every existing session for this user (a password change
    # should log out other devices), then re-issue a fresh cookie for the
    # device that made the change so it stays signed in.
    user.token_version = int(user.token_version) + 1
    token = create_session_token(
        user_id=user.id, role=user.role, token_version=user.token_version
    )
    _set_session_cookie(response, token)
    log.info("auth: %s changed password (sessions invalidated)", user.username)
    return {"ok": True}
