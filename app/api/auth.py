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

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.auth.schemas import ChangePasswordRequest, LoginRequest, UserOut
from app.auth.security import (
    SESSION_COOKIE_NAME,
    create_session_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.db import get_session
from app.db.models import User
from app.db.repositories import users as users_repo

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


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
    body: LoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
):
    """Verify credentials, issue session cookie.

    Constant-time-ish failure delay on bad credentials so an attacker
    can't easily distinguish "unknown user" from "wrong password" by
    timing. We don't reveal which side failed in the error body either.
    """
    user = await users_repo.get_by_username(session, body.username)
    ok = False
    if user is not None and user.is_active:
        ok = verify_password(body.password, user.password_hash)

    if not ok:
        # Sleep ~250ms ± jitter so a successful and a failed login take
        # comparable wall time. Cheap user-enumeration defence.
        await asyncio.sleep(0.2 + secrets.randbelow(100) / 1000.0)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    assert user is not None  # narrowed by `ok`
    # Upgrade the stored hash if argon2 parameters have changed since
    # the password was last stored. Transparent rehash on next login.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    await users_repo.update_last_login(session, user.id)
    token = create_session_token(user_id=user.id, role=user.role)
    _set_session_cookie(response, token)
    log.info("auth: %s logged in (role=%s)", user.username, user.role)

    return UserOut.model_validate(user)


@router.post("/logout")
async def logout(response: Response):
    """Clear the session cookie. Server-side state is stateless JWT, so
    there's nothing else to invalidate (see plan's notes on
    token-revocation tradeoffs)."""
    _clear_session_cookie(response)
    return {"ok": True}


@router.get("/me")
async def me(user: User = Depends(get_current_user)) -> UserOut:
    """Current session's identity. Used by the dashboard's AuthContext
    on app-load to decide between the login screen and the queue."""
    return UserOut.model_validate(user)


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not verify_password(body.old_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Old password is incorrect",
        )
    user.password_hash = hash_password(body.new_password)
    log.info("auth: %s changed password", user.username)
    return {"ok": True}
