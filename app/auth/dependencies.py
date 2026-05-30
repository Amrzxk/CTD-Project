"""FastAPI dependencies that gate route access by authentication / role.

Two main exports:

* ``require_user`` — returns the authenticated ``User`` row or raises 401.
  Use on any route that needs login.
* ``require_admin`` — same, plus enforces ``role == 'admin'`` (raises 403).
  Use on destructive admin endpoints (e.g. DELETE /suppressions/{id},
  POST /_debug/clear).

The cookie ``hids_session`` is the single auth transport. ``Authorization``
headers are not supported by design — the dashboard is the only client
and the cookie path is the right one for browsers.
"""
from __future__ import annotations

import logging

from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.db.models import User
from app.db.repositories import users as users_repo
from .security import SESSION_COOKIE_NAME, JWTError, decode_session_token

log = logging.getLogger(__name__)

# Redis key prefix for the per-token logout denylist. Mirrors the writer in
# app/api/auth.py (logout).
REVOKED_JTI_PREFIX = "revoked_jti:"


async def _jti_is_revoked(request: Request, jti: str | None) -> bool:
    """True if this token's jti is on the logout denylist.

    Fails open when Redis is unavailable — the coarser token_version check
    (DB-backed) still provides revocation, so a Redis outage degrades the
    single-session logout guarantee but never locks every analyst out.
    """
    if not jti:
        return False
    redis = getattr(request.app.state, "redis_pool", None)
    if redis is None:
        return False
    try:
        return bool(await redis.exists(f"{REVOKED_JTI_PREFIX}{jti}"))
    except Exception:
        log.debug("jti denylist probe failed; treating as not-revoked", exc_info=True)
        return False

# Repeated 401 / 403 responses — define once so we don't drift in detail
# strings across routes.
_UNAUTH = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
)
_FORBIDDEN = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Admin role required",
)


async def get_current_user(
    request: Request,
    hids_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Resolve the authenticated user from the session cookie.

    Revocation is enforced on three independent axes so a stolen or stale
    cookie can be killed without waiting for the 8h JWT to expire:

    * ``is_active`` — a deactivated account 401s on its next request.
    * ``token_version`` — a password change / "log out everywhere" bumps the
      user row; tokens carrying an older version are rejected.
    * per-token ``jti`` denylist — single-session logout (Redis-backed).
    """
    if not hids_session:
        raise _UNAUTH
    try:
        claims = decode_session_token(hids_session)
    except JWTError:
        raise _UNAUTH

    sub = claims.get("sub")
    if not sub:
        raise _UNAUTH
    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise _UNAUTH

    user = await users_repo.get_by_id(session, user_id)
    if user is None or not user.is_active:
        raise _UNAUTH

    # token_version: missing claim is treated as 0 so tokens minted before this
    # feature shipped (and never password-changed) still authenticate.
    token_version = int(claims.get("token_version", 0) or 0)
    if token_version != int(user.token_version):
        raise _UNAUTH

    if await _jti_is_revoked(request, claims.get("jti")):
        raise _UNAUTH

    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """Require an authenticated user *with* the admin role."""
    if user.role != "admin":
        raise _FORBIDDEN
    return user


# Convenience alias so route signatures read naturally:
#   async def handler(user: User = require_user) -> ...
# is too cute (a Depends() can't be used as a default value here). Stick
# with the explicit Depends(get_current_user).
__all__ = ["get_current_user", "require_admin"]
