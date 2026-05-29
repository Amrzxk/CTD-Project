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

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.db.models import User
from app.db.repositories import users as users_repo
from .security import SESSION_COOKIE_NAME, JWTError, decode_session_token

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
    hids_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Resolve the authenticated user from the session cookie.

    We always re-fetch the User row by id so a deactivated account
    (``is_active = false``) is revoked immediately — no need to wait for
    the JWT to expire.
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
