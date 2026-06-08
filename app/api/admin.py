"""Admin-only user management.

Lets an admin mint SOC analyst accounts, list/enable/disable them, and reset
their passwords. Every route is gated by ``require_admin`` (403 for analysts)
and every mutation writes a ``user_admin_history`` audit row.

Security notes:

* ``role`` is hard-coded to ``analyst`` on create — the body has no role
  field, so this endpoint can never be used to mint another admin.
* Admin accounts are immutable here (can't be disabled or password-reset)
  so an admin can't lock the platform out of its only privileged account.
* The plaintext password is supplied by the dashboard (typed or
  client-generated) and is **never** returned or logged — only the argon2
  hash is persisted.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_admin
from app.auth.schemas import (
    CreateUserRequest,
    ResetPasswordRequest,
    SetActiveRequest,
    UserOut,
)
from app.auth.security import hash_password
from app.db import get_session
from app.db.models import User
from app.db.repositories import user_admin_history as audit_repo
from app.db.repositories import users as users_repo

log = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/users", tags=["admin"])


@router.get("")
async def list_users(
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> list[UserOut]:
    """Every account (active or not) for the management table."""
    users = await users_repo.list_all(session)
    return [UserOut.model_validate(u) for u in users]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> UserOut:
    """Create a SOC analyst account with an admin-set temporary password.
    The user is forced to change it on first login."""
    existing = await users_repo.get_by_username(session, body.username)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that username already exists.",
        )
    user = await users_repo.create(
        session,
        username=body.username,
        password_hash=hash_password(body.password),
        role="analyst",
        must_change_password=True,
    )
    await audit_repo.record(
        session,
        actor_id=admin.id,
        target_id=user.id,
        target_username=user.username,
        action="create",
    )
    await session.commit()
    log.info("admin %s created analyst %s", admin.username, user.username)
    return UserOut.model_validate(user)


@router.post("/{user_id}/active")
async def set_user_active(
    user_id: int,
    body: SetActiveRequest,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> UserOut:
    """Enable or disable an analyst account. Disabling invalidates the
    user's live sessions. Admin accounts are immutable here."""
    target = await users_repo.get_by_id(session, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin accounts cannot be enabled/disabled here.",
        )
    await users_repo.set_active(session, user_id, body.is_active)
    await audit_repo.record(
        session,
        actor_id=admin.id,
        target_id=target.id,
        target_username=target.username,
        action="enable" if body.is_active else "disable",
    )
    await session.commit()
    log.info(
        "admin %s %s analyst %s",
        admin.username,
        "enabled" if body.is_active else "disabled",
        target.username,
    )
    return UserOut.model_validate(target)


@router.post("/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    body: ResetPasswordRequest,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> UserOut:
    """Admin-set a new temporary password and re-arm the forced first-login
    change. Invalidates the user's existing sessions. Admin accounts are
    immutable here."""
    target = await users_repo.get_by_id(session, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin passwords cannot be reset here.",
        )
    await users_repo.reset_password(session, user_id, hash_password(body.password))
    await audit_repo.record(
        session,
        actor_id=admin.id,
        target_id=target.id,
        target_username=target.username,
        action="reset_password",
    )
    await session.commit()
    log.info("admin %s reset password for analyst %s", admin.username, target.username)
    return UserOut.model_validate(target)
