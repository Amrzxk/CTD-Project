"""First-run admin seed.

Runs on FastAPI startup *after* migrations have been applied. If the
users table is empty AND ``ADMIN_USERNAME`` + ``ADMIN_PASSWORD`` are
both set in the environment, creates one admin user with that name and
password.

Never overwrites an existing admin — a previously-seeded deployment
can rotate credentials via ``POST /auth/change-password`` (or by direct
SQL), but won't lose them to a container restart that happens to have
different ``ADMIN_PASSWORD`` env.

If the env vars are missing on a fresh DB, we log a loud warning and
return; the operator gets 401 on every endpoint until they fix it.
That's a more honest failure mode than auto-creating a default-password
admin.
"""
from __future__ import annotations

import logging
import os

from app.auth.security import hash_password
from app.db import SessionLocal
from app.db.repositories import users as users_repo

log = logging.getLogger(__name__)


async def seed_initial_admin() -> None:
    """Idempotent bootstrap. Safe to call on every API startup."""
    username = (os.getenv("ADMIN_USERNAME") or "").strip()
    password = os.getenv("ADMIN_PASSWORD") or ""

    async with SessionLocal() as session:
        try:
            if await users_repo.has_any(session):
                # Already seeded (or has users that we shouldn't disturb).
                return

            if not username or not password:
                log.warning(
                    "users table is empty and ADMIN_USERNAME/ADMIN_PASSWORD are not "
                    "both set in the environment. The API will reject all requests "
                    "until at least one user is created."
                )
                return

            user = await users_repo.create(
                session,
                username=username,
                password_hash=hash_password(password),
                role="admin",
            )
            await session.commit()
            log.info("seeded initial admin user: %s (id=%s)", user.username, user.id)
        except Exception:
            await session.rollback()
            log.exception("admin seed failed")
