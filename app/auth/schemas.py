"""Pydantic request/response models for the auth surface."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

# --- Password policy -----------------------------------------------------
# Industry-standard strength gate, enforced server-side on every surface
# that *sets* a password (admin create, admin reset, user change). The
# dashboard mirrors this with a live strength meter, but the server is the
# source of truth — a direct API call with a weak password is rejected.
PASSWORD_MIN_LENGTH = 12

_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
_DIGIT = re.compile(r"[0-9]")
_SYMBOL = re.compile(r"[^A-Za-z0-9]")


def validate_password_strength(pw: str) -> str:
    """Enforce ≥12 chars + at least one upper, lower, digit, and symbol.

    Returns the password unchanged on success; raises ``ValueError`` with a
    human-readable list of what's missing otherwise (Pydantic surfaces it as
    a 422)."""
    missing: list[str] = []
    if len(pw) < PASSWORD_MIN_LENGTH:
        missing.append(f"at least {PASSWORD_MIN_LENGTH} characters")
    if not _UPPER.search(pw):
        missing.append("an uppercase letter")
    if not _LOWER.search(pw):
        missing.append("a lowercase letter")
    if not _DIGIT.search(pw):
        missing.append("a number")
    if not _SYMBOL.search(pw):
        missing.append("a symbol")
    if missing:
        raise ValueError("Password must contain " + ", ".join(missing) + ".")
    return pw


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=256)

    @field_validator("new_password")
    @classmethod
    def _strong(cls, v: str) -> str:
        return validate_password_strength(v)


class CreateUserRequest(BaseModel):
    """Admin → create a SOC analyst account. ``role`` is intentionally absent:
    the server hard-codes ``analyst`` so this endpoint can never mint admins."""

    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=256)

    @field_validator("password")
    @classmethod
    def _strong(cls, v: str) -> str:
        return validate_password_strength(v)


class ResetPasswordRequest(BaseModel):
    """Admin → set a new temporary password for an analyst account."""

    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=256)

    @field_validator("password")
    @classmethod
    def _strong(cls, v: str) -> str:
        return validate_password_strength(v)


class SetActiveRequest(BaseModel):
    is_active: bool


class UserOut(BaseModel):
    id: int
    username: str
    role: Literal["admin", "analyst"]
    is_active: bool
    must_change_password: bool = False
    created_at: datetime | None = None
    last_login_at: datetime | None = None

    class Config:
        from_attributes = True
