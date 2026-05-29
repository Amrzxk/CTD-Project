"""Pydantic request/response models for the auth surface."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=256)


class UserOut(BaseModel):
    id: int
    username: str
    role: Literal["admin", "analyst"]
    is_active: bool
    last_login_at: datetime | None = None

    class Config:
        from_attributes = True
