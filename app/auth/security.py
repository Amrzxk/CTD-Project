"""Password hashing + session-token primitives.

Argon2id for password storage (OWASP recommendation as of 2025) via the
``argon2-cffi`` library, and HS256 JWT session tokens via ``python-jose``.
The JWT lives in an httpOnly + SameSite=Strict cookie set by
``POST /auth/login`` — see ``app/api/auth.py``.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from jose import jwt
from jose.exceptions import JWTError

# Argon2 parameters — moderate cost. Production-realistic without being
# painful in tests. ``argon2-cffi`` will accept stored hashes with
# different parameters and auto-rehash on next verify if we tighten these.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=4,
    hash_len=32,
)

_ALG = "HS256"


def _secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        # Fail loudly. A blank secret would let anyone forge tokens.
        raise RuntimeError(
            "JWT_SECRET is not set. Configure it in .env (see app/.env.example) "
            "before running the API."
        )
    return secret


# ----------------------------------------------------------------------
# Password hashing
# ----------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Argon2id-hash a plaintext password. Returns the encoded string
    that's safe to store in the DB."""
    return _HASHER.hash(plain)


def verify_password(plain: str, stored_hash: str) -> bool:
    """True iff the plaintext matches. Constant-time inside argon2."""
    try:
        return _HASHER.verify(stored_hash, plain)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """If we tighten the argon2 parameters above, this tells callers to
    re-hash on next successful verify."""
    try:
        return _HASHER.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# ----------------------------------------------------------------------
# Session tokens
# ----------------------------------------------------------------------

# Cookie name — kept in one place so the auth endpoint and the dependency
# never drift.
SESSION_COOKIE_NAME = "hids_session"
# Default token lifetime: 8h, roughly one SOC shift. Tunable via env in
# case a deployment wants shorter sessions.
_DEFAULT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", str(8 * 3600)))


def create_session_token(
    *,
    user_id: int,
    role: str,
    token_version: int = 0,
    ttl_seconds: int | None = None,
) -> str:
    """Mint an HS256 JWT for this user. Payload mirrors RFC 7519 claims
    (``sub``, ``iat``, ``exp``, ``jti``) plus custom ``role`` and
    ``token_version`` claims.

    ``jti`` is a unique token id so a single session can be revoked on logout
    (Redis denylist). ``token_version`` is compared against the user row on
    every request so a password change / "log out everywhere" invalidates all
    outstanding tokens at once without enumerating their jtis.
    """
    ttl = ttl_seconds or _DEFAULT_TTL_SECONDS
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "token_version": int(token_version),
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
    }
    return jwt.encode(payload, _secret(), algorithm=_ALG)


def decode_session_token(token: str) -> dict:
    """Verify + decode. Raises ``JWTError`` (or subclass) on any failure;
    callers translate to HTTPException(401)."""
    return jwt.decode(token, _secret(), algorithms=[_ALG])


def revocation_ttl_seconds(claims: dict) -> int:
    """Seconds a denylist entry for this token should live: its remaining
    lifetime. Falls back to the default TTL if ``exp`` is absent. Always
    ≥ 1 so the SETEX never rejects a zero/negative TTL."""
    exp = claims.get("exp")
    if exp is None:
        return _DEFAULT_TTL_SECONDS
    remaining = int(exp) - int(datetime.now(timezone.utc).timestamp())
    return max(1, remaining)


__all__ = [
    "SESSION_COOKIE_NAME",
    "hash_password",
    "verify_password",
    "needs_rehash",
    "create_session_token",
    "decode_session_token",
    "revocation_ttl_seconds",
    "JWTError",
]
