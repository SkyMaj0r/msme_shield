"""
auth.py
-------
Authentication utilities for MSME Shield.

Functions:
    get_password_hash(password)  — bcrypt hash (direct, no passlib)
    verify_password(plain, hash) — bcrypt verify
    create_access_token(data)    — HS256 JWT via python-jose
    get_current_org(token)       — FastAPI dependency: decodes Bearer JWT

Why no passlib: passlib 1.7.4 (last release 2020) reads bcrypt.__about__
which was removed in bcrypt 4.x.  We call bcrypt directly instead.

All secrets come from environment variables (JWT_SECRET, JWT_ALGORITHM).
Never hardcode secrets here.

Import rule: absolute imports only (uvicorn CWD = backend/).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

load_dotenv()

_JWT_SECRET: str = os.getenv("JWT_SECRET", "")
_JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
_TOKEN_EXPIRE_HOURS: int = 24

if not _JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set in the environment / .env file.")

_bearer_scheme = HTTPBearer()


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def get_password_hash(password: str) -> str:
    """Return a bcrypt hash of *password* as a UTF-8 string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the stored bcrypt *hashed* value."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(data: dict) -> str:
    """
    Encode *data* into a signed JWT with a 24-hour expiry.

    Always adds an 'exp' claim; callers should supply at least 'sub'.
    """
    payload = dict(data)
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=_TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def get_current_org(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> dict:
    """
    FastAPI dependency that validates a Bearer JWT and returns its payload.

    Raises HTTP 401 if the token is missing, invalid, or expired.
    """
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            credentials.credentials,
            _JWT_SECRET,
            algorithms=[_JWT_ALGORITHM],
        )
        if "sub" not in payload:
            raise exc
        return payload
    except JWTError:
        raise exc
