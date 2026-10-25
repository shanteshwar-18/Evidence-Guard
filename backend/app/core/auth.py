"""
Evidence Guard – Authentication and Authorization (P2.1)

Security:
  - Passwords hashed with Argon2id (preferred) or bcrypt
  - Short-lived access tokens (JWT) + refresh tokens
  - TOTP MFA required for all human users
  - Brute-force protection (lockout after 5 failures)
  - Tokens never appear in logs
  - Permissions driven by docs/contracts/permissions.yaml
  - Service accounts cannot do interactive login
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

import pyotp
import yaml
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Password hashing ──────────────────────────────────────────────────────────
# Argon2id is preferred. Falls back to bcrypt if argon2 is not available.
try:
    pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
except Exception:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plaintext: str) -> str:
    """Hash a password. Never log or return the plaintext."""
    return pwd_context.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """Verify a password against its hash. Constant-time comparison."""
    return pwd_context.verify(plaintext, hashed)


# ── JWT tokens ────────────────────────────────────────────────────────────────
_ALGORITHM = settings.JWT_ALGORITHM
_ACCESS_EXPIRE = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
_REFRESH_EXPIRE = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
_MFA_EXPIRE = timedelta(minutes=5)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: str, username: str, role: str) -> str:
    """Create a short-lived JWT access token."""
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "type": "access",
        "exp": _now() + _ACCESS_EXPIRE,
        "iat": _now(),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=_ALGORITHM)


def create_temp_token(user_id: str, username: str) -> str:
    """Create a short-lived token for MFA step 2."""
    payload = {
        "sub": user_id,
        "username": username,
        "type": "mfa_pending",
        "exp": _now() + _MFA_EXPIRE,
        "iat": _now(),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[_ALGORITHM])
        return payload
    except JWTError as exc:
        logger.debug("JWT decode failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ── MFA (TOTP) ────────────────────────────────────────────────────────────────

def generate_mfa_secret() -> str:
    """Generate a new TOTP secret for a user. Return base32 string."""
    return pyotp.random_base32()


def get_mfa_provisioning_uri(secret: str, username: str) -> str:
    """Return the otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.MFA_ISSUER)


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a TOTP code. Accepts one time-step drift (30 s window).
    A wrong code must NOT reveal whether the password was correct.
    """
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ── Permission system ────────────────────────────────────────────────────────
_PERMISSIONS_PATH = (
    Path(__file__).parent.parent.parent.parent  # repo root
    / "docs" / "contracts" / "permissions.yaml"
)


@lru_cache(maxsize=1)
def _load_permissions() -> dict:
    """Load permissions.yaml once and cache it."""
    try:
        with open(_PERMISSIONS_PATH, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except FileNotFoundError:
        logger.warning("permissions.yaml not found at %s – using empty permissions", _PERMISSIONS_PATH)
        return {"roles": {}, "service_accounts": {}}


def can(role: str, action: str) -> bool:
    """
    Check whether a role is allowed to perform an action.
    This is the SINGLE permission check used everywhere (P2 requirement).
    """
    perms = _load_permissions()
    role_perms = perms.get("roles", {}).get(role, {})
    permissions = role_perms.get("permissions", {})
    return bool(permissions.get(action, False))


# ── FastAPI dependency ────────────────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=True)


class CurrentUser:
    """Data object carried by the authenticated request."""

    def __init__(self, user_id: str, username: str, role: str):
        self.user_id = user_id
        self.username = username
        self.role = role


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> CurrentUser:
    """
    Dependency: validates JWT, returns CurrentUser.
    Use this in every protected endpoint.
    """
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return CurrentUser(
        user_id=payload["sub"],
        username=payload["username"],
        role=payload["role"],
    )


def require_permission(action: str):
    """
    Dependency factory: inject this with Depends to enforce a permission check.

    Usage:
        @router.post("/cases/{id}/seal")
        async def seal_case(
            current_user: Annotated[CurrentUser, Depends(get_current_user)],
            _: Annotated[None, Depends(require_permission("seal_case"))],
        ):
            ...
    """
    async def _check(current_user: Annotated[CurrentUser, Depends(get_current_user)]):
        if not can(current_user.role, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not permitted to '{action}'",
            )
        return current_user
    return _check


# ── Brute-force protection (in-memory; use Redis in production) ───────────────
_LOCKOUT_ATTEMPTS = 5
_LOCKOUT_MINUTES = 15
_login_attempts: dict[str, list[datetime]] = {}


def check_brute_force(username: str) -> None:
    """Raise 429 if the account is temporarily locked out."""
    now = _now()
    window_start = now - timedelta(minutes=_LOCKOUT_MINUTES)
    attempts = [t for t in _login_attempts.get(username, []) if t > window_start]
    if len(attempts) >= _LOCKOUT_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked. Try again later.",
        )


def record_failed_attempt(username: str) -> None:
    """Record a failed login attempt."""
    now = _now()
    window_start = now - timedelta(minutes=_LOCKOUT_MINUTES)
    prev = _login_attempts.get(username, [])
    _login_attempts[username] = [t for t in prev if t > window_start] + [now]


def clear_attempts(username: str) -> None:
    """Clear failed login attempts on successful login."""
    _login_attempts.pop(username, None)
