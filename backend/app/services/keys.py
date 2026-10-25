"""
Evidence Guard – Key Service (P3.1)

Per-case data key, wrapped by a master key loaded from environment.
Only the wrapped key is stored – plaintext NEVER appears in storage, logs,
API responses, or the database (Master Rule R8).

Interface is designed so a real KMS can replace the env-based implementation
without changing any caller code.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from cryptography.hazmat.backends import default_backend

from app.core.config import settings


def _master_key() -> bytes:
    """
    Load the master key from config (env var or mounted secret).
    Validates it is exactly 32 bytes.
    NEVER log or return this value.
    """
    hex_key = settings.MASTER_KEY_HEX
    if not hex_key:
        raise RuntimeError(
            "MASTER_KEY_HEX is not set. "
            "Set it in .env or mount it as a secret. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    key_bytes = bytes.fromhex(hex_key)
    if len(key_bytes) != 32:
        raise ValueError(
            f"MASTER_KEY_HEX must be 64 hex characters (32 bytes), got {len(key_bytes)} bytes"
        )
    return key_bytes


def generate_data_key() -> bytes:
    """Generate a new 32-byte data key. Used once per case."""
    return os.urandom(32)


def wrap_key(data_key: bytes) -> str:
    """
    Wrap a data key with the master key using AES Key Wrap (RFC 3394).
    Returns base64-encoded wrapped key safe for storage.
    Plaintext data_key is never stored or logged.
    """
    master = _master_key()
    wrapped = aes_key_wrap(master, data_key, default_backend())
    return base64.b64encode(wrapped).decode("ascii")


def unwrap_key(wrapped_key_b64: str) -> bytes:
    """
    Unwrap a previously wrapped data key.
    Returns the plaintext data key in memory only.
    """
    master = _master_key()
    wrapped = base64.b64decode(wrapped_key_b64)
    return aes_key_unwrap(master, wrapped, default_backend())


def get_or_create_case_key(wrapped_key_b64: str | None) -> tuple[bytes, str]:
    """
    Return (plaintext_key, wrapped_key_b64) for a case.
    - If wrapped_key_b64 is None, generates a new data key and wraps it.
    - If wrapped_key_b64 is provided, unwraps and returns it.

    The returned wrapped_key_b64 should be stored in the wrapped_keys table.
    The returned plaintext_key must be used in memory and then discarded.
    """
    if wrapped_key_b64 is None:
        data_key = generate_data_key()
        wrapped = wrap_key(data_key)
        return data_key, wrapped
    else:
        data_key = unwrap_key(wrapped_key_b64)
        return data_key, wrapped_key_b64
