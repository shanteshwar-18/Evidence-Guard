"""
Evidence Guard – Hashing Service (P3.1)

Streaming SHA-256 over file chunks (8 MiB) with constant memory.
Returns hex digest and the algorithm name 'SHA-256'.
MD5 and SHA-1 are explicitly rejected (Section 63(4) compliance).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import AsyncIterator, BinaryIO, Iterator

HASH_ALGORITHM = "SHA-256"
_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB


def _reject_weak_algorithm(algorithm: str) -> None:
    """Raise ValueError for weak hash algorithms (Section 63(4) compliance)."""
    weak = {"md5", "sha1", "sha-1", "sha_1"}
    if algorithm.lower().replace("-", "").replace("_", "") in {
        a.replace("-", "").replace("_", "") for a in weak
    }:
        raise ValueError(
            f"Algorithm '{algorithm}' is too weak. Use SHA-256 or stronger. "
            "MD5 and SHA-1 are explicitly rejected (Section 63(4) BSA 2023)."
        )


def hash_file_stream(stream: BinaryIO, chunk_size: int = _CHUNK_SIZE) -> tuple[str, str]:
    """
    Compute SHA-256 of a file stream in constant memory.

    Args:
        stream: A binary file-like object (opened in 'rb' mode).
        chunk_size: Bytes per read (default 8 MiB).

    Returns:
        (sha256_hex, algorithm_name) e.g. ('abc123...', 'SHA-256')
    """
    h = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        h.update(chunk)
    return h.hexdigest(), HASH_ALGORITHM


def hash_bytes(data: bytes) -> tuple[str, str]:
    """Hash a bytes object. For small data only – use hash_file_stream for large files."""
    return hashlib.sha256(data).hexdigest(), HASH_ALGORITHM


def hash_iter(chunks: Iterator[bytes]) -> tuple[str, str]:
    """Hash from an iterator of byte chunks (constant memory)."""
    h = hashlib.sha256()
    for chunk in chunks:
        h.update(chunk)
    return h.hexdigest(), HASH_ALGORITHM


def canonical_json(obj: dict) -> bytes:
    """
    Serialize a dict to canonical JSON for reproducible hashing.
    Rules: keys sorted, compact separators, UTF-8 encoding.
    This is the single canonical JSON implementation used everywhere.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_canonical_json(obj: dict) -> tuple[str, str]:
    """Hash a dict as canonical JSON. Returns (sha256_hex, algorithm_name)."""
    return hashlib.sha256(canonical_json(obj)).hexdigest(), HASH_ALGORITHM
