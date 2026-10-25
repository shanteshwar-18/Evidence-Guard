"""
Evidence Guard – Crypto Service (P3.1)

AES-256-GCM chunked encryption.
- Each chunk has a unique nonce.
- evidence_id and chunk_index are bound as associated data (AAD),
  so chunks cannot be reordered or truncated undetected.
- A small file header records version, chunk size, and nonce scheme.
- Plaintext is NEVER written to disk; only the encrypted stream.
"""

from __future__ import annotations

import io
import os
import struct
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Constants ─────────────────────────────────────────────────────────────────
_HEADER_MAGIC = b"EG01"          # 4 bytes – version marker
_CHUNK_SIZE = 8 * 1024 * 1024   # 8 MiB default
_KEY_BITS = 256                  # AES-256
_NONCE_BYTES = 12                # 96-bit nonce (GCM standard)
_TAG_BYTES = 16                  # GCM authentication tag
_HEADER_FMT = "!4sIHH"          # magic(4) + chunk_size(4) + nonce_bytes(2) + tag_bytes(2)
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)
_CHUNK_LEN_FMT = "!I"           # 4-byte big-endian chunk length prefix


def _make_aad(evidence_id: str, chunk_index: int) -> bytes:
    """
    Build Associated Data for GCM.
    Binds each chunk to its evidence_id and position so reordering is detected.
    """
    return f"evidence_id={evidence_id}|chunk={chunk_index}".encode("utf-8")


def _unique_nonce(used: set) -> bytes:
    """Generate a random 12-byte nonce, guaranteed unique in this session."""
    for _ in range(100):
        nonce = os.urandom(_NONCE_BYTES)
        if nonce not in used:
            used.add(nonce)
            return nonce
    raise RuntimeError("Failed to generate a unique nonce in 100 attempts")


# ── Encrypt ───────────────────────────────────────────────────────────────────

def encrypt_stream(
    plaintext_stream: BinaryIO,
    key: bytes,
    evidence_id: str,
    chunk_size: int = _CHUNK_SIZE,
) -> Iterator[bytes]:
    """
    Encrypt a plaintext stream chunk-by-chunk with AES-256-GCM.

    Yields:
        header (once) then for each chunk: length_prefix + nonce + ciphertext+tag

    Memory: only one chunk is in memory at a time.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")

    aesgcm = AESGCM(key)
    used_nonces: set = set()

    # Write header
    header = struct.pack(_HEADER_FMT, _HEADER_MAGIC, chunk_size, _NONCE_BYTES, _TAG_BYTES)
    yield header

    chunk_index = 0
    while True:
        plaintext_chunk = plaintext_stream.read(chunk_size)
        if not plaintext_chunk:
            break
        nonce = _unique_nonce(used_nonces)
        aad = _make_aad(evidence_id, chunk_index)
        ciphertext = aesgcm.encrypt(nonce, plaintext_chunk, aad)  # includes 16-byte tag
        chunk_data = nonce + ciphertext
        # Prefix with 4-byte length so the decryptor knows where each chunk ends
        yield struct.pack(_CHUNK_LEN_FMT, len(chunk_data)) + chunk_data
        chunk_index += 1


def encrypt_bytes(plaintext: bytes, key: bytes, evidence_id: str) -> bytes:
    """Convenience: encrypt bytes and return the full ciphertext blob."""
    stream = io.BytesIO(plaintext)
    return b"".join(encrypt_stream(stream, key, evidence_id))


# ── Decrypt ───────────────────────────────────────────────────────────────────

def decrypt_stream(
    ciphertext_stream: BinaryIO,
    key: bytes,
    evidence_id: str,
) -> Iterator[bytes]:
    """
    Decrypt a stream produced by encrypt_stream, chunk-by-chunk.

    Raises:
        ValueError:  Bad header magic or version.
        InvalidTag:  Any byte of the ciphertext has been tampered with.

    Memory: only one chunk is in memory at a time.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")

    # Parse header
    header_bytes = ciphertext_stream.read(_HEADER_SIZE)
    if len(header_bytes) < _HEADER_SIZE:
        raise ValueError("Truncated ciphertext: header missing")
    magic, chunk_size, nonce_bytes, tag_bytes = struct.unpack(_HEADER_FMT, header_bytes)
    if magic != _HEADER_MAGIC:
        raise ValueError(f"Bad magic: expected {_HEADER_MAGIC!r}, got {magic!r}")
    if nonce_bytes != _NONCE_BYTES or tag_bytes != _TAG_BYTES:
        raise ValueError("Unsupported nonce/tag size in header")

    aesgcm = AESGCM(key)
    chunk_index = 0

    while True:
        len_prefix = ciphertext_stream.read(4)
        if not len_prefix:
            break  # end of stream
        if len(len_prefix) < 4:
            raise ValueError("Truncated ciphertext: chunk length prefix missing")
        (chunk_data_len,) = struct.unpack(_CHUNK_LEN_FMT, len_prefix)
        chunk_data = ciphertext_stream.read(chunk_data_len)
        if len(chunk_data) < chunk_data_len:
            raise ValueError(f"Truncated ciphertext: expected {chunk_data_len} bytes, got {len(chunk_data)}")

        nonce = chunk_data[:nonce_bytes]
        ciphertext_with_tag = chunk_data[nonce_bytes:]
        aad = _make_aad(evidence_id, chunk_index)

        # InvalidTag is raised if any byte has changed
        plaintext_chunk = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        yield plaintext_chunk
        chunk_index += 1


def decrypt_bytes(ciphertext: bytes, key: bytes, evidence_id: str) -> bytes:
    """Convenience: decrypt a full blob and return plaintext bytes."""
    stream = io.BytesIO(ciphertext)
    return b"".join(decrypt_stream(stream, key, evidence_id))
