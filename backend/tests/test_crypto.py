"""
P3 – Crypto and hashing tests.
Covers: round-trip, tamper detection, truncation, empty/1-byte files, nonce uniqueness.
Run: pytest backend/tests/test_crypto.py -v
"""

from __future__ import annotations

import io
import os
import pytest

from cryptography.exceptions import InvalidTag

from app.services.crypto import (
    decrypt_bytes,
    decrypt_stream,
    encrypt_bytes,
    encrypt_stream,
    _CHUNK_SIZE,
)
from app.services.hashing import hash_bytes, hash_file_stream, hash_iter, hash_canonical_json
from app.services.keys import generate_data_key, wrap_key, unwrap_key, get_or_create_case_key


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def key() -> bytes:
    return generate_data_key()


@pytest.fixture
def evidence_id() -> str:
    return "test-evidence-id-12345"


# ── Hash tests ────────────────────────────────────────────────────────────────

def test_hash_bytes_known():
    """SHA-256 of empty string matches RFC value."""
    digest, algo = hash_bytes(b"")
    assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert algo == "SHA-256"


def test_hash_file_stream_matches_hash_bytes():
    data = b"Evidence Guard test data " * 1000
    digest_stream, _ = hash_file_stream(io.BytesIO(data))
    digest_bytes, _ = hash_bytes(data)
    assert digest_stream == digest_bytes


def test_hash_empty_file():
    digest, algo = hash_file_stream(io.BytesIO(b""))
    assert len(digest) == 64
    assert algo == "SHA-256"


def test_hash_one_byte_file():
    digest, algo = hash_file_stream(io.BytesIO(b"\x00"))
    assert len(digest) == 64


def test_hash_canonical_json_is_deterministic():
    obj = {"b": 2, "a": 1, "c": "hello"}
    d1, _ = hash_canonical_json(obj)
    d2, _ = hash_canonical_json(obj)
    assert d1 == d2


def test_hash_canonical_json_key_order_independent():
    """Keys in different order must produce the same hash."""
    a, _ = hash_canonical_json({"x": 1, "y": 2})
    b, _ = hash_canonical_json({"y": 2, "x": 1})
    assert a == b


# ── Key service tests ─────────────────────────────────────────────────────────

def test_wrap_unwrap_roundtrip(key):
    wrapped = wrap_key(key)
    assert isinstance(wrapped, str)
    assert wrapped  # not empty
    recovered = unwrap_key(wrapped)
    assert recovered == key


def test_wrapped_key_is_base64(key):
    import base64
    wrapped = wrap_key(key)
    decoded = base64.b64decode(wrapped)
    assert len(decoded) > 0


def test_get_or_create_case_key_new():
    key_bytes, wrapped = get_or_create_case_key(None)
    assert len(key_bytes) == 32
    assert wrapped


def test_get_or_create_case_key_existing():
    _, wrapped = get_or_create_case_key(None)
    key_bytes2, _ = get_or_create_case_key(wrapped)
    key_bytes_original, _ = get_or_create_case_key(wrapped)
    assert key_bytes2 == key_bytes_original


# ── Encrypt / Decrypt round-trip ──────────────────────────────────────────────

def test_roundtrip_small(key, evidence_id):
    plaintext = b"Hello Evidence Guard!"
    ct = encrypt_bytes(plaintext, key, evidence_id)
    pt = decrypt_bytes(ct, key, evidence_id)
    assert pt == plaintext


def test_roundtrip_empty_file(key, evidence_id):
    ct = encrypt_bytes(b"", key, evidence_id)
    pt = decrypt_bytes(ct, key, evidence_id)
    assert pt == b""


def test_roundtrip_one_byte(key, evidence_id):
    ct = encrypt_bytes(b"\xff", key, evidence_id)
    pt = decrypt_bytes(ct, key, evidence_id)
    assert pt == b"\xff"


def test_roundtrip_multi_chunk(key, evidence_id):
    """Test with data larger than one chunk (forces multiple chunks)."""
    chunk_size = 64 * 1024   # 64 KiB chunks for speed
    # 3 chunks + partial
    plaintext = os.urandom(chunk_size * 3 + 12345)
    stream = io.BytesIO(plaintext)
    ct_chunks = list(encrypt_stream(stream, key, evidence_id, chunk_size=chunk_size))
    ct = b"".join(ct_chunks)
    pt = decrypt_bytes(ct, key, evidence_id)
    assert pt == plaintext


def test_hash_preserved_after_roundtrip(key, evidence_id):
    """Hash before encryption must equal hash after decryption."""
    plaintext = os.urandom(256 * 1024)  # 256 KiB
    original_hash, _ = hash_bytes(plaintext)

    ct = encrypt_bytes(plaintext, key, evidence_id)
    pt = decrypt_bytes(ct, key, evidence_id)
    decrypted_hash, _ = hash_bytes(pt)

    assert decrypted_hash == original_hash


# ── Tamper detection ──────────────────────────────────────────────────────────

def test_tamper_one_byte_detected(key, evidence_id):
    """Flipping one byte in the ciphertext must raise InvalidTag."""
    plaintext = b"tamper-test-data-" * 100
    ct = bytearray(encrypt_bytes(plaintext, key, evidence_id))

    # Flip a byte in the middle of the ciphertext (skip the header)
    mid = len(ct) // 2
    ct[mid] ^= 0xFF

    with pytest.raises(InvalidTag):
        decrypt_bytes(bytes(ct), key, evidence_id)


def test_truncation_detected(key, evidence_id):
    """Truncating the ciphertext must raise an exception."""
    plaintext = b"truncation-test-data" * 50
    ct = encrypt_bytes(plaintext, key, evidence_id)

    # Remove the last 20 bytes
    truncated = ct[:-20]

    with pytest.raises((ValueError, InvalidTag, Exception)):
        decrypt_bytes(truncated, key, evidence_id)


def test_wrong_key_rejected(evidence_id):
    """Decrypting with a different key must raise InvalidTag."""
    key1 = generate_data_key()
    key2 = generate_data_key()
    assert key1 != key2

    ct = encrypt_bytes(b"secret data", key1, evidence_id)
    with pytest.raises(InvalidTag):
        decrypt_bytes(ct, key2, evidence_id)


def test_wrong_evidence_id_rejected(key):
    """Decrypting with a different evidence_id (wrong AAD) must raise InvalidTag."""
    ct = encrypt_bytes(b"secret data", key, "evidence-A")
    with pytest.raises(InvalidTag):
        decrypt_bytes(ct, key, "evidence-B")


# ── Nonce uniqueness ──────────────────────────────────────────────────────────

def test_nonce_uniqueness_100k():
    """Generate 100,000 chunks and verify all nonces are unique."""
    from app.services.crypto import _unique_nonce
    used: set = set()
    count = 100_000
    for _ in range(count):
        nonce = _unique_nonce(used)
        # nonce is already added to `used` inside _unique_nonce
    assert len(used) == count
