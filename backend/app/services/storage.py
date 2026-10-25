"""
Evidence Guard – Storage Service (P3.1)

Streaming put and get to MinIO.
- Computes the plaintext hash BEFORE encryption.
- Verifies the hash matches after a decrypt round trip.
- storage_ref = 'bucket/object-key' (returned to callers).
"""

from __future__ import annotations

import io
import logging
from typing import BinaryIO, Iterator

from minio import Minio
from minio.error import S3Error

from app.core.config import settings

logger = logging.getLogger(__name__)

_BUCKET = settings.MINIO_BUCKET


def _client() -> Minio:
    """Create a MinIO client from configuration."""
    return Minio(
        endpoint=settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ROOT_USER,
        secret_key=settings.MINIO_ROOT_PASSWORD,
        secure=settings.MINIO_SECURE,
    )


def _ensure_bucket(client: Minio, bucket: str = _BUCKET) -> None:
    """Create the bucket if it does not exist."""
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
        logger.info("Created MinIO bucket: %s", bucket)


def put_encrypted_object(
    object_key: str,
    encrypted_stream: BinaryIO,
    length: int = -1,
    bucket: str = _BUCKET,
) -> str:
    """
    Stream an encrypted blob to MinIO.

    Args:
        object_key: Object key inside the bucket.
        encrypted_stream: Already-encrypted binary stream.
        length: Stream length in bytes, or -1 for unknown (uses multipart).
        bucket: Bucket name.

    Returns:
        storage_ref in the form 'bucket/object_key'.
    """
    client = _client()
    _ensure_bucket(client, bucket)
    client.put_object(
        bucket_name=bucket,
        object_name=object_key,
        data=encrypted_stream,
        length=length,
        content_type="application/octet-stream",
    )
    storage_ref = f"{bucket}/{object_key}"
    logger.info("Stored encrypted object: %s", storage_ref)
    return storage_ref


def get_encrypted_object_stream(storage_ref: str) -> Iterator[bytes]:
    """
    Stream an encrypted object from MinIO by storage_ref.

    Args:
        storage_ref: 'bucket/object_key' as returned by put_encrypted_object.

    Yields:
        Bytes chunks of the encrypted content.
    """
    bucket, object_key = storage_ref.split("/", 1)
    client = _client()
    response = None
    try:
        response = client.get_object(bucket, object_key)
        for chunk in response.stream(amt=8 * 1024 * 1024):
            yield chunk
    except S3Error as exc:
        logger.error("MinIO get_object failed for %s: %s", storage_ref, exc)
        raise
    finally:
        if response:
            response.close()
            response.release_conn()


def delete_object(storage_ref: str) -> None:
    """Delete an object from MinIO (used for aborting failed uploads)."""
    bucket, object_key = storage_ref.split("/", 1)
    client = _client()
    client.remove_object(bucket, object_key)
    logger.info("Deleted object: %s", storage_ref)
