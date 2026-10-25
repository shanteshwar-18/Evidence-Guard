"""
Evidence Guard – Metadata Service (P3.1)

Captures acquisition metadata per ISO/IEC 27037 and produces
a canonical JSON hash for immutable provenance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.services.hashing import hash_canonical_json


class AcquisitionMetadata(BaseModel):
    """Acquisition metadata captured at upload time (ISO/IEC 27037 fields)."""

    evidence_id: str
    file_name: str
    file_size_bytes: int
    mime_type: str
    case_id: str

    # Who collected it and how
    collector_username: str
    acquisition_tool: str | None = None
    acquisition_device: str | None = None
    acquisition_time: datetime | None = None
    notes: str | None = None


def build_metadata_record(meta: AcquisitionMetadata) -> dict[str, Any]:
    """
    Build a canonical metadata dict for hashing.
    All datetime values are converted to ISO 8601 UTC strings.
    """
    record: dict[str, Any] = {
        "evidence_id": meta.evidence_id,
        "file_name": meta.file_name,
        "file_size_bytes": meta.file_size_bytes,
        "mime_type": meta.mime_type,
        "case_id": meta.case_id,
        "collector_username": meta.collector_username,
    }
    # Optional fields – include only if present (null fields not hashed)
    if meta.acquisition_tool:
        record["acquisition_tool"] = meta.acquisition_tool
    if meta.acquisition_device:
        record["acquisition_device"] = meta.acquisition_device
    if meta.acquisition_time:
        dt = meta.acquisition_time
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        record["acquisition_time"] = dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    if meta.notes:
        record["notes"] = meta.notes
    return record


def compute_metadata_hash(meta: AcquisitionMetadata) -> tuple[str, str]:
    """
    Compute the metadata_hash for a piece of evidence.

    Returns:
        (sha256_hex, algorithm_name)
    """
    record = build_metadata_record(meta)
    return hash_canonical_json(record)
