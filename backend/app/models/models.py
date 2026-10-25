"""
Evidence Guard – SQLAlchemy models (P1.1)

Tables:
  users           – human accounts
  roles           – role definitions
  user_roles      – many-to-many join
  cases           – investigation cases
  evidence        – evidence items (metadata only; files go to MinIO)
  custody_events  – chain of custody (append-only)
  wrapped_keys    – per-case data key (wrapped; plaintext NEVER stored)
  ai_results      – AI module outputs (leads, reviewed by humans)
  ai_provenance   – anchored output hashes for AI reproducibility
  access_log      – every read/download/analysis event
  upload_sessions – resumable chunked upload state

Rules enforced at model level:
  R1: no file content, encryption keys, or personal data on-chain or in plaintext columns
  R8: only wrapped_key_b64 is stored; never the plaintext key
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enums ─────────────────────────────────────────────────────────────────────

RoleNameEnum = Enum(
    "admin", "investigator", "analyst", "supervisor", "viewer",
    name="role_name",
)

CaseStatusEnum = Enum(
    "active", "under_review", "resolved", "closed", "sealed",
    name="case_status",
)

CasePriorityEnum = Enum(
    "low", "medium", "high", "critical",
    name="case_priority",
)

EvidenceStatusEnum = Enum(
    "verified", "under_review", "flagged", "failed_integrity",
    name="evidence_status",
)

AlertSeverityEnum = Enum(
    "critical", "high", "medium", "low",
    name="alert_severity",
)

CustodyActionEnum = Enum(
    "registered", "transferred", "accessed", "verified",
    "ai_analyzed", "flagged", "sealed", "exported",
    name="custody_action",
)

AIModuleEnum = Enum(
    "m1_classifier", "m2_entities", "m3_anomaly", "m4_explain",
    name="ai_module",
)

ReviewDecisionEnum = Enum(
    "accepted", "rejected", "pending",
    name="review_decision",
)

UploadStateEnum = Enum(
    "pending", "uploading", "complete", "aborted",
    name="upload_state",
)


# ── Base ──────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Users and Roles ───────────────────────────────────────────────────────────

class Role(Base):
    __tablename__ = "roles"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    name: str = Column(RoleNameEnum, unique=True, nullable=False)
    description: str = Column(Text, nullable=True)

    user_roles = relationship("UserRole", back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    username: str = Column(String(64), unique=True, nullable=False, index=True)
    display_name: str = Column(String(128), nullable=False)
    email: str = Column(String(254), unique=True, nullable=False, index=True)

    # Auth – never store plaintext passwords
    password_hash: str = Column(String(256), nullable=False)
    mfa_secret: str = Column(String(64), nullable=True)   # TOTP secret, encrypted at rest
    mfa_enabled: bool = Column(Boolean, default=False, nullable=False)

    # Account state
    is_active: bool = Column(Boolean, default=True, nullable=False)
    is_service_account: bool = Column(Boolean, default=False, nullable=False)  # ai-service, system
    failed_login_count: int = Column(Integer, default=0, nullable=False)
    locked_until: datetime = Column(DateTime(timezone=True), nullable=True)

    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: datetime = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    user_roles = relationship("UserRole", back_populates="user")


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    user_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"))
    role_id: str = Column(UUID(as_uuid=False), ForeignKey("roles.id", ondelete="CASCADE"))

    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="user_roles")


# ── Cases ─────────────────────────────────────────────────────────────────────

class Case(Base):
    __tablename__ = "cases"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_number: str = Column(String(32), unique=True, nullable=False, index=True)
    title: str = Column(String(256), nullable=False)
    description: str = Column(Text, nullable=True)
    status: str = Column(CaseStatusEnum, nullable=False, default="active")
    priority: str = Column(CasePriorityEnum, nullable=False, default="medium")

    lead_investigator_id: str = Column(
        UUID(as_uuid=False), ForeignKey("users.id"), nullable=False
    )
    sealed_at: datetime = Column(DateTime(timezone=True), nullable=True)
    sealed_by_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)

    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: datetime = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    lead_investigator = relationship("User", foreign_keys=[lead_investigator_id])
    sealed_by = relationship("User", foreign_keys=[sealed_by_id])
    evidence_items = relationship("Evidence", back_populates="case")
    wrapped_keys = relationship("WrappedKey", back_populates="case")


# ── Evidence ──────────────────────────────────────────────────────────────────

class Evidence(Base):
    """
    Evidence metadata. File content is stored encrypted in MinIO (storage_ref).
    The plaintext hash is computed before encryption; the on-chain record mirrors
    sha256_hex and ledger_tx_id for verification.
    """
    __tablename__ = "evidence"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id: str = Column(
        UUID(as_uuid=False), ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    file_name: str = Column(String(512), nullable=False)    # sanitised original name
    file_size_bytes: int = Column(Integer, nullable=False)
    mime_type: str = Column(String(128), nullable=False)

    # Hashes – algorithm name always stored alongside the digest (Section 63(4))
    sha256_hex: str = Column(String(64), nullable=False)
    hash_algorithm: str = Column(String(16), nullable=False, default="SHA-256")
    metadata_hash: str = Column(String(64), nullable=True)  # canonical metadata JSON hash

    # Storage
    storage_ref: str = Column(String(512), nullable=False)  # MinIO bucket/object-key

    # Status
    status: str = Column(EvidenceStatusEnum, nullable=False, default="under_review")

    # Acquisition metadata (ISO/IEC 27037)
    collector_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    acquisition_tool: str = Column(String(128), nullable=True)
    acquisition_device: str = Column(String(256), nullable=True)
    acquisition_time: datetime = Column(DateTime(timezone=True), nullable=True)
    notes: str = Column(Text, nullable=True)

    # Blockchain reference (on-chain record mirrors sha256_hex)
    ledger_tx_id: str = Column(String(256), nullable=True)
    ledger_platform: str = Column(String(32), nullable=True)  # fabric | ethereum | mock

    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: datetime = Column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    case = relationship("Case", back_populates="evidence_items")
    collector = relationship("User")
    custody_events = relationship(
        "CustodyEvent", back_populates="evidence", order_by="CustodyEvent.occurred_at"
    )

    __table_args__ = (
        Index("ix_evidence_case_status", "case_id", "status"),
    )


# ── Custody Events (append-only) ──────────────────────────────────────────────

class CustodyEvent(Base):
    """
    Immutable custody log. Rows are INSERT-only; no UPDATE or DELETE.
    The ledger_tx_id ties each event to the on-chain record.
    """
    __tablename__ = "custody_events"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    evidence_id: str = Column(
        UUID(as_uuid=False), ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    actor_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    action: str = Column(CustodyActionEnum, nullable=False)
    occurred_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    note: str = Column(Text, nullable=True)     # free text; NOT on-chain (R1 / privacy)
    from_actor_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)

    # Ledger reference
    ledger_tx_id: str = Column(String(256), nullable=True)
    event_hash: str = Column(String(64), nullable=True)   # SHA-256 of canonical event JSON

    evidence = relationship("Evidence", back_populates="custody_events")
    actor = relationship("User", foreign_keys=[actor_id])
    from_actor = relationship("User", foreign_keys=[from_actor_id])


# ── Wrapped Keys ──────────────────────────────────────────────────────────────

class WrappedKey(Base):
    """
    Per-case data encryption key, wrapped by the master key.
    ONLY the wrapped_key_b64 is stored here – never the plaintext key (R8).
    """
    __tablename__ = "wrapped_keys"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id: str = Column(
        UUID(as_uuid=False), ForeignKey("cases.id", ondelete="RESTRICT"),
        nullable=False, unique=True,
    )
    wrapped_key_b64: str = Column(String(256), nullable=False)  # base64(AES-KW(data_key))
    key_algorithm: str = Column(String(16), nullable=False, default="AES-256-GCM")
    wrap_algorithm: str = Column(String(16), nullable=False, default="AES-KW")
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    case = relationship("Case", back_populates="wrapped_keys")


# ── AI Results ────────────────────────────────────────────────────────────────

class AIResult(Base):
    """
    Output from an AI module. Always 'lead' status until a human accepts/rejects.
    AI outputs are NEVER findings without human review.
    """
    __tablename__ = "ai_results"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    evidence_id: str = Column(
        UUID(as_uuid=False), ForeignKey("evidence.id"), nullable=False, index=True
    )
    module: str = Column(AIModuleEnum, nullable=False)
    model_version: str = Column(String(64), nullable=False)

    # Result payload (JSON text) – human-readable lead, not a finding
    result_json: str = Column(Text, nullable=False)
    output_hash: str = Column(String(64), nullable=False)   # SHA-256 of result_json
    hash_algorithm: str = Column(String(16), nullable=False, default="SHA-256")

    # Integrity gate ticket (must pass before AI runs)
    integrity_ticket_id: str = Column(String(256), nullable=True)
    integrity_passed: bool = Column(Boolean, nullable=False, default=False)

    # Human review (mandatory before use in reports)
    review_decision: str = Column(ReviewDecisionEnum, nullable=False, default="pending")
    reviewed_by_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    reviewed_at: datetime = Column(DateTime(timezone=True), nullable=True)
    review_note: str = Column(Text, nullable=True)

    # Ledger anchor
    ledger_tx_id: str = Column(String(256), nullable=True)

    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    evidence = relationship("Evidence")
    reviewed_by = relationship("User")
    provenance = relationship("AIProvenance", back_populates="ai_result", uselist=False)


class AIProvenance(Base):
    """
    Records the inputs used to produce an AI result, so the result can be
    reproduced and the output_hash verified (Hypothesis H4).
    """
    __tablename__ = "ai_provenance"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    ai_result_id: str = Column(
        UUID(as_uuid=False), ForeignKey("ai_results.id"), nullable=False, unique=True
    )
    input_hash: str = Column(String(64), nullable=False)   # hash of the input copy
    model_artifact_hash: str = Column(String(64), nullable=True)
    random_seed: int = Column(Integer, nullable=True)
    recorded_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    ai_result = relationship("AIResult", back_populates="provenance")


# ── Access Log (non-repudiation) ──────────────────────────────────────────────

class AccessLog(Base):
    """
    Every read, download, analysis and report action is logged here
    and anchored on the ledger for non-repudiation.
    """
    __tablename__ = "access_log"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    actor_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    action: str = Column(String(64), nullable=False)   # read | download | analyze | export
    resource_type: str = Column(String(64), nullable=False)
    resource_id: str = Column(UUID(as_uuid=False), nullable=False)
    occurred_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    ledger_tx_id: str = Column(String(256), nullable=True)

    actor = relationship("User")


# ── Upload Sessions ────────────────────────────────────────────────────────────

class UploadSession(Base):
    """
    Tracks resumable chunked uploads. Deleted after evidence is registered.
    Temporary files live in a 0700 directory and are removed on completion or abort.
    """
    __tablename__ = "upload_sessions"

    id: str = Column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id: str = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False)
    initiated_by_id: str = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    file_name: str = Column(String(512), nullable=False)
    file_size_bytes: int = Column(Integer, nullable=True)
    mime_type: str = Column(String(128), nullable=False)
    state: str = Column(UploadStateEnum, nullable=False, default="pending")
    parts_uploaded: int = Column(Integer, default=0, nullable=False)
    sha256_hex: str = Column(String(64), nullable=True)   # set on complete
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: datetime = Column(DateTime(timezone=True), nullable=True)

    initiated_by = relationship("User")
