"""
Evidence Guard – Ledger Client Interface (P4)

This is the single abstraction between the backend and the blockchain.
Three implementations are provided:
  1. MockLedger     – in-memory, no blockchain required (development / tests / demo fallback)
  2. FabricLedger   – Hyperledger Fabric via gRPC gateway (target architecture)
  3. EthereumLedger – Private Ethereum via web3.py (break-glass fallback)

The backend only ever imports LedgerClient.  Swap implementations by changing
LEDGER_PLATFORM in .env.

Master Rule R1: NEVER put file content, encryption keys, plaintext secrets,
review comment text, or personal data on-chain.
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Data structures ───────────────────────────────────────────────────────────

class OnChainEvidenceRecord:
    """On-chain evidence record. Fields defined in docs/contracts/onchain-fields.md."""

    def __init__(
        self,
        evidence_id: str,
        case_number: str,
        sha256_hex: str,
        hash_algorithm: str,
        metadata_hash: str,
        registered_by: str,
        status: str = "under_review",
    ):
        self.evidence_id = evidence_id
        self.case_number = case_number
        self.sha256_hex = sha256_hex
        self.hash_algorithm = hash_algorithm
        self.metadata_hash = metadata_hash
        self.registered_by = registered_by
        self.status = status
        self.ledger_registered_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "case_number": self.case_number,
            "sha256_hex": self.sha256_hex,
            "hash_algorithm": self.hash_algorithm,
            "metadata_hash": self.metadata_hash,
            "registered_by": self.registered_by,
            "status": self.status,
            "ledger_registered_at": self.ledger_registered_at,
        }


class OnChainCustodyEvent:
    """On-chain custody event. Fields defined in docs/contracts/onchain-fields.md."""

    def __init__(
        self,
        event_id: str,
        evidence_id: str,
        action: str,
        actor: str,
        from_actor: str | None = None,
    ):
        self.event_id = event_id
        self.evidence_id = evidence_id
        self.action = action
        self.actor = actor
        self.from_actor = from_actor
        self.occurred_at = datetime.now(timezone.utc).isoformat()
        self.event_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        record = {
            "event_id": self.event_id,
            "evidence_id": self.evidence_id,
            "action": self.action,
            "actor": self.actor,
            "from_actor": self.from_actor,
            "occurred_at": self.occurred_at,
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "evidence_id": self.evidence_id,
            "action": self.action,
            "actor": self.actor,
            "from_actor": self.from_actor,
            "occurred_at": self.occurred_at,
            "event_hash": self.event_hash,
        }


class OnChainAIProvenance:
    """AI provenance anchor. Fields defined in docs/contracts/onchain-fields.md."""

    def __init__(
        self,
        ai_result_id: str,
        evidence_id: str,
        module: str,
        model_version: str,
        output_hash: str,
        hash_algorithm: str,
        input_hash: str,
        model_artifact_hash: str | None,
        anchored_by: str,
    ):
        self.ai_result_id = ai_result_id
        self.evidence_id = evidence_id
        self.module = module
        self.model_version = model_version
        self.output_hash = output_hash
        self.hash_algorithm = hash_algorithm
        self.input_hash = input_hash
        self.model_artifact_hash = model_artifact_hash
        self.anchored_by = anchored_by
        self.anchored_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "ai_result_id": self.ai_result_id,
            "evidence_id": self.evidence_id,
            "module": self.module,
            "model_version": self.model_version,
            "output_hash": self.output_hash,
            "hash_algorithm": self.hash_algorithm,
            "input_hash": self.input_hash,
            "model_artifact_hash": self.model_artifact_hash,
            "anchored_by": self.anchored_by,
            "anchored_at": self.anchored_at,
        }


# ── Abstract interface ─────────────────────────────────────────────────────────

class LedgerClient(abc.ABC):
    """
    Abstract ledger interface.  All implementations must provide these methods.
    The backend only calls this interface – never the blockchain SDK directly.
    """

    @abc.abstractmethod
    def register_evidence(self, record: OnChainEvidenceRecord) -> str:
        """Register evidence. Returns transaction ID."""

    @abc.abstractmethod
    def log_custody_event(self, event: OnChainCustodyEvent) -> str:
        """Append a custody event. Returns transaction ID."""

    @abc.abstractmethod
    def verify_evidence(self, evidence_id: str, sha256_hex: str) -> dict[str, Any]:
        """Verify evidence hash against on-chain record. Returns verification result."""

    @abc.abstractmethod
    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        """Return on-chain evidence record or None if not found."""

    @abc.abstractmethod
    def get_custody_history(self, evidence_id: str) -> list[dict[str, Any]]:
        """Return all custody events for evidence in chronological order."""

    @abc.abstractmethod
    def update_evidence_status(self, evidence_id: str, status: str, actor: str) -> str:
        """Update evidence status on-chain. Returns transaction ID."""

    @abc.abstractmethod
    def seal_case(self, case_number: str, actor: str) -> str:
        """Seal a case (all its evidence becomes write-locked). Returns transaction ID."""

    @abc.abstractmethod
    def anchor_ai_result(self, provenance: OnChainAIProvenance) -> str:
        """Anchor an AI provenance record. Must be called by ai-service identity only."""


# ── Mock ledger (in-memory) ────────────────────────────────────────────────────

class MockLedger(LedgerClient):
    """
    In-memory mock ledger for development, CI and demo fallback.
    Thread-safe.  Data does not persist between process restarts.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._evidence: dict[str, dict] = {}
        self._events: dict[str, list[dict]] = {}   # evidence_id -> list of events
        self._ai_provenance: dict[str, dict] = {}   # ai_result_id -> record
        self._sealed_cases: set[str] = set()

    def _new_tx_id(self) -> str:
        return f"mock-tx-{uuid.uuid4().hex}"

    def _check_sealed(self, evidence_id: str) -> None:
        """Raise if the case containing this evidence is sealed."""
        record = self._evidence.get(evidence_id)
        if record:
            case_number = record.get("case_number", "")
            if case_number in self._sealed_cases:
                raise ValueError(f"Case {case_number} is sealed; evidence is write-locked")

    def register_evidence(self, record: OnChainEvidenceRecord) -> str:
        with self._lock:
            if record.evidence_id in self._evidence:
                raise ValueError(f"Evidence {record.evidence_id} is already registered")
            self._evidence[record.evidence_id] = record.to_dict()
            self._events[record.evidence_id] = []
            tx_id = self._new_tx_id()
            logger.debug("[MockLedger] Registered evidence %s (tx: %s)", record.evidence_id, tx_id)
            return tx_id

    def log_custody_event(self, event: OnChainCustodyEvent) -> str:
        with self._lock:
            self._check_sealed(event.evidence_id)
            if event.evidence_id not in self._events:
                self._events[event.evidence_id] = []
            self._events[event.evidence_id].append(event.to_dict())
            tx_id = self._new_tx_id()
            logger.debug(
                "[MockLedger] Custody event %s for %s (tx: %s)",
                event.action, event.evidence_id, tx_id
            )
            return tx_id

    def verify_evidence(self, evidence_id: str, sha256_hex: str) -> dict[str, Any]:
        with self._lock:
            record = self._evidence.get(evidence_id)
            if record is None:
                return {
                    "evidence_id": evidence_id,
                    "verified": False,
                    "error": "Evidence not found on ledger",
                    "ledger_hash": None,
                    "provided_hash": sha256_hex,
                }
            ledger_hash = record["sha256_hex"]
            match = ledger_hash == sha256_hex
            return {
                "evidence_id": evidence_id,
                "verified": match,
                "ledger_hash": ledger_hash,
                "provided_hash": sha256_hex,
                "hash_algorithm": record.get("hash_algorithm", "SHA-256"),
                "registered_at": record.get("ledger_registered_at"),
            }

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._evidence.get(evidence_id)

    def get_custody_history(self, evidence_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events.get(evidence_id, []))

    def update_evidence_status(self, evidence_id: str, status: str, actor: str) -> str:
        with self._lock:
            self._check_sealed(evidence_id)
            if evidence_id not in self._evidence:
                raise ValueError(f"Evidence {evidence_id} not found on ledger")
            self._evidence[evidence_id]["status"] = status
            tx_id = self._new_tx_id()
            logger.debug(
                "[MockLedger] Updated status of %s to %s (tx: %s)", evidence_id, status, tx_id
            )
            return tx_id

    def seal_case(self, case_number: str, actor: str) -> str:
        with self._lock:
            self._sealed_cases.add(case_number)
            tx_id = self._new_tx_id()
            logger.info("[MockLedger] Sealed case %s by %s (tx: %s)", case_number, actor, tx_id)
            return tx_id

    def anchor_ai_result(self, provenance: OnChainAIProvenance) -> str:
        with self._lock:
            # Only ai-service identity may anchor AI results (R9)
            if provenance.anchored_by != "ai-service":
                raise PermissionError(
                    f"Only 'ai-service' may anchor AI results; got '{provenance.anchored_by}'"
                )
            self._ai_provenance[provenance.ai_result_id] = provenance.to_dict()
            tx_id = self._new_tx_id()
            logger.debug(
                "[MockLedger] Anchored AI result %s (tx: %s)", provenance.ai_result_id, tx_id
            )
            return tx_id


# ── Placeholder for Fabric and Ethereum ───────────────────────────────────────

class FabricLedger(LedgerClient):
    """
    Hyperledger Fabric ledger client.
    Implemented in P4.2 after the test network is up.
    Set LEDGER_PLATFORM=fabric in .env to activate.
    """

    def __init__(self):
        raise NotImplementedError(
            "FabricLedger is not yet implemented. "
            "Run blockchain/network/start-fabric.sh and implement P4.2."
        )

    def register_evidence(self, record): ...
    def log_custody_event(self, event): ...
    def verify_evidence(self, evidence_id, sha256_hex): ...
    def get_evidence(self, evidence_id): ...
    def get_custody_history(self, evidence_id): ...
    def update_evidence_status(self, evidence_id, status, actor): ...
    def seal_case(self, case_number, actor): ...
    def anchor_ai_result(self, provenance): ...


class EthereumLedger(LedgerClient):
    """
    Private Ethereum ledger client (break-glass Scenario 1).
    Implemented in P4.4 if Fabric is blocked.
    Set LEDGER_PLATFORM=ethereum in .env to activate.
    """

    def __init__(self):
        raise NotImplementedError(
            "EthereumLedger is not yet implemented. "
            "Use break-glass Scenario 1: run blockchain/network/start-eth.sh and implement P4.4."
        )

    def register_evidence(self, record): ...
    def log_custody_event(self, event): ...
    def verify_evidence(self, evidence_id, sha256_hex): ...
    def get_evidence(self, evidence_id): ...
    def get_custody_history(self, evidence_id): ...
    def update_evidence_status(self, evidence_id, status, actor): ...
    def seal_case(self, case_number, actor): ...
    def anchor_ai_result(self, provenance): ...


# ── Factory ───────────────────────────────────────────────────────────────────

_ledger_instance: LedgerClient | None = None


def get_ledger() -> LedgerClient:
    """
    Return the singleton LedgerClient for the configured platform.
    Call this wherever a ledger is needed (dependency injection pattern).
    """
    global _ledger_instance
    if _ledger_instance is not None:
        return _ledger_instance

    from app.core.config import settings

    platform = settings.LEDGER_PLATFORM.lower()
    if platform == "mock":
        _ledger_instance = MockLedger()
        logger.info("Using MockLedger (in-memory, no blockchain required)")
    elif platform == "fabric":
        _ledger_instance = FabricLedger()
        logger.info("Using Hyperledger Fabric ledger")
    elif platform == "ethereum":
        _ledger_instance = EthereumLedger()
        logger.info("Using Ethereum ledger")
    else:
        raise ValueError(f"Unknown LEDGER_PLATFORM: {platform!r}")

    return _ledger_instance
