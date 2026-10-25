"""
P4 – Mock Ledger tests.
Covers: register, custody events, verify (pass/fail), history, status update,
seal case (write lock), AI provenance anchor, concurrency.
Run: pytest backend/tests/test_ledger.py -v
"""

from __future__ import annotations

import threading
import pytest

from app.services.ledger_client import (
    MockLedger,
    OnChainEvidenceRecord,
    OnChainCustodyEvent,
    OnChainAIProvenance,
)


@pytest.fixture
def ledger() -> MockLedger:
    return MockLedger()


@pytest.fixture
def evidence_record() -> OnChainEvidenceRecord:
    return OnChainEvidenceRecord(
        evidence_id="ev-001",
        case_number="CYB-2025-014",
        sha256_hex="abc123" + "0" * 58,
        hash_algorithm="SHA-256",
        metadata_hash="def456" + "0" * 58,
        registered_by="alex.carter",
    )


def test_register_evidence(ledger, evidence_record):
    tx_id = ledger.register_evidence(evidence_record)
    assert tx_id.startswith("mock-tx-")


def test_register_evidence_idempotent_fails(ledger, evidence_record):
    """Re-registering the same evidence must fail (no duplicate registration)."""
    ledger.register_evidence(evidence_record)
    with pytest.raises(ValueError, match="already registered"):
        ledger.register_evidence(evidence_record)


def test_get_evidence(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    rec = ledger.get_evidence("ev-001")
    assert rec is not None
    assert rec["sha256_hex"] == evidence_record.sha256_hex
    assert rec["hash_algorithm"] == "SHA-256"


def test_get_evidence_not_found(ledger):
    assert ledger.get_evidence("nonexistent") is None


def test_verify_evidence_pass(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    result = ledger.verify_evidence("ev-001", evidence_record.sha256_hex)
    assert result["verified"] is True
    assert result["ledger_hash"] == evidence_record.sha256_hex


def test_verify_evidence_tampered(ledger, evidence_record):
    """A different hash must fail verification."""
    ledger.register_evidence(evidence_record)
    result = ledger.verify_evidence("ev-001", "badhash" + "0" * 57)
    assert result["verified"] is False


def test_verify_evidence_not_found(ledger):
    result = ledger.verify_evidence("nonexistent", "abc123" + "0" * 58)
    assert result["verified"] is False
    assert "not found" in result["error"].lower()


def test_log_custody_event(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    event = OnChainCustodyEvent(
        event_id="evt-001",
        evidence_id="ev-001",
        action="accessed",
        actor="priya.sharma",
    )
    tx_id = ledger.log_custody_event(event)
    assert tx_id.startswith("mock-tx-")


def test_get_custody_history(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    for i, action in enumerate(["accessed", "transferred", "verified"]):
        event = OnChainCustodyEvent(
            event_id=f"evt-{i}",
            evidence_id="ev-001",
            action=action,
            actor="alex.carter",
        )
        ledger.log_custody_event(event)

    history = ledger.get_custody_history("ev-001")
    assert len(history) == 3
    assert history[0]["action"] == "accessed"
    assert history[2]["action"] == "verified"


def test_custody_event_has_hash(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    event = OnChainCustodyEvent(
        event_id="evt-hash-test",
        evidence_id="ev-001",
        action="registered",
        actor="alex.carter",
    )
    tx = ledger.log_custody_event(event)
    history = ledger.get_custody_history("ev-001")
    assert len(history[0]["event_hash"]) == 64   # SHA-256 hex


def test_update_evidence_status(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    tx = ledger.update_evidence_status("ev-001", "verified", "system")
    rec = ledger.get_evidence("ev-001")
    assert rec["status"] == "verified"


def test_seal_case_blocks_writes(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    ledger.seal_case("CYB-2025-014", "raj.patel")

    # Any write to sealed case must fail
    with pytest.raises(ValueError, match="sealed"):
        event = OnChainCustodyEvent(
            event_id="evt-blocked",
            evidence_id="ev-001",
            action="accessed",
            actor="someone",
        )
        ledger.log_custody_event(event)

    with pytest.raises(ValueError, match="sealed"):
        ledger.update_evidence_status("ev-001", "flagged", "someone")


def test_anchor_ai_result_by_ai_service(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    prov = OnChainAIProvenance(
        ai_result_id="ai-001",
        evidence_id="ev-001",
        module="m1_classifier",
        model_version="1.0.0",
        output_hash="a" * 64,
        hash_algorithm="SHA-256",
        input_hash="b" * 64,
        model_artifact_hash=None,
        anchored_by="ai-service",
    )
    tx = ledger.anchor_ai_result(prov)
    assert tx.startswith("mock-tx-")


def test_anchor_ai_result_by_human_fails(ledger, evidence_record):
    ledger.register_evidence(evidence_record)
    prov = OnChainAIProvenance(
        ai_result_id="ai-002",
        evidence_id="ev-001",
        module="m1_classifier",
        model_version="1.0.0",
        output_hash="a" * 64,
        hash_algorithm="SHA-256",
        input_hash="b" * 64,
        model_artifact_hash=None,
        anchored_by="alex.carter",   # human – must be rejected
    )
    with pytest.raises(PermissionError, match="ai-service"):
        ledger.anchor_ai_result(prov)


def test_thread_safety(ledger):
    """Register 100 evidence items concurrently and verify no race conditions."""
    errors = []

    def register(i: int):
        try:
            rec = OnChainEvidenceRecord(
                evidence_id=f"ev-thread-{i:04d}",
                case_number="CYB-2025-001",
                sha256_hex=f"{i:064x}",
                hash_algorithm="SHA-256",
                metadata_hash="0" * 64,
                registered_by="system",
            )
            ledger.register_evidence(rec)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=register, args=(i,)) for i in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread safety errors: {errors}"
    for i in range(100):
        assert ledger.get_evidence(f"ev-thread-{i:04d}") is not None
