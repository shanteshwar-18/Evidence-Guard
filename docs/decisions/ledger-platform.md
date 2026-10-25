# Ledger Platform Decision Record

**Date:** 2026-10-25  
**Status:** OPEN  
**Decision point:** End of Week 5

---

## Decision

At the end of Week 5, the team must decide: **Fabric** or **Ethereum fallback**.

### Option A – Hyperledger Fabric (target architecture)

**Pros:** Permissioned, MSP identities, channels, private data collections  
**Cons:** Complex setup, requires Go expertise for chaincode

**Features available with Fabric:**
- Separate channels per case type (law-enforcement / forensic / judicial)
- Private data collections for sensitive metadata
- MSP-bound identities for role verification
- Pluggable consensus (Raft)

### Option B – Private Ethereum with Hardhat (break-glass fallback)

**Pros:** Easier to set up, well-known tooling  
**Cons:** Loses channels, private data collections, MSP identities

**What is lost when switching to Ethereum:**
- [ ] Channels to separate law-enforcement, forensic and judicial workflows
- [ ] Private data collections for sensitive metadata
- [ ] MSP identity binding for role verification at chaincode level
- [ ] Fabric-specific endorsement policy

### Option C – Mock Ledger (development / demo fallback)

Pure Python in-memory ledger implementing the same `LedgerClient` interface.  
Used for local development, CI tests, and demo fallback mode.

---

## LedgerClient Interface

The `LedgerClient` interface in `backend/app/services/ledger_client.py` is the same  
for all three options. Swap the implementation class in `.env` with `LEDGER_PLATFORM=`.

```
LEDGER_PLATFORM=mock      # default – no blockchain required
LEDGER_PLATFORM=fabric    # Hyperledger Fabric
LEDGER_PLATFORM=ethereum  # Private Ethereum
```

---

## Outcome

*To be filled in at end of Week 5.*

**Decision:** ___________  
**Reason:** ___________  
**Team sign-off:** ___________
