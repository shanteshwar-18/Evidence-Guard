# Limitations Statement

**Evidence Guard – Research Prototype Limitations**

> This statement must be copied into every report, slide deck, and README.

---

## What This System Does

- Computes and stores SHA-256 hashes of evidence files at the earliest point in the workflow.
- Maintains a verifiable handling history on an immutable ledger (tamper-evident).
- Encrypts evidence files with AES-256-GCM and per-case keys before storage.
- Provides AI-assisted triage, entity extraction, anomaly detection, and explainability.
- Generates reports with BSA 2023 Section 63(4) field mapping.

## What This System Does NOT Do

- **Does not issue a legally sufficient Section 63(4) certificate.** The certificate requires two human signatories and must be in the prescribed format. The system generates a report with the required fields; a human must review and sign it.
- **Does not guarantee court acceptance.** Admissibility depends on proper collection procedure, chain of custody, and the expert's testimony.
- **Does not replace the expert.** A certifying expert can be cross-examined; the system cannot.
- **Does not prove the evidence was collected correctly.** The hash proves the file has not changed since it was registered. It does not prove collection was lawful or procedurally correct.
- **Does not prove that AI conclusions are true.** AI outputs are investigative leads, not findings. A human investigator must review every AI result before it appears in a report.
- **Is not a production system.** This is a research prototype. It has not been through a security audit, penetration test, or compliance certification.
- **Does not handle real personal data.** The prototype uses only synthetic or public data.

## Honest Claims

Blockchain makes registered evidence and its handling history **tamper-evident** — changes become detectable. It does not make evidence tamper-proof, and it does not prove the evidence was authentic when collected.

---

*Prepared: 2026-10-25 | Project: Evidence Guard | For research use only*
