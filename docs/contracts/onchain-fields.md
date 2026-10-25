# Evidence Guard – On-Chain Fields
# P1.3 – docs/contracts/onchain-fields.md
#
# This document defines the EXACT fields that go on-chain.
# Never on-chain: file content, encryption keys, plaintext secrets,
#                 review comment text, personal data (Master Rule R1).
#
# All leads (all four) must approve any change to this list.

## On-Chain Evidence Record

| Field | Type | Description |
|-------|------|-------------|
| `evidence_id` | UUID string | Stable identifier matching `evidence.id` in PostgreSQL |
| `case_number` | string | e.g. `CYB-2025-014` |
| `sha256_hex` | string (64 hex chars) | SHA-256 of the plaintext evidence file |
| `hash_algorithm` | string | Always `"SHA-256"` (required for Section 63(4)) |
| `metadata_hash` | string (64 hex chars) | SHA-256 of canonical acquisition metadata JSON |
| `ledger_registered_at` | ISO 8601 UTC | Block timestamp at registration |
| `registered_by` | username or identity string | Actor identity (MSP ID on Fabric) |
| `status` | string enum | `verified` \| `under_review` \| `flagged` \| `failed_integrity` |

## On-Chain Custody Event Record

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | UUID string | Matches `custody_events.id` |
| `evidence_id` | UUID string | Links to the evidence record |
| `action` | string enum | `registered` \| `transferred` \| `accessed` \| `verified` \| `ai_analyzed` \| `flagged` \| `sealed` \| `exported` |
| `actor` | identity string | Who performed the action |
| `from_actor` | identity string \| null | Previous custodian (for transfers) |
| `occurred_at` | ISO 8601 UTC | Block timestamp |
| `event_hash` | string (64 hex chars) | SHA-256 of canonical event JSON |

## On-Chain AI Provenance Record

| Field | Type | Description |
|-------|------|-------------|
| `ai_result_id` | UUID string | Matches `ai_results.id` |
| `evidence_id` | UUID string | Evidence this result was produced from |
| `module` | string | `m1_classifier` \| `m2_entities` \| `m3_anomaly` \| `m4_explain` |
| `model_version` | string | Semantic version of the model |
| `output_hash` | string (64 hex chars) | SHA-256 of `result_json` |
| `hash_algorithm` | string | Always `"SHA-256"` |
| `input_hash` | string (64 hex chars) | SHA-256 of the input copy |
| `model_artifact_hash` | string \| null | Hash of model weights file if available |
| `anchored_by` | identity string | Must be `ai-service` identity |
| `anchored_at` | ISO 8601 UTC | Block timestamp |

## NEVER on-chain

- File content (even encrypted)
- Encryption keys (even wrapped)
- Plaintext metadata containing personal data
- Review comment text
- Raw model outputs (only the hash of `result_json`)
- Passwords, tokens, secrets of any kind

## Canonical JSON Rules

For reproducible hashing, canonical JSON is defined as:
- Keys sorted lexicographically
- No extra whitespace (compact: separators `(",", ":")`)
- UTF-8 encoding
- Timestamps in ISO 8601 UTC format: `YYYY-MM-DDTHH:MM:SS.ffffffZ`

This rule applies wherever a hash of a JSON object is computed (metadata_hash, event_hash, output_hash).
