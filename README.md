# Evidence Guard

> **Blockchain-backed digital evidence management system with AI-assisted investigation.**
> 
> ⚠️ **Limitations**: This is a research prototype. It supports but does not replace the BSA 2023 Section 63(4) certificate or the expert. AI outputs are investigative leads, not findings. No claim of court acceptance, certification, or tamper-proof evidence is made.

---

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Docker Desktop | 24+ |
| Docker Compose | v2.24+ |
| Python | 3.12+ |
| Node.js | 20+ |
| Git | 2.40+ |

### 1. Clone and configure

```bash
git clone https://github.com/shanteshwar-18/Evidence-Guard.git
cd Evidence-Guard
cp .env.example .env
# Edit .env: set SECRET_KEY, POSTGRES_PASSWORD, MINIO_ROOT_PASSWORD, MASTER_KEY_HEX
```

Generate required secrets:
```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('MASTER_KEY_HEX=' + secrets.token_hex(32))"
```

### 2. Start all services

```bash
make up
```

Expected output:
```
NAME          IMAGE              STATUS          PORTS
eg_backend    eg_backend:latest  healthy         127.0.0.1:8000->8000/tcp
eg_postgres   postgres:16-alpine healthy         127.0.0.1:5432->5432/tcp
eg_minio      minio/minio:latest healthy         127.0.0.1:9000->9000/tcp
```

### 3. Verify health

```bash
curl http://localhost:8000/health
# → {"status":"ok","service":"evidence-guard-backend","version":"0.1.0"}
```

### 4. Run tests

```bash
make test
```

### 5. Seed synthetic data

```bash
make seed
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (React + TypeScript + Vite)                            │
│  No direct blockchain access from the frontend.                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST API (HTTPS / JWT)
┌──────────────────────────▼──────────────────────────────────────┐
│  Backend (FastAPI / Python)                                      │
│  Auth · Cases · Evidence · AI orchestration · Reports           │
└────────┬──────────────┬──────────────────────┬──────────────────┘
         │              │                      │
    ┌────▼────┐   ┌──────▼──────┐    ┌─────────▼─────────┐
    │PostgreSQL│   │   MinIO     │    │  Ledger (Fabric /  │
    │(metadata)│   │(encrypted   │    │  Ethereum / Mock)  │
    └──────────┘   │ evidence)   │    └────────────────────┘
                   └─────────────┘
         │
    ┌────▼──────────────────────────────┐
    │  AI Services (isolated)           │
    │  M1: Classifier · M2: Entities    │
    │  M3: Anomaly · M4: Explainability │
    │  Runs on copies after integrity   │
    │  gate; outputs are leads only.    │
    └───────────────────────────────────┘
```

---

## Folder Structure

```
evidence-guard/
├── backend/          FastAPI backend
│   ├── app/
│   │   ├── api/      Route handlers (P2-P5, P14-P15)
│   │   ├── core/     Config, security, database
│   │   ├── models/   SQLAlchemy models (P1)
│   │   └── services/ Business logic (P2-P5, P12)
│   └── tests/
├── blockchain/
│   ├── chaincode/    Hyperledger Fabric chaincode (Go) (P4)
│   ├── network/      Fabric test network scripts
│   └── gateway/      Fabric gateway client (Python)
├── ai/
│   ├── m1_classifier/ Email classification (P9)
│   ├── m2_entities/   Entity extraction + graph (P10)
│   ├── m3_anomaly/    Custody anomaly detection (P11)
│   ├── m4_explain/    Explainability + anchoring (P12)
│   └── common/        Shared utilities
├── frontend/          React + TypeScript + Vite + Tailwind (P6-P7, P13)
├── data/
│   ├── synthetic/     Synthetic evidence files (P8)
│   ├── public/        Public datasets (gitignored)
│   └── model_cards/   Model cards (P9-P11)
├── docs/
│   ├── contracts/     openapi.yaml, permissions.yaml, onchain-fields.md
│   ├── decisions/     Architecture decision records
│   ├── evaluation/    Experiment results (E1-E9)
│   └── datasets/      Dataset provenance records
├── infra/             docker-compose.yml
├── scripts/           seed.py, migrate.py, demo.sh
├── tests/e2e/         Playwright end-to-end tests
├── .env.example       Environment variables template
├── .gitignore
├── LICENSE            MIT
├── Makefile
└── README.md
```

---

## Build Units (Prompt Book)

| Unit | Description | Status |
|------|-------------|--------|
| P0   | Repository and Environment | ✅ Done |
| P1   | Data Model and API Contracts | 🔄 In Progress |
| P2   | Authentication and Roles | ⏳ Pending |
| P3   | Evidence Handling Service | ⏳ Pending |
| P4   | Blockchain Layer | ⏳ Pending |
| P5   | Evidence APIs | ⏳ Pending |
| P6   | Frontend Foundation | ⏳ Pending |
| P7   | Frontend Core Screens | ⏳ Pending |
| P8   | Synthetic Data and Datasets | ⏳ Pending |
| P9   | M1 - Classification and Triage | ⏳ Pending |
| P10  | M2 - Entities, Correlation and Graph | ⏳ Pending |
| P11  | M3 - Custody Anomaly Detection | ⏳ Pending |
| P12  | M4 - Explainability, Human Review and AI Anchoring | ⏳ Pending |
| P13  | AI Screens | ⏳ Pending |
| P14  | Reports and Export | ⏳ Pending |
| P15  | Integration - Integrity Gate, Sealing and Admin | ⏳ Pending |
| P16  | Testing and Evaluation (E1-E9) | ⏳ Pending |
| P17  | Documentation and Demo | ⏳ Pending |

---

## Git Strategy

- **main** – milestone-ready only (tagged: `v0.1-milestone-a`, `v0.2-milestone-b`, `v1.0-final`)
- **dev** – integration branch (PR required from feature branches)
- **feature branches** – `<initials>/p<unit>-<description>` (e.g., `bb/p4-chaincode`)

### Commit Conventions
```
feat(scope): description    # new feature
fix(scope): description     # bug fix
test(scope): description    # test addition
docs(scope): description    # documentation
chore: description          # tooling, config
```

---

## Security

- Role-based access control (5 roles: Admin, Investigator, Analyst, Supervisor, Viewer)
- Multi-factor authentication (TOTP)
- TLS everywhere in production
- AES-256-GCM per-case encryption; master key from env/KMS — never on-chain
- SHA-256 streaming hash before encryption
- Signed blockchain transactions for non-repudiation
- AI runs on copies only after integrity gate passes
- No real personal data in the prototype

---

## Legal and Ethical

- **Synthetic or public data only.** No real case data. No real personal data.
- AI outputs are investigative leads. Human review is mandatory before any report.
- This system supports Section 63(4) BSA 2023 field mapping; it does not issue legally sufficient certificates or replace the expert.
- See `docs/decisions/limitations.md` for the full limitations statement.
