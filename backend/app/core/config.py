"""
Evidence Guard – application settings.

All values are loaded from environment variables (never hard-coded).
See .env.example for the full list with descriptions.
"""

from __future__ import annotations

import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Allow extra fields gracefully
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "Evidence Guard"
    APP_ENV: str = "development"         # development | staging | production
    DEBUG: bool = False
    # Required in production; test uses a generated value if not set.
    SECRET_KEY: str = ""
    FRONTEND_ORIGIN: str = "http://localhost:5173"

    # ── PostgreSQL ───────────────────────────────────────────────────────────
    POSTGRES_USER: str = "eg_user"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "evidence_guard"
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ── MinIO ────────────────────────────────────────────────────────────────
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ROOT_USER: str = "eg_minio_user"
    MINIO_ROOT_PASSWORD: str = ""
    MINIO_BUCKET: str = "evidence-guard"
    MINIO_SECURE: bool = False           # set True in production (TLS)

    # ── Encryption (P3) ──────────────────────────────────────────────────────
    MASTER_KEY_HEX: str = ""            # 32-byte hex; load from secret mount in prod
    CHUNK_SIZE_BYTES: int = 8 * 1024 * 1024   # 8 MiB

    # ── JWT / Auth (P2) ──────────────────────────────────────────────────────
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    MFA_ISSUER: str = "EvidenceGuard"

    # ── Blockchain (P4) ──────────────────────────────────────────────────────
    LEDGER_PLATFORM: str = "mock"        # fabric | ethereum | mock
    FABRIC_GATEWAY_HOST: str = "localhost"
    FABRIC_GATEWAY_PORT: int = 7051
    ETH_RPC_URL: str = "http://localhost:8545"
    ETH_CONTRACT_ADDRESS: str = ""

    # ── AI service (P9-P12) ──────────────────────────────────────────────────
    AI_SERVICE_URL: str = "http://localhost:8001"
    AI_SERVICE_API_KEY: str = ""         # Set in .env for non-mock
    AI_MAX_INPUT_BYTES: int = 10 * 1024 * 1024   # 10 MiB input cap

    # ── Rate limiting / uploads ───────────────────────────────────────────────
    MAX_UPLOAD_BYTES: int = 2 * 1024 * 1024 * 1024   # 2 GB
    ALLOWED_MIME_TYPES: list[str] = [
        "message/rfc822",          # .eml
        "text/plain",              # .txt, .log
        "text/csv",                # .csv
        "application/json",        # .json
        "image/png",               # .png
        "image/jpeg",              # .jpg/.jpeg
        "application/pdf",         # .pdf
    ]

    def model_post_init(self, __context: object) -> None:
        """Validate required fields that must be set in production."""
        if self.APP_ENV == "production":
            missing = []
            if not self.SECRET_KEY:
                missing.append("SECRET_KEY")
            if not self.POSTGRES_PASSWORD:
                missing.append("POSTGRES_PASSWORD")
            if not self.MINIO_ROOT_PASSWORD:
                missing.append("MINIO_ROOT_PASSWORD")
            if not self.MASTER_KEY_HEX:
                missing.append("MASTER_KEY_HEX")
            if missing:
                raise ValueError(
                    f"Missing required environment variables for production: {missing}"
                )
        # In dev/test, generate ephemeral values if not set
        if not self.SECRET_KEY:
            object.__setattr__(self, "SECRET_KEY", secrets.token_hex(32))
        if not self.MASTER_KEY_HEX:
            object.__setattr__(self, "MASTER_KEY_HEX", secrets.token_hex(32))


settings = Settings()
