"""
Evidence Guard – FastAPI application entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings

app = FastAPI(
    title="Evidence Guard API",
    version="0.1.0",
    description=(
        "Blockchain-backed digital evidence management system with AI-assisted "
        "investigation. AI outputs are leads, not findings."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS (allow only the configured frontend origin) ─────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Health endpoint (P0.1 requirement) ───────────────────────────────────────
@app.get("/health", tags=["system"])
async def health() -> dict:
    """Return service health status. Used by Docker health checks and CI."""
    return {"status": "ok", "service": "evidence-guard-backend", "version": "0.1.0"}


# ── API routers (added progressively through P1-P15) ─────────────────────────
# Routers are imported and registered here as each build unit is completed.
# Example (uncomment as units are built):
# from app.api import auth, cases, evidence, uploads, ai_analysis, reports, admin
# app.include_router(auth.router,         prefix="/api/v1/auth",     tags=["auth"])
# app.include_router(cases.router,        prefix="/api/v1/cases",    tags=["cases"])
# app.include_router(evidence.router,     prefix="/api/v1/evidence", tags=["evidence"])
# app.include_router(uploads.router,      prefix="/api/v1/uploads",  tags=["uploads"])
# app.include_router(ai_analysis.router,  prefix="/api/v1/ai",       tags=["ai"])
# app.include_router(reports.router,      prefix="/api/v1/reports",  tags=["reports"])
# app.include_router(admin.router,        prefix="/api/v1/admin",    tags=["admin"])
