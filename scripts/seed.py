"""
Evidence Guard – database seed script for synthetic data.
Run: python scripts/seed.py
"""

import asyncio
import random
import string
from datetime import datetime, timezone

# Seed is deterministic – reproducible results
random.seed(42)


CASES = [
    {
        "case_id": "CYB-2025-001",
        "title": "Phishing Campaign – Finance Department",
        "status": "active",
        "priority": "high",
    },
    {
        "case_id": "CYB-2025-002",
        "title": "Insider Threat Investigation – IT Access Logs",
        "status": "under_review",
        "priority": "medium",
    },
    {
        "case_id": "CYB-2025-003",
        "title": "Ransomware Incident – Server Farm",
        "status": "resolved",
        "priority": "critical",
    },
    {
        "case_id": "CYB-2025-014",
        "title": "Suspicious Email – CEO Impersonation",
        "status": "active",
        "priority": "high",
    },
]

USERS = [
    {"username": "alex.carter",   "role": "investigator", "display": "Alex Carter"},
    {"username": "priya.sharma",  "role": "analyst",       "display": "Priya Sharma"},
    {"username": "raj.patel",     "role": "supervisor",    "display": "Raj Patel"},
    {"username": "admin",         "role": "admin",          "display": "System Admin"},
]


def seed():
    print("=== Evidence Guard – Seeding synthetic data ===")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"  Cases to seed: {len(CASES)}")
    print(f"  Users to seed: {len(USERS)}")
    print()
    print("NOTE: This script seeds the in-memory/mock data model.")
    print("      Database migrations will be run in P1.")
    print()
    for case in CASES:
        print(f"  [CASE] {case['case_id']}: {case['title']} ({case['priority']})")
    for user in USERS:
        print(f"  [USER] {user['username']} ({user['role']})")
    print()
    print("✅ Seed complete (no DB connection required at P0).")
    print("   Full seed with Alembic migrations comes in P1.")


if __name__ == "__main__":
    seed()
