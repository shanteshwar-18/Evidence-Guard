"""
Health endpoint test – P0.1 verification checkpoint.
Run: pytest backend/tests/test_health.py -v
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_200():
    """GET /health must return HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_body():
    """GET /health must return {status: ok}."""
    response = client.get("/health")
    data = response.json()
    assert data["status"] == "ok"
    assert "service" in data
    assert "version" in data


def test_health_content_type():
    """GET /health must return JSON."""
    response = client.get("/health")
    assert "application/json" in response.headers["content-type"]
