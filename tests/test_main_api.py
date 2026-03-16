"""
Tests for NAVvoice FastAPI application.

Tests health endpoint and reconcile endpoint behavior
(mocked credentials for reconcile success path).
"""

import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient

from main import app


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def mock_nav_credentials(monkeypatch):
    """Set minimal NAV env vars so _get_nav_credentials succeeds."""
    monkeypatch.setenv("NAV_TECHNICAL_USER", "testuser")
    monkeypatch.setenv("NAV_PASSWORD", "testpass")
    monkeypatch.setenv("NAV_SIGNATURE_KEY", "a" * 32)
    monkeypatch.setenv("NAV_REPLACEMENT_KEY", "b" * 32)
    monkeypatch.setenv("NAV_TAX_NUMBER", "12345678")


@pytest.fixture
def clear_nav_credentials(monkeypatch):
    """Ensure NAV credentials are not set."""
    for key in (
        "NAV_TECHNICAL_USER", "NAV_LOGIN", "NAV_PASSWORD",
        "NAV_SIGNATURE_KEY", "NAV_REPLACEMENT_KEY", "NAV_TAX_NUMBER"
    ):
        monkeypatch.delenv(key, raising=False)


# =============================================================================
# HEALTH ENDPOINT
# =============================================================================

class TestHealthEndpoint:
    """Tests for GET /health."""

    def test_health_returns_200(self, client):
        """Health endpoint returns 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "navvoice"


# =============================================================================
# RECONCILE ENDPOINT
# =============================================================================

class TestReconcileEndpoint:
    """Tests for POST /api/v1/tenants/{tenant_id}/reconcile."""

    def test_reconcile_without_credentials_returns_503(
        self, client, clear_nav_credentials
    ):
        """Reconcile returns 503 when NAV credentials are not configured."""
        response = client.post(
            "/api/v1/tenants/test-tenant/reconcile",
            json={},
        )
        assert response.status_code == 503
        assert "NAV credentials" in response.json()["detail"]

    @patch("main.run_reconciliation")
    def test_reconcile_with_credentials_calls_engine(
        self, mock_run, client, mock_nav_credentials
    ):
        """Reconcile calls run_reconciliation when credentials are set."""
        mock_run.return_value = {
            "nav_fetched": 5,
            "inserted": 3,
            "skipped": 2,
            "matched": 1,
            "missing_count": 0,
            "emails_generated": 0,
            "queue_added": 0,
            "errors": [],
        }
        response = client.post(
            "/api/v1/tenants/my-tenant/reconcile",
            json={
                "date_from": "2024-01-01",
                "date_to": "2024-01-31",
                "pdf_folder_path": "data/pdfs/my-tenant",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == "my-tenant"
        assert data["status"] == "complete"
        assert data["summary"]["nav_fetched"] == 5
        mock_run.assert_called_once()
        call_config = mock_run.call_args[1]["config"]
        assert call_config.date_from == "2024-01-01"
        assert call_config.date_to == "2024-01-31"
        assert call_config.pdf_folder_path == "data/pdfs/my-tenant"

    @patch("main.run_reconciliation")
    def test_reconcile_uses_defaults_when_body_empty(
        self, mock_run, client, mock_nav_credentials
    ):
        """Reconcile uses default date range and pdf path when body empty."""
        mock_run.return_value = {
            "nav_fetched": 0,
            "inserted": 0,
            "skipped": 0,
            "matched": 0,
            "missing_count": 0,
            "emails_generated": 0,
            "queue_added": 0,
            "errors": [],
        }
        response = client.post(
            "/api/v1/tenants/tenant-123/reconcile",
            json={},
        )
        assert response.status_code == 200
        mock_run.assert_called_once()
        call_config = mock_run.call_args[1]["config"]
        assert call_config.pdf_folder_path == os.path.join("data", "pdfs", "tenant-123")
