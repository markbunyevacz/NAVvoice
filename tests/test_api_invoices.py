"""
Tests for api/invoices.py -- list, sync, upload endpoints.

DatabaseManager, reconciliation engine, and PDF scanner are mocked.
"""

import io
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from api import deps
from auth import AuthService, AuthConfig, UserRole, User, Permission


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _make_auth_service():
    svc = AuthService(AuthConfig(secret_key="test-key-invoices"))
    return svc


def _register_and_token(svc, email, password, role, tenant_id="t-001"):
    svc.register(email=email, password=password, role=role, tenant_id=tenant_id, name="Test")
    result = svc.login(email, password)
    return result["access_token"]


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset():
    deps.reset_singletons()
    yield
    deps.reset_singletons()


@pytest.fixture
def auth_service():
    return _make_auth_service()


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.db_path = "data/invoices.db"
    db.initialize = MagicMock()
    return db


@pytest.fixture
def client(auth_service, mock_db):
    app.dependency_overrides[deps.get_auth_service] = lambda: auth_service
    app.dependency_overrides[deps.get_db] = lambda: mock_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def accountant_token(auth_service):
    return _register_and_token(
        auth_service, "acc@test.hu", "Passw0rd!Strong", UserRole.ACCOUNTANT
    )


@pytest.fixture
def site_manager_token(auth_service):
    return _register_and_token(
        auth_service, "site@test.hu", "Passw0rd!Strong", UserRole.SITE_MANAGER
    )


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# -------------------------------------------------------------------------
# GET /api/v1/invoices
# -------------------------------------------------------------------------

class TestListInvoices:
    def test_list_returns_items(self, client, accountant_token, mock_db):
        mock_db.search_invoices.return_value = [
            {
                "id": 1,
                "tenant_id": "t-001",
                "nav_invoice_number": "INV-001",
                "vendor_name": "Supplier Kft",
                "vendor_tax_number": "12345678",
                "amount": 100000.0,
                "currency": "HUF",
                "invoice_date": "2024-01-15",
                "status": "MISSING",
                "last_updated": "2024-01-20T10:00:00",
                "email_count": 0,
                "pdf_path": None,
                "notes": None,
            }
        ]
        resp = client.get("/api/v1/invoices", headers=_auth(accountant_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["items"][0]["nav_invoice_number"] == "INV-001"

    def test_list_with_status_filter(self, client, accountant_token, mock_db):
        mock_db.get_invoices_by_status.return_value = []
        resp = client.get(
            "/api/v1/invoices?status=MISSING",
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 200
        mock_db.get_invoices_by_status.assert_called_once()

    def test_list_invalid_status(self, client, accountant_token):
        resp = client.get(
            "/api/v1/invoices?status=INVALID",
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 422

    def test_list_with_search_query(self, client, accountant_token, mock_db):
        mock_db.search_invoices.return_value = []
        resp = client.get(
            "/api/v1/invoices?query=Supplier",
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 200
        mock_db.search_invoices.assert_called_once_with("t-001", "Supplier", limit=100)

    def test_list_requires_auth(self, client):
        resp = client.get("/api/v1/invoices")
        assert resp.status_code == 401

    def test_site_manager_can_view(self, client, site_manager_token, mock_db):
        mock_db.search_invoices.return_value = []
        resp = client.get("/api/v1/invoices", headers=_auth(site_manager_token))
        assert resp.status_code == 200


# -------------------------------------------------------------------------
# POST /api/v1/invoices/sync
# -------------------------------------------------------------------------

class TestSyncInvoices:
    @patch("reconciliation_engine.run_reconciliation")
    def test_sync_success(self, mock_recon, client, accountant_token, mock_db, monkeypatch):
        monkeypatch.setenv("NAV_TECHNICAL_USER", "testuser")
        monkeypatch.setenv("NAV_PASSWORD", "testpass")
        monkeypatch.setenv("NAV_SIGNATURE_KEY", "a" * 32)
        monkeypatch.setenv("NAV_REPLACEMENT_KEY", "b" * 32)
        monkeypatch.setenv("NAV_TAX_NUMBER", "12345678")

        mock_recon.return_value = {"nav_fetched": 3, "inserted": 2}

        resp = client.post(
            "/api/v1/invoices/sync",
            json={"date_from": "2024-01-01", "date_to": "2024-01-31"},
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "complete"
        assert data["summary"]["nav_fetched"] == 3

    def test_sync_no_nav_creds(self, client, accountant_token, monkeypatch):
        for key in ("NAV_TECHNICAL_USER", "NAV_LOGIN", "NAV_PASSWORD",
                     "NAV_SIGNATURE_KEY", "NAV_REPLACEMENT_KEY", "NAV_TAX_NUMBER"):
            monkeypatch.delenv(key, raising=False)

        resp = client.post("/api/v1/invoices/sync", headers=_auth(accountant_token))
        assert resp.status_code == 503

    def test_sync_forbidden_for_site_manager(self, client, site_manager_token):
        resp = client.post("/api/v1/invoices/sync", headers=_auth(site_manager_token))
        assert resp.status_code == 403


# -------------------------------------------------------------------------
# POST /api/v1/invoices/{id}/upload
# -------------------------------------------------------------------------

class TestUploadPDF:
    @patch("pdf_scanner.PDFMalwareScanner")
    def test_upload_matches_invoice(self, MockScanner, client, accountant_token, mock_db, tmp_path):
        MockScanner.return_value.scan_file.return_value = (True, [])
        mock_db.get_invoice.return_value = {"id": 1, "nav_invoice_number": "INV-001"}
        mock_db.mark_as_received.return_value = True

        pdf_bytes = b"%PDF-1.4 fake content"
        resp = client.post(
            "/api/v1/invoices/INV-001/upload",
            headers=_auth(accountant_token),
            files={"file": ("Supplier_INV-001.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["matched"] is True
        assert data["invoice_number"] == "INV-001"

    @patch("pdf_scanner.PDFMalwareScanner")
    def test_upload_no_matching_invoice(self, MockScanner, client, accountant_token, mock_db):
        MockScanner.return_value.scan_file.return_value = (True, [])
        mock_db.get_invoice.return_value = None

        pdf_bytes = b"%PDF-1.4 fake content"
        resp = client.post(
            "/api/v1/invoices/INV-999/upload",
            headers=_auth(accountant_token),
            files={"file": ("doc.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
        )
        assert resp.status_code == 200
        assert resp.json()["matched"] is False

    def test_upload_rejects_non_pdf(self, client, accountant_token):
        resp = client.post(
            "/api/v1/invoices/INV-001/upload",
            headers=_auth(accountant_token),
            files={"file": ("data.csv", io.BytesIO(b"a,b,c"), "text/csv")},
        )
        assert resp.status_code == 422
        assert "PDF" in resp.json()["detail"]

    def test_upload_requires_auth(self, client):
        resp = client.post(
            "/api/v1/invoices/INV-001/upload",
            files={"file": ("x.pdf", io.BytesIO(b"%PDF"), "application/pdf")},
        )
        assert resp.status_code == 401

    def test_upload_allowed_for_site_manager(self, client, site_manager_token, mock_db):
        with patch("pdf_scanner.PDFMalwareScanner") as MockScanner:
            MockScanner.return_value.scan_file.return_value = (True, [])
            mock_db.get_invoice.return_value = None

            resp = client.post(
                "/api/v1/invoices/INV-001/upload",
                headers=_auth(site_manager_token),
                files={"file": ("doc.pdf", io.BytesIO(b"%PDF-1.4"), "application/pdf")},
            )
            assert resp.status_code == 200
