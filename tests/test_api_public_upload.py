"""
Tests for api/public.py -- unauthenticated vendor upload endpoint.
"""

import io
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from api import deps
from upload_links import generate_upload_token


TENANT = "t-001"
INVOICE = "INV-2024-001"


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset():
    deps.reset_singletons()
    yield
    deps.reset_singletons()


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.db_path = "data/invoices.db"
    db.initialize = MagicMock()
    return db


@pytest.fixture
def mock_queue():
    return MagicMock()


@pytest.fixture
def client(mock_db, mock_queue):
    app.dependency_overrides[deps.get_db] = lambda: mock_db
    app.dependency_overrides[deps.get_approval_queue] = lambda: mock_queue
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def valid_token():
    return generate_upload_token()


@pytest.fixture
def active_token_row(valid_token):
    return {
        "token": valid_token,
        "tenant_id": TENANT,
        "invoice_number": INVOICE,
        "expires_at": datetime.now() + timedelta(hours=1),
        "used_at": None,
        "invalidated_at": None,
    }


def _pdf_file(name="test.pdf", size=128):
    """Helper: create a tiny fake PDF upload."""
    content = b"%PDF-1.4 " + b"\x00" * size
    return ("file", (name, io.BytesIO(content), "application/pdf"))


# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------


class TestPublicUploadEndpoint:

    @patch("api.public.PDFMalwareScanner")
    @patch("api.public.PDFContentExtractor")
    def test_successful_upload_matched(
        self,
        mock_extractor_cls,
        mock_scanner_cls,
        client,
        mock_db,
        mock_queue,
        valid_token,
        active_token_row,
    ):
        scanner_inst = MagicMock()
        scanner_inst.scan_file.return_value = (True, [])
        mock_scanner_cls.return_value = scanner_inst
        extractor_inst = MagicMock()
        extractor_inst.extract_invoice_data.return_value = {"invoice_numbers": []}
        mock_extractor_cls.return_value = extractor_inst
        mock_db.get_upload_token.return_value = active_token_row

        mock_db.get_invoice.return_value = {
            "nav_invoice_number": INVOICE,
        }

        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        with patch("api.public.Path.mkdir"), \
             patch("api.public.Path.write_bytes"):
            resp = client.post(url, files=[_pdf_file()])

        assert resp.status_code == 200
        body = resp.json()
        assert body["matched"] is True
        assert body["invoice_number"] == INVOICE
        mock_db.mark_as_received.assert_called_once()
        mock_db.mark_upload_token_used.assert_called_once()
        mock_queue.close_for_invoice.assert_called_once()

    @patch("api.public.PDFMalwareScanner")
    @patch("api.public.PDFContentExtractor")
    def test_successful_upload_unmatched(
        self, mock_extractor_cls, mock_scanner_cls, client, mock_db, valid_token, active_token_row,
    ):
        scanner_inst = MagicMock()
        scanner_inst.scan_file.return_value = (True, [])
        mock_scanner_cls.return_value = scanner_inst
        extractor_inst = MagicMock()
        extractor_inst.extract_invoice_data.return_value = {"invoice_numbers": []}
        mock_extractor_cls.return_value = extractor_inst
        mock_db.get_upload_token.return_value = active_token_row
        mock_db.get_invoice.return_value = None

        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        with patch("api.public.Path.mkdir"), \
             patch("api.public.Path.write_bytes"):
            resp = client.post(url, files=[_pdf_file()])

        assert resp.status_code == 200
        body = resp.json()
        assert body["matched"] is False

    def test_invalid_token_rejected(self, client):
        url = f"/api/v1/public/upload/{TENANT}/bad-token"
        resp = client.post(url, files=[_pdf_file()])
        assert resp.status_code == 403

    def test_wrong_tenant_rejected(self, client, mock_db, valid_token, active_token_row):
        mock_db.get_upload_token.return_value = active_token_row
        url = f"/api/v1/public/upload/wrong-tenant/{valid_token}"
        resp = client.post(url, files=[_pdf_file()])
        assert resp.status_code == 403

    def test_non_pdf_rejected(self, client, mock_db, valid_token, active_token_row):
        mock_db.get_upload_token.return_value = active_token_row
        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        file = (
            "file",
            ("doc.txt", io.BytesIO(b"hello"), "text/plain"),
        )
        resp = client.post(url, files=[file])
        assert resp.status_code == 422

    def test_oversized_file_rejected(self, client, mock_db, valid_token, active_token_row):
        mock_db.get_upload_token.return_value = active_token_row
        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        big = b"%PDF-1.4 " + b"\x00" * (51 * 1024 * 1024)
        file = (
            "file",
            ("big.pdf", io.BytesIO(big), "application/pdf"),
        )
        resp = client.post(url, files=[file])
        assert resp.status_code == 413

    @patch("api.public.PDFMalwareScanner")
    @patch("api.public.PDFContentExtractor")
    def test_malware_scan_failure(
        self, mock_extractor_cls, mock_scanner_cls, client, mock_db, valid_token, active_token_row,
    ):
        scanner_inst = MagicMock()
        scanner_inst.scan_file.return_value = (
            False, ["JavaScript detected"],
        )
        mock_scanner_cls.return_value = scanner_inst
        mock_extractor_cls.return_value = MagicMock()
        mock_db.get_upload_token.return_value = active_token_row

        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        with patch("api.public.Path.mkdir"), \
             patch("api.public.Path.write_bytes"), \
             patch("api.public.Path.unlink"):
            resp = client.post(url, files=[_pdf_file()])

        assert resp.status_code == 422
        assert "security scan" in resp.json()["detail"]

    def test_expired_token_rejected(self, client, mock_db, valid_token):
        mock_db.get_upload_token.return_value = {
            "token": valid_token,
            "tenant_id": TENANT,
            "invoice_number": INVOICE,
            "expires_at": datetime.now() - timedelta(minutes=1),
            "used_at": None,
            "invalidated_at": None,
        }
        token = valid_token
        url = f"/api/v1/public/upload/{TENANT}/{token}"
        resp = client.post(url, files=[_pdf_file()])
        assert resp.status_code == 403

    def test_upload_page_renders(self, client, mock_db, valid_token, active_token_row):
        mock_db.get_upload_token.return_value = active_token_row
        resp = client.get(f"/api/v1/public/upload/{TENANT}/{valid_token}")
        assert resp.status_code == 200
        assert "Hiányzó számla feltöltése" in resp.text
        assert INVOICE in resp.text

    def test_upload_page_invalid_token_shows_disabled_form(self, client):
        resp = client.get(f"/api/v1/public/upload/{TENANT}/bad-token")
        assert resp.status_code == 200
        assert "ervenytelen" in resp.text
