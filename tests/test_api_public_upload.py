"""
Tests for api/public.py -- unauthenticated vendor upload endpoint.
"""

import io
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from api import deps
from upload_links import generate_upload_token


SECRET = "test-upload-secret"
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
def client(mock_db):
    app.dependency_overrides[deps.get_db] = lambda: mock_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def valid_token():
    return generate_upload_token(TENANT, INVOICE, SECRET)


def _pdf_file(name="test.pdf", size=128):
    """Helper: create a tiny fake PDF upload."""
    content = b"%PDF-1.4 " + b"\x00" * size
    return ("file", (name, io.BytesIO(content), "application/pdf"))


# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------


class TestPublicUploadEndpoint:

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    @patch("api.public.PDFMalwareScanner")
    def test_successful_upload_matched(
        self, mock_scanner_cls, client, mock_db, valid_token,
    ):
        scanner_inst = MagicMock()
        scanner_inst.scan_file.return_value = (True, [])
        mock_scanner_cls.return_value = scanner_inst

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

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    @patch("api.public.PDFMalwareScanner")
    def test_successful_upload_unmatched(
        self, mock_scanner_cls, client, mock_db, valid_token,
    ):
        scanner_inst = MagicMock()
        scanner_inst.scan_file.return_value = (True, [])
        mock_scanner_cls.return_value = scanner_inst
        mock_db.get_invoice.return_value = None

        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        with patch("api.public.Path.mkdir"), \
             patch("api.public.Path.write_bytes"):
            resp = client.post(url, files=[_pdf_file()])

        assert resp.status_code == 200
        body = resp.json()
        assert body["matched"] is False

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    def test_invalid_token_rejected(self, client):
        url = f"/api/v1/public/upload/{TENANT}/bad-token"
        resp = client.post(url, files=[_pdf_file()])
        assert resp.status_code == 403

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    def test_wrong_tenant_rejected(self, client, valid_token):
        url = f"/api/v1/public/upload/wrong-tenant/{valid_token}"
        resp = client.post(url, files=[_pdf_file()])
        assert resp.status_code == 403

    @patch.dict(
        os.environ, {"UPLOAD_LINK_SECRET": ""},
        clear=False,
    )
    def test_missing_secret_returns_503(self, client, valid_token):
        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        resp = client.post(url, files=[_pdf_file()])
        assert resp.status_code == 503

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    def test_non_pdf_rejected(self, client, valid_token):
        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        file = (
            "file",
            ("doc.txt", io.BytesIO(b"hello"), "text/plain"),
        )
        resp = client.post(url, files=[file])
        assert resp.status_code == 422

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    def test_oversized_file_rejected(self, client, valid_token):
        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        big = b"%PDF-1.4 " + b"\x00" * (51 * 1024 * 1024)
        file = (
            "file",
            ("big.pdf", io.BytesIO(big), "application/pdf"),
        )
        resp = client.post(url, files=[file])
        assert resp.status_code == 413

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    @patch("api.public.PDFMalwareScanner")
    def test_malware_scan_failure(
        self, mock_scanner_cls, client, valid_token,
    ):
        scanner_inst = MagicMock()
        scanner_inst.scan_file.return_value = (
            False, ["JavaScript detected"],
        )
        mock_scanner_cls.return_value = scanner_inst

        url = f"/api/v1/public/upload/{TENANT}/{valid_token}"
        with patch("api.public.Path.mkdir"), \
             patch("api.public.Path.write_bytes"), \
             patch("api.public.Path.unlink"):
            resp = client.post(url, files=[_pdf_file()])

        assert resp.status_code == 422
        assert "security scan" in resp.json()["detail"]

    @patch.dict(os.environ, {"UPLOAD_LINK_SECRET": SECRET})
    def test_expired_token_rejected(self, client):
        token = generate_upload_token(
            TENANT, INVOICE, SECRET, expires_hours=0,
        )
        url = f"/api/v1/public/upload/{TENANT}/{token}"
        import time
        time.sleep(0.1)
        resp = client.post(url, files=[_pdf_file()])
        assert resp.status_code == 403
