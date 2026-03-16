"""Tests for persisted upload-link helpers."""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from database_manager import DatabaseManager
from upload_links import (
    create_upload_link,
    generate_upload_link,
    generate_upload_token,
    get_upload_link_expiry_hours,
    validate_upload_token,
)

TENANT = "t-001"
INVOICE = "INV-2024-001"


@pytest.fixture
def db(tmp_path):
    db = DatabaseManager(str(tmp_path / "upload-links.db"))
    db.initialize()
    db.upsert_nav_invoices(
        TENANT,
        [{
            "invoiceNumber": INVOICE,
            "supplierName": "Supplier Kft",
            "grossAmount": 100000,
            "invoiceDate": "2024-01-10",
        }],
    )
    return db


class TestGenerateUploadToken:

    def test_returns_string(self):
        assert isinstance(generate_upload_token(), str)

    def test_tokens_are_random(self):
        assert generate_upload_token() != generate_upload_token()

    def test_token_is_url_safe(self):
        token = generate_upload_token()
        forbidden = set(" +/=\n\r\t")
        assert not forbidden.intersection(token)


class TestValidateUploadToken:

    def test_valid_token(self, db):
        upload = create_upload_link(db, "https://example.com", TENANT, INVOICE)
        data = validate_upload_token(db, upload["token"])
        assert data is not None
        assert data["tenant_id"] == TENANT
        assert data["invoice_number"] == INVOICE

    def test_expired_token(self, db):
        token = "expired-token"
        db.create_upload_token(
            tenant_id=TENANT,
            invoice_number=INVOICE,
            token=token,
            expires_at=datetime.now() - timedelta(minutes=1),
        )
        assert validate_upload_token(db, token) is None

    def test_used_token_rejected(self, db):
        upload = create_upload_link(db, "https://example.com", TENANT, INVOICE)
        db.mark_upload_token_used(upload["token"], TENANT)
        assert validate_upload_token(db, upload["token"]) is None

    def test_invalidated_token_rejected(self, db):
        upload = create_upload_link(db, "https://example.com", TENANT, INVOICE)
        db.invalidate_upload_tokens(TENANT, token=upload["token"], reason="superseded")
        assert validate_upload_token(db, upload["token"]) is None

    def test_missing_token_rejected(self, db):
        assert validate_upload_token(db, "missing-token") is None


class TestGenerateUploadLink:

    def test_basic_link_structure(self):
        link = generate_upload_link("https://app.navvoice.hu", TENANT, "abc123")
        assert link == "https://app.navvoice.hu/api/v1/public/upload/t-001/abc123"

    def test_strips_trailing_slash(self):
        link = generate_upload_link("https://app.navvoice.hu/", TENANT, "abc123")
        assert "//" not in link.split("://", 1)[1]

    def test_create_upload_link_persists_token(self, db):
        upload = create_upload_link(
            db,
            "https://example.com",
            TENANT,
            INVOICE,
            queue_item_id="APR-1",
            vendor_email="vendor@example.com",
            created_by="tester",
            expires_hours=1,
        )
        assert upload["url"].startswith("https://example.com/api/v1/public/upload/t-001/")
        token_row = db.get_upload_token(upload["token"], tenant_id=TENANT)
        assert token_row is not None
        assert token_row["queue_item_id"] == "APR-1"
        assert token_row["vendor_email"] == "vendor@example.com"


class TestExpiryConfig:

    def test_env_value_used(self):
        with patch.dict("os.environ", {"UPLOAD_LINK_EXPIRY_HOURS": "24"}):
            assert get_upload_link_expiry_hours() == 24

    def test_invalid_env_value_falls_back(self):
        with patch.dict("os.environ", {"UPLOAD_LINK_EXPIRY_HOURS": "abc"}):
            assert get_upload_link_expiry_hours() == 168
