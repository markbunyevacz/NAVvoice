"""
Tests for upload_links.py -- token generation, validation, and link building.
"""

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from upload_links import (
    generate_upload_token,
    validate_upload_token,
    generate_upload_link,
)


SECRET = "test-secret-key-2024"
TENANT = "t-001"
INVOICE = "INV-2024-001"


# =============================================================================
# generate_upload_token
# =============================================================================


class TestGenerateUploadToken:

    def test_returns_string(self):
        token = generate_upload_token(TENANT, INVOICE, SECRET)
        assert isinstance(token, str)

    def test_contains_dot_separator(self):
        token = generate_upload_token(TENANT, INVOICE, SECRET)
        assert "." in token
        parts = token.split(".")
        assert len(parts) == 2

    def test_deterministic_within_same_second(self):
        t1 = generate_upload_token(TENANT, INVOICE, SECRET, 1)
        t2 = generate_upload_token(TENANT, INVOICE, SECRET, 1)
        assert t1 == t2

    def test_different_secrets_produce_different_tokens(self):
        t1 = generate_upload_token(TENANT, INVOICE, "secret-a")
        t2 = generate_upload_token(TENANT, INVOICE, "secret-b")
        assert t1 != t2

    def test_url_safe(self):
        token = generate_upload_token(TENANT, INVOICE, SECRET)
        forbidden = set(" +/=\n\r\t")
        payload_part = token.split(".")[0]
        assert not forbidden.intersection(payload_part)


# =============================================================================
# validate_upload_token
# =============================================================================


class TestValidateUploadToken:

    def test_valid_token(self):
        token = generate_upload_token(TENANT, INVOICE, SECRET)
        data = validate_upload_token(token, SECRET)
        assert data is not None
        assert data["tenant_id"] == TENANT
        assert data["invoice_number"] == INVOICE

    def test_expired_token(self):
        token = generate_upload_token(
            TENANT, INVOICE, SECRET, expires_hours=0,
        )
        with patch("upload_links.time") as mock_time:
            mock_time.time.return_value = time.time() + 1
            data = validate_upload_token(token, SECRET)
        assert data is None

    def test_wrong_secret_rejected(self):
        token = generate_upload_token(TENANT, INVOICE, SECRET)
        data = validate_upload_token(token, "wrong-secret")
        assert data is None

    def test_tampered_payload_rejected(self):
        token = generate_upload_token(TENANT, INVOICE, SECRET)
        parts = token.split(".")
        tampered = "dGFtcGVyZWQ=." + parts[1]
        data = validate_upload_token(tampered, SECRET)
        assert data is None

    def test_tampered_signature_rejected(self):
        token = generate_upload_token(TENANT, INVOICE, SECRET)
        parts = token.split(".")
        tampered = parts[0] + ".0000000000000000"
        data = validate_upload_token(tampered, SECRET)
        assert data is None

    def test_empty_token(self):
        assert validate_upload_token("", SECRET) is None

    def test_no_dot_token(self):
        assert validate_upload_token("nodot", SECRET) is None

    def test_bad_base64(self):
        assert validate_upload_token("!!!.abcd", SECRET) is None

    def test_wrong_segment_count(self):
        import base64
        payload = base64.urlsafe_b64encode(
            b"only-two-segments",
        ).decode()
        assert validate_upload_token(
            f"{payload}.abcdef0123456789", SECRET,
        ) is None

    def test_non_integer_expiry(self):
        import base64
        payload = base64.urlsafe_b64encode(
            b"t-001:INV-001:not-a-number",
        ).decode()
        assert validate_upload_token(
            f"{payload}.abcdef0123456789", SECRET,
        ) is None


# =============================================================================
# generate_upload_link
# =============================================================================


class TestGenerateUploadLink:

    def test_basic_link_structure(self):
        link = generate_upload_link(
            "https://app.navvoice.hu",
            TENANT, INVOICE, SECRET,
        )
        assert link.startswith(
            f"https://app.navvoice.hu/api/v1/public/upload/{TENANT}/",
        )

    def test_strips_trailing_slash(self):
        link = generate_upload_link(
            "https://app.navvoice.hu/",
            TENANT, INVOICE, SECRET,
        )
        assert "//" not in link.split("://", 1)[1]

    def test_token_in_link_is_valid(self):
        link = generate_upload_link(
            "https://example.com",
            TENANT, INVOICE, SECRET,
        )
        token = link.rsplit("/", 1)[-1]
        data = validate_upload_token(token, SECRET)
        assert data is not None
        assert data["tenant_id"] == TENANT
        assert data["invoice_number"] == INVOICE

    def test_custom_expiry(self):
        link = generate_upload_link(
            "https://example.com",
            TENANT, INVOICE, SECRET,
            expires_hours=1,
        )
        token = link.rsplit("/", 1)[-1]
        data = validate_upload_token(token, SECRET)
        assert data is not None
        assert data["expiry"] <= int(time.time()) + 3601
