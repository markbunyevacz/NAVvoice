"""
Unit Tests for NAV Online Számla v3.0 API Client

Run with: pytest test_nav_client.py -v
"""

import pytest
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone
from lxml import etree

from nav_client import (
    NavClient,
    NavCredentials,
    NavApiError,
    NavErrorCode,
    NAMESPACES
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def valid_credentials():
    """Valid NAV credentials for testing."""
    return NavCredentials(
        login="test_user",
        password="test_password_123",
        signature_key="12345678901234567890123456789012",  # 32 chars
        replacement_key="abcdefghijklmnopqrstuvwxyz123456",  # 32 chars
        tax_number="12345678"
    )


@pytest.fixture
def nav_client(valid_credentials):
    """NavClient instance for testing."""
    return NavClient(
        credentials=valid_credentials,
        use_test_api=True,
        software_id="HUTEST12345-0001"
    )


@pytest.fixture
def sample_invoice_digest_response():
    """Sample NAV API response XML for invoice digest query."""
    return b'''<?xml version="1.0" encoding="UTF-8"?>
    <QueryInvoiceDigestResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
        <header xmlns="http://schemas.nav.gov.hu/OSA/3.0/common">
            <requestId>ABC123</requestId>
            <timestamp>2024-01-15T10:30:00.000Z</timestamp>
            <requestVersion>3.0</requestVersion>
            <headerVersion>1.0</headerVersion>
        </header>
        <result xmlns="http://schemas.nav.gov.hu/OSA/3.0/common">
            <funcCode>OK</funcCode>
        </result>
        <invoiceDigestResult>
            <availablePage>1</availablePage>
            <currentPage>1</currentPage>
            <invoiceDigest>
                <invoiceNumber>INV-2024-001</invoiceNumber>
                <supplierName>Test Supplier Kft.</supplierName>
                <supplierTaxNumber>87654321</supplierTaxNumber>
                <invoiceIssueDate>2024-01-10</invoiceIssueDate>
                <invoiceNetAmount>100000</invoiceNetAmount>
                <invoiceVatAmount>25000</invoiceVatAmount>
                <currency>HUF</currency>
            </invoiceDigest>
            <invoiceDigest>
                <invoiceNumber>INV-2024-002</invoiceNumber>
                <supplierName>Another Vendor Zrt.</supplierName>
                <supplierTaxNumber>11223344</supplierTaxNumber>
                <invoiceIssueDate>2024-01-12</invoiceIssueDate>
                <invoiceNetAmount>200000</invoiceNetAmount>
                <invoiceVatAmount>50000.50</invoiceVatAmount>
                <currency>EUR</currency>
            </invoiceDigest>
        </invoiceDigestResult>
    </QueryInvoiceDigestResponse>'''


@pytest.fixture
def error_response():
    """Sample NAV API error response."""
    return b'''<?xml version="1.0" encoding="UTF-8"?>
    <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
        <result xmlns="http://schemas.nav.gov.hu/OSA/3.0/common">
            <funcCode>ERROR</funcCode>
            <errorCode>INVALID_SECURITY_TOKEN</errorCode>
            <message>Authentication failed</message>
        </result>
    </GeneralErrorResponse>'''


# =============================================================================
# CREDENTIALS VALIDATION TESTS
# =============================================================================

class TestNavCredentials:
    """Test credential validation."""
    
    def test_valid_credentials(self, valid_credentials):
        """Valid credentials should be accepted."""
        assert valid_credentials.login == "test_user"
        assert valid_credentials.tax_number == "12345678"
    
    def test_invalid_signature_key_length(self):
        """Signature key must be exactly 32 characters."""
        with pytest.raises(ValueError, match="Signature key must be exactly 32"):
            NavCredentials(
                login="user",
                password="pass",
                signature_key="too_short",
                replacement_key="12345678901234567890123456789012",
                tax_number="12345678"
            )
    
    def test_invalid_replacement_key_length(self):
        """Replacement key must be exactly 32 characters."""
        with pytest.raises(ValueError, match="Replacement key must be exactly 32"):
            NavCredentials(
                login="user",
                password="pass",
                signature_key="12345678901234567890123456789012",
                replacement_key="short",
                tax_number="12345678"
            )
    
    def test_invalid_tax_number_format(self):
        """Tax number must be 8 digits."""
        with pytest.raises(ValueError, match="Tax number must be 8 digits"):
            NavCredentials(
                login="user",
                password="pass",
                signature_key="12345678901234567890123456789012",
                replacement_key="12345678901234567890123456789012",
                tax_number="1234567"  # 7 digits
            )
    
    def test_tax_number_non_numeric(self):
        """Tax number must be numeric only."""
        with pytest.raises(ValueError, match="Tax number must be 8 digits"):
            NavCredentials(
                login="user",
                password="pass",
                signature_key="12345678901234567890123456789012",
                replacement_key="12345678901234567890123456789012",
                tax_number="1234567A"
            )


# =============================================================================
# CRYPTOGRAPHIC TESTS
# =============================================================================

class TestCryptography:
    """Test SHA-512 hashing and signature generation."""

    def test_sha512_hash(self, nav_client):
        """Test SHA-512 hash generation."""
        result = nav_client._hash_sha512("test")
        expected = hashlib.sha512("test".encode('utf-8')).hexdigest().upper()
        assert result == expected
        assert len(result) == 128  # SHA-512 produces 128 hex chars

    def test_password_hash(self, nav_client):
        """Test password hashing."""
        result = nav_client._compute_password_hash()
        expected = hashlib.sha512("test_password_123".encode('utf-8')).hexdigest().upper()
        assert result == expected

    def test_request_signature_format(self, nav_client):
        """Test request signature is valid SHA-512 hash."""
        request_id = "ABC123456789012345678901234567"
        timestamp = "2024-01-15T10:30:00.000Z"

        signature = nav_client._compute_request_signature(request_id, timestamp)

        assert len(signature) == 128
        assert signature.isupper()
        assert all(c in '0123456789ABCDEF' for c in signature)

    def test_request_signature_deterministic(self, nav_client):
        """Same inputs should produce same signature."""
        request_id = "ABC123456789012345678901234567"
        timestamp = "2024-01-15T10:30:00.000Z"

        sig1 = nav_client._compute_request_signature(request_id, timestamp)
        sig2 = nav_client._compute_request_signature(request_id, timestamp)

        assert sig1 == sig2

    def test_request_signature_different_for_different_inputs(self, nav_client):
        """Different inputs should produce different signatures."""
        request_id = "ABC123456789012345678901234567"

        sig1 = nav_client._compute_request_signature(request_id, "2024-01-15T10:30:00.000Z")
        sig2 = nav_client._compute_request_signature(request_id, "2024-01-15T10:30:01.000Z")

        assert sig1 != sig2

    def test_request_id_generation(self, nav_client):
        """Test request ID format."""
        request_id = nav_client._generate_request_id()

        assert len(request_id) == 30
        assert request_id.isalnum()

    def test_request_id_unique(self, nav_client):
        """Request IDs should be unique."""
        ids = [nav_client._generate_request_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_timestamp_format(self, nav_client):
        """Test UTC timestamp format."""
        timestamp = nav_client._get_utc_timestamp()

        # Should match: 2024-01-15T10:30:00.000Z
        assert 'T' in timestamp
        assert timestamp.endswith('Z')
        assert len(timestamp) == 24


# =============================================================================
# XML BUILDING TESTS
# =============================================================================

class TestXmlBuilding:
    """Test XML request construction."""

    def test_build_header(self, nav_client):
        """Test header element structure."""
        request_id = "TEST123456789012345678901234"
        timestamp = "2024-01-15T10:30:00.000Z"

        header = nav_client._build_basic_header(request_id, timestamp)

        assert header.tag == "{%s}header" % NAMESPACES['common']
        assert header.find("{%s}requestId" % NAMESPACES['common']).text == request_id
        assert header.find("{%s}timestamp" % NAMESPACES['common']).text == timestamp
        assert header.find("{%s}requestVersion" % NAMESPACES['common']).text == "3.0"

    def test_build_user_element(self, nav_client):
        """Test user authentication element."""
        request_id = "TEST123456789012345678901234"
        timestamp = "2024-01-15T10:30:00.000Z"

        user = nav_client._build_user_element(request_id, timestamp)

        assert user.find("{%s}login" % NAMESPACES['common']).text == "test_user"
        assert user.find("{%s}taxNumber" % NAMESPACES['common']).text == "12345678"
        # Password should be hashed
        password_hash = user.find("{%s}passwordHash" % NAMESPACES['common']).text
        assert len(password_hash) == 128

    def test_build_software_element(self, nav_client):
        """Test software identification element."""
        software = nav_client._build_software_element()

        assert software.find("{%s}softwareId" % NAMESPACES['api']).text == "HUTEST12345-0001"
        assert software.find("{%s}softwareOperation" % NAMESPACES['api']).text == "ONLINE_SERVICE"

    def test_build_query_data_request_valid_xml(self, nav_client):
        """Test complete query data request is valid XML."""
        request_body = nav_client._build_query_invoice_data_request(
            invoice_number="INV-2024-001",
            invoice_direction="INBOUND"
        )

        # Should be valid XML
        root = etree.fromstring(request_body)
        assert root.tag.endswith("QueryInvoiceDataRequest")
        assert NAMESPACES['api'] in root.tag

        # Should have declaration
        assert request_body.startswith(b"<?xml")

    def test_build_query_digest_request_valid_xml(self, nav_client):
        """Test complete query digest request is valid XML."""
        request_body = nav_client._build_query_invoice_digest_request(
            invoice_direction="INBOUND",
            issue_date_from="2024-01-01",
            issue_date_to="2024-01-31",
            page=1
        )
        
        root = etree.fromstring(request_body)
        assert root.tag.endswith("QueryInvoiceDigestRequest")
        assert NAMESPACES['api'] in root.tag


# =============================================================================
# RESPONSE PARSING TESTS
# =============================================================================

class TestResponseParsing:
    """Test XML response parsing."""

    def test_parse_invoice_digest_response(self, nav_client, sample_invoice_digest_response):
        """Test parsing valid invoice digest response."""
        invoices = nav_client._parse_invoice_digest_response(sample_invoice_digest_response)

        assert len(invoices) == 2

        inv1 = invoices[0]
        assert inv1["invoiceNumber"] == "INV-2024-001"
        assert inv1["supplierName"] == "Test Supplier Kft."
        assert inv1["invoiceNetAmount"] == 100000.0
        assert inv1["invoiceVatAmount"] == 25000.0
        assert inv1["currency"] == "HUF"

        inv2 = invoices[1]
        assert inv2["invoiceNumber"] == "INV-2024-002"
        assert inv2["currency"] == "EUR"


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling:
    """Test error detection and handling."""

    def test_check_response_for_errors(self, nav_client, error_response):
        """Test error detection in response."""
        with pytest.raises(NavApiError) as exc_info:
            nav_client._check_response_for_errors(error_response)

        assert exc_info.value.code == "INVALID_SECURITY_TOKEN"
        assert "Authentication failed" in exc_info.value.message

    def test_retryable_errors(self):
        """Test which errors are retryable."""
        retryable = NavApiError("TOO_MANY_REQUESTS", "Rate limited")
        non_retryable = NavApiError("INVALID_SIGNATURE", "Bad signature")

        assert retryable.is_retryable is True
        assert non_retryable.is_retryable is False

    def test_date_validation_valid(self, nav_client):
        """Valid dates should pass validation."""
        nav_client._validate_date_format("2024-01-15")
        nav_client._validate_date_format("2024-12-31")

    def test_date_validation_invalid(self, nav_client):
        """Invalid dates should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid date format"):
            nav_client._validate_date_format("2024/01/15")

        with pytest.raises(ValueError, match="Invalid date format"):
            nav_client._validate_date_format("15-01-2024")

        with pytest.raises(ValueError, match="Invalid date format"):
            nav_client._validate_date_format("invalid")


# =============================================================================
# RETRY MECHANISM TESTS
# =============================================================================

class TestRetryMechanism:
    """Test retry logic with mocked HTTP responses."""

    @patch('nav_client.requests.Session')
    def test_successful_request_no_retry(self, mock_session_class, valid_credentials, sample_invoice_digest_response):
        """Successful request should not retry."""
        mock_session = MagicMock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = sample_invoice_digest_response
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = NavClient(valid_credentials, use_test_api=True)
        client.session = mock_session

        result = client._execute_with_retry("/queryInvoiceDigest", b"<request/>")

        assert mock_session.post.call_count == 1

    @patch('nav_client.time.sleep')
    @patch('nav_client.requests.Session')
    def test_retry_on_timeout(self, mock_session_class, mock_sleep, valid_credentials, sample_invoice_digest_response):
        """Should retry on timeout errors."""
        import requests

        mock_session = MagicMock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = sample_invoice_digest_response

        # First call times out, second succeeds
        mock_session.post.side_effect = [
            requests.Timeout("Connection timed out"),
            mock_response
        ]
        mock_session_class.return_value = mock_session

        client = NavClient(valid_credentials, use_test_api=True)
        client.session = mock_session

        result = client._execute_with_retry("/queryInvoiceDigest", b"<request/>")

        assert mock_session.post.call_count == 2
        mock_sleep.assert_called_once()

    @patch('nav_client.time.sleep')
    def test_max_retries_exceeded(self, mock_sleep, nav_client):
        """Should raise after max retries exhausted."""
        import requests

        nav_client.session.post = Mock(side_effect=requests.Timeout("Timeout"))

        with pytest.raises(NavApiError) as exc_info:
            nav_client._execute_with_retry("/test", b"<request/>", max_retries=2)

        assert exc_info.value.code == "TIMEOUT"
        assert nav_client.session.post.call_count == 3  # Initial + 2 retries


# =============================================================================
# INTEGRATION TESTS (with mocked HTTP)
# =============================================================================

class TestQueryInvoices:
    """Test invoice query methods with mocked HTTP."""

    @patch.object(NavClient, '_execute_with_retry')
    def test_query_incoming_invoices(self, mock_execute, nav_client, sample_invoice_digest_response):
        """Test querying incoming invoices."""
        mock_execute.return_value = sample_invoice_digest_response

        invoices = nav_client.query_incoming_invoices(
            issue_date_from="2024-01-01",
            issue_date_to="2024-01-31"
        )

        assert len(invoices) == 2
        assert invoices[0]["invoiceNumber"] == "INV-2024-001"
        assert invoices[1]["invoiceNetAmount"] == 200000.0

        # Verify endpoint called
        mock_execute.assert_called()
        call_args = mock_execute.call_args
        assert "/queryInvoiceDigest" in call_args[0]

    @patch.object(NavClient, '_execute_with_retry')
    def test_query_outgoing_invoices(self, mock_execute, nav_client, sample_invoice_digest_response):
        """Test querying outgoing invoices."""
        mock_execute.return_value = sample_invoice_digest_response

        invoices = nav_client.query_outgoing_invoices(
            issue_date_from="2024-01-01",
            issue_date_to="2024-01-31"
        )

        assert len(invoices) == 2

    @patch.object(NavClient, '_execute_with_retry')
    def test_test_connection_success(self, mock_execute, nav_client, sample_invoice_digest_response):
        """Test connection check."""
        mock_execute.return_value = sample_invoice_digest_response

        result = nav_client.test_connection()

        assert result is True


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
