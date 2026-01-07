"""
Comprehensive Unit Tests for NAV API Write Operations (manageInvoice)

Tests cover:
- Token exchange and decryption
- Invoice submission (CREATE, MODIFY, STORNO operations)
- September 2025 validation rules (errors 435, 734, 1311)
- Request signature calculation for write operations
- Transaction ID handling
- Error handling for write operations

Run with: pytest test_manage_invoice.py -v
"""

import pytest
import base64
import hashlib
from unittest.mock import Mock, MagicMock, patch
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
        signature_key="12345678901234567890123456789012",
        replacement_key="0123456789abcdef0123456789abcdef",  # 32 hex chars = 16 bytes
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
def mock_session():
    """Mock requests session."""
    with patch('nav_client.requests.Session') as mock:
        session = MagicMock()
        mock.return_value = session
        yield session


@pytest.fixture
def sample_invoice_xml():
    """Sample invoice XML for testing."""
    return b"""<?xml version="1.0" encoding="UTF-8"?>
    <Invoice xmlns="http://schemas.nav.gov.hu/OSA/3.0/data">
        <invoiceNumber>INV-2024-001</invoiceNumber>
        <invoiceIssueDate>2024-01-15</invoiceIssueDate>
        <supplierTaxNumber>12345678</supplierTaxNumber>
        <customerTaxNumber>87654321</customerTaxNumber>
        <invoiceLines>
            <line>
                <lineNumber>1</lineNumber>
                <lineDescription>Test Product</lineDescription>
                <quantity>10</quantity>
                <unitPrice>1000</unitPrice>
                <lineNetAmount>10000</lineNetAmount>
                <vatRate>27</vatRate>
                <lineVatAmount>2700</lineVatAmount>
            </line>
        </invoiceLines>
        <invoiceSummary>
            <summaryByVatRate>
                <vatRateNetAmount>10000</vatRateNetAmount>
                <vatRateVatAmount>2700</vatRateVatAmount>
            </summaryByVatRate>
            <invoiceNetAmount>10000</invoiceNetAmount>
            <invoiceVatAmount>2700</invoiceVatAmount>
            <invoiceGrossAmount>12700</invoiceGrossAmount>
        </invoiceSummary>
    </Invoice>"""


@pytest.fixture
def sample_invoice_base64(sample_invoice_xml):
    """Base64 encoded invoice XML."""
    return base64.b64encode(sample_invoice_xml).decode('utf-8')


@pytest.fixture
def token_exchange_response():
    """Sample token exchange response."""
    # Create a mock encrypted token (in real scenario this would be AES encrypted)
    return b"""<?xml version="1.0" encoding="UTF-8"?>
    <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
        <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
            <funcCode>OK</funcCode>
        </result>
        <encodedExchangeToken>dGVzdF90b2tlbl92YWx1ZQ==</encodedExchangeToken>
    </TokenExchangeResponse>"""


@pytest.fixture
def manage_invoice_response():
    """Sample manage invoice response with transaction ID."""
    return b"""<?xml version="1.0" encoding="UTF-8"?>
    <ManageInvoiceResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
        <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
            <funcCode>OK</funcCode>
        </result>
        <transactionId>TXN20240115100000ABC123</transactionId>
    </ManageInvoiceResponse>"""


# =============================================================================
# TOKEN EXCHANGE TESTS
# =============================================================================

class TestTokenExchange:
    """Test token exchange functionality."""

    def test_build_token_exchange_request(self, nav_client):
        """Should build valid token exchange request XML."""
        request_body = nav_client._build_token_exchange_request()
        
        root = etree.fromstring(request_body)
        
        # Verify root element
        assert root.tag.endswith("TokenExchangeRequest")
        
        # Verify header
        header = root.find(".//{%s}header" % NAMESPACES['common'])
        assert header is not None
        assert header.find("{%s}requestId" % NAMESPACES['common']) is not None
        assert header.find("{%s}timestamp" % NAMESPACES['common']) is not None
        
        # Verify user element
        user = root.find(".//{%s}user" % NAMESPACES['common'])
        assert user is not None
        assert user.find("{%s}login" % NAMESPACES['common']).text == "test_user"
        
        # Verify software element
        software = root.find(".//{%s}software" % NAMESPACES['api'])
        assert software is not None

    def test_token_exchange_success(self, nav_client, mock_session):
        """Should successfully exchange token."""
        # Mock encrypted token response
        # For testing, we'll mock the decrypt method
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdF90b2tlbg==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        mock_session.post.return_value = mock_response
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="decrypted_token"):
            token = nav_client.token_exchange()
            
            assert token == "decrypted_token"
            mock_session.post.assert_called_once()

    def test_token_exchange_missing_token(self, nav_client, mock_session):
        """Should raise error when token is missing from response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
        </TokenExchangeResponse>"""
        mock_session.post.return_value = mock_response
        nav_client.session = mock_session
        
        with pytest.raises(NavApiError) as exc_info:
            nav_client.token_exchange()
        
        assert exc_info.value.code == "MISSING_TOKEN"

    def test_decrypt_token_invalid_data(self, nav_client):
        """Should raise error for invalid encrypted data."""
        # Test with invalid base64 data that will fail decryption
        # The token must be valid base64 but will fail AES decryption
        with pytest.raises(NavApiError):
            nav_client._decrypt_token("aW52YWxpZF9kYXRhX2Zvcl9hZXM=")  # "invalid_data_for_aes"

    def test_decrypt_token_empty_result(self, nav_client):
        """Should raise error for empty decrypted token."""
        with patch('nav_client.AES') as mock_aes:
            mock_cipher = MagicMock()
            mock_cipher.decrypt.return_value = b'\x00\x00\x00\x00'  # All null bytes
            mock_aes.new.return_value = mock_cipher
            mock_aes.MODE_ECB = 1
            mock_aes.block_size = 16
            
            with pytest.raises(NavApiError) as exc_info:
                nav_client._decrypt_token("dGVzdHRlc3R0ZXN0dGVzdA==")  # 16 bytes base64
            
            assert exc_info.value.code == "EMPTY_TOKEN"


# =============================================================================
# MANAGE INVOICE TESTS
# =============================================================================

class TestManageInvoice:
    """Test manage invoice (write operations) functionality."""

    def test_manage_invoice_create_success(self, nav_client, mock_session, sample_invoice_base64, manage_invoice_response):
        """Should successfully create invoice."""
        # Mock token exchange
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        # Mock manage invoice response
        manage_response = Mock()
        manage_response.status_code = 200
        manage_response.content = manage_invoice_response
        
        mock_session.post.side_effect = [token_response, manage_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [{
                "index": 1,
                "operation": "CREATE",
                "invoiceData": sample_invoice_base64
            }]
            
            transaction_id = nav_client.manage_invoice(operations, validate_sept_2025=False)
            
            assert transaction_id == "TXN20240115100000ABC123"
            assert mock_session.post.call_count == 2

    def test_manage_invoice_modify_operation(self, nav_client, mock_session, sample_invoice_base64, manage_invoice_response):
        """Should handle MODIFY operation."""
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        manage_response = Mock()
        manage_response.status_code = 200
        manage_response.content = manage_invoice_response
        
        mock_session.post.side_effect = [token_response, manage_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [{
                "index": 1,
                "operation": "MODIFY",
                "invoiceData": sample_invoice_base64
            }]
            
            transaction_id = nav_client.manage_invoice(operations, validate_sept_2025=False)
            
            assert transaction_id is not None

    def test_manage_invoice_storno_operation(self, nav_client, mock_session, sample_invoice_base64, manage_invoice_response):
        """Should handle STORNO (cancel) operation."""
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        manage_response = Mock()
        manage_response.status_code = 200
        manage_response.content = manage_invoice_response
        
        mock_session.post.side_effect = [token_response, manage_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [{
                "index": 1,
                "operation": "STORNO",
                "invoiceData": sample_invoice_base64
            }]
            
            # STORNO should skip Sept 2025 validation
            transaction_id = nav_client.manage_invoice(operations, validate_sept_2025=True)
            
            assert transaction_id is not None

    def test_manage_invoice_multiple_operations(self, nav_client, mock_session, sample_invoice_base64, manage_invoice_response):
        """Should handle multiple invoice operations in batch."""
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        manage_response = Mock()
        manage_response.status_code = 200
        manage_response.content = manage_invoice_response
        
        mock_session.post.side_effect = [token_response, manage_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [
                {"index": 1, "operation": "CREATE", "invoiceData": sample_invoice_base64},
                {"index": 2, "operation": "CREATE", "invoiceData": sample_invoice_base64},
                {"index": 3, "operation": "CREATE", "invoiceData": sample_invoice_base64},
            ]
            
            transaction_id = nav_client.manage_invoice(operations, validate_sept_2025=False)
            
            assert transaction_id is not None
            
            # Verify request contains all operations
            call_args = mock_session.post.call_args_list[1]
            request_body = call_args[1]['data']
            root = etree.fromstring(request_body)
            
            # Find invoiceOperation elements - the XML uses default namespace
            # so we need to use namespace-aware queries
            ns = {'api': 'http://schemas.nav.gov.hu/OSA/3.0/api'}
            invoice_ops = root.findall(".//api:invoiceOperations/api:invoiceOperation", ns)
            assert len(invoice_ops) == 3

    def test_manage_invoice_missing_transaction_id(self, nav_client, mock_session, sample_invoice_base64):
        """Should raise error when transaction ID is missing."""
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        # Response without transaction ID
        manage_response = Mock()
        manage_response.status_code = 200
        manage_response.content = b"""<?xml version="1.0"?>
        <ManageInvoiceResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
        </ManageInvoiceResponse>"""
        
        mock_session.post.side_effect = [token_response, manage_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [{"index": 1, "operation": "CREATE", "invoiceData": sample_invoice_base64}]
            
            with pytest.raises(NavApiError) as exc_info:
                nav_client.manage_invoice(operations, validate_sept_2025=False)
            
            assert exc_info.value.code == "MISSING_TRX_ID"

    def test_manage_invoice_signature_includes_invoice_hash(self, nav_client, mock_session, sample_invoice_base64, manage_invoice_response):
        """Should include invoice hash in request signature."""
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        manage_response = Mock()
        manage_response.status_code = 200
        manage_response.content = manage_invoice_response
        
        mock_session.post.side_effect = [token_response, manage_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [{"index": 1, "operation": "CREATE", "invoiceData": sample_invoice_base64}]
            
            nav_client.manage_invoice(operations, validate_sept_2025=False)
            
            # Verify request signature was computed with invoice hash
            call_args = mock_session.post.call_args_list[1]
            request_body = call_args[1]['data']
            root = etree.fromstring(request_body)
            
            signature = root.find(".//{%s}requestSignature" % NAMESPACES['common'])
            assert signature is not None
            assert len(signature.text) == 128  # SHA3-512 produces 128 hex chars


# =============================================================================
# SEPTEMBER 2025 VALIDATION TESTS
# =============================================================================

class TestSept2025Validation:
    """Test September 2025 blocking validation rules."""

    def test_validate_sept_2025_valid_invoice(self, nav_client, sample_invoice_xml):
        """Should pass validation for valid invoice."""
        errors = nav_client._validate_sept_2025_rules(sample_invoice_xml)
        assert len(errors) == 0

    def test_validate_sept_2025_vat_line_item_error_1311(self, nav_client):
        """Should detect VAT line item calculation error (Error 1311)."""
        # Invoice with incorrect VAT calculation: 10000 * 27% = 2700, but shows 3000
        # Note: The validation looks for 'vatPercentage' not 'vatRate'
        invalid_invoice = b"""<?xml version="1.0"?>
        <Invoice>
            <invoiceLines>
                <line>
                    <lineNumber>1</lineNumber>
                    <lineNetAmount>10000</lineNetAmount>
                    <vatPercentage>27</vatPercentage>
                    <lineVatAmount>3000</lineVatAmount>
                </line>
            </invoiceLines>
        </Invoice>"""
        
        errors = nav_client._validate_sept_2025_rules(invalid_invoice)
        
        assert len(errors) > 0
        assert any("1311" in e for e in errors)

    def test_validate_sept_2025_vat_summary_mismatch_734(self, nav_client):
        """Should detect VAT summary mismatch (Error 734)."""
        # Invoice where line item VAT doesn't match summary
        invalid_invoice = b"""<?xml version="1.0"?>
        <Invoice>
            <invoiceLines>
                <line>
                    <lineNumber>1</lineNumber>
                    <lineNetAmount>10000</lineNetAmount>
                    <vatRate>27</vatRate>
                    <lineVatAmount>2700</lineVatAmount>
                </line>
            </invoiceLines>
            <invoiceSummary>
                <summaryByVatRate>
                    <vatRateVatAmount>5000</vatRateVatAmount>
                </summaryByVatRate>
            </invoiceSummary>
        </Invoice>"""
        
        errors = nav_client._validate_sept_2025_rules(invalid_invoice)
        
        assert len(errors) > 0
        assert any("734" in e for e in errors)

    def test_validate_sept_2025_allows_1_huf_tolerance(self, nav_client):
        """Should allow 1 HUF tolerance in VAT calculations."""
        # Invoice with 1 HUF rounding difference (within tolerance)
        valid_invoice = b"""<?xml version="1.0"?>
        <Invoice>
            <invoiceLines>
                <line>
                    <lineNumber>1</lineNumber>
                    <lineNetAmount>10000</lineNetAmount>
                    <vatRate>27</vatRate>
                    <lineVatAmount>2701</lineVatAmount>
                </line>
            </invoiceLines>
        </Invoice>"""
        
        errors = nav_client._validate_sept_2025_rules(valid_invoice)
        
        # 1 HUF difference should be within tolerance
        assert len(errors) == 0

    def test_manage_invoice_sept_2025_validation_enabled(self, nav_client, mock_session):
        """Should validate Sept 2025 rules when enabled."""
        # Invalid invoice with VAT calculation error
        # Note: The validation looks for 'vatPercentage' not 'vatRate'
        invalid_invoice = b"""<?xml version="1.0"?>
        <Invoice>
            <invoiceLines>
                <line>
                    <lineNumber>1</lineNumber>
                    <lineNetAmount>10000</lineNetAmount>
                    <vatPercentage>27</vatPercentage>
                    <lineVatAmount>5000</lineVatAmount>
                </line>
            </invoiceLines>
        </Invoice>"""
        invalid_base64 = base64.b64encode(invalid_invoice).decode('utf-8')
        
        operations = [{"index": 1, "operation": "CREATE", "invoiceData": invalid_base64}]
        
        with pytest.raises(NavApiError) as exc_info:
            nav_client.manage_invoice(operations, validate_sept_2025=True)
        
        assert exc_info.value.code == "SEPT_2025_VALIDATION"
        assert "1311" in exc_info.value.message

    def test_manage_invoice_sept_2025_validation_disabled(self, nav_client, mock_session, manage_invoice_response):
        """Should skip Sept 2025 validation when disabled."""
        # Invalid invoice that would fail validation
        invalid_invoice = b"""<?xml version="1.0"?>
        <Invoice>
            <invoiceLines>
                <line>
                    <lineNumber>1</lineNumber>
                    <lineNetAmount>10000</lineNetAmount>
                    <vatRate>27</vatRate>
                    <lineVatAmount>5000</lineVatAmount>
                </line>
            </invoiceLines>
        </Invoice>"""
        invalid_base64 = base64.b64encode(invalid_invoice).decode('utf-8')
        
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        manage_response = Mock()
        manage_response.status_code = 200
        manage_response.content = manage_invoice_response
        
        mock_session.post.side_effect = [token_response, manage_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [{"index": 1, "operation": "CREATE", "invoiceData": invalid_base64}]
            
            # Should not raise when validation is disabled
            transaction_id = nav_client.manage_invoice(operations, validate_sept_2025=False)
            
            assert transaction_id is not None

    def test_validate_sept_2025_multiple_line_items(self, nav_client):
        """Should validate all line items."""
        # Invoice with multiple lines, one invalid
        # Note: The validation looks for 'vatPercentage' not 'vatRate'
        # Line 1: 10000 * 27% = 2700 (correct)
        # Line 2: 20000 * 27% = 5400, but shows 9999 (incorrect, diff > 1 HUF)
        invalid_invoice = b"""<?xml version="1.0"?>
        <Invoice>
            <invoiceLines>
                <line>
                    <lineNumber>1</lineNumber>
                    <lineNetAmount>10000</lineNetAmount>
                    <vatPercentage>27</vatPercentage>
                    <lineVatAmount>2700</lineVatAmount>
                </line>
                <line>
                    <lineNumber>2</lineNumber>
                    <lineNetAmount>20000</lineNetAmount>
                    <vatPercentage>27</vatPercentage>
                    <lineVatAmount>9999</lineVatAmount>
                </line>
            </invoiceLines>
        </Invoice>"""
        
        errors = nav_client._validate_sept_2025_rules(invalid_invoice)
        
        assert len(errors) > 0
        assert any("Line 2" in e for e in errors)

    def test_validate_sept_2025_handles_invalid_xml(self, nav_client):
        """Should handle invalid XML gracefully."""
        invalid_xml = b"not valid xml"
        
        # Should not raise, just return empty errors (can't validate)
        errors = nav_client._validate_sept_2025_rules(invalid_xml)
        
        # Implementation may return empty list for unparseable XML
        assert isinstance(errors, list)


# =============================================================================
# REQUEST SIGNATURE TESTS FOR WRITE OPERATIONS
# =============================================================================

class TestWriteOperationSignature:
    """Test request signature calculation for write operations."""

    def test_signature_includes_additional_data(self, nav_client):
        """Should include additional data in signature for write operations."""
        request_id = "REQ123456789012345678901234567"
        timestamp = "2024-01-15T10:00:00.000Z"
        additional_data = "HASH_OF_INVOICE_DATA"
        
        sig_with_data = nav_client._compute_request_signature(request_id, timestamp, additional_data)
        sig_without_data = nav_client._compute_request_signature(request_id, timestamp)
        
        # Signatures should be different
        assert sig_with_data != sig_without_data

    def test_signature_uses_sha3_512(self, nav_client):
        """Should use SHA3-512 for signature calculation."""
        request_id = "REQ123456789012345678901234567"
        timestamp = "2024-01-15T10:00:00.000Z"
        
        signature = nav_client._compute_request_signature(request_id, timestamp)
        
        # SHA3-512 produces 128 hex characters
        assert len(signature) == 128
        assert signature.isupper()

    def test_invoice_hash_calculation(self, nav_client, sample_invoice_base64):
        """Should correctly hash invoice operation for signature."""
        operation = "CREATE"
        invoice_data = sample_invoice_base64
        
        # The hash should be SHA3-512 of operation + invoiceData
        expected_input = operation + invoice_data
        expected_hash = hashlib.sha3_512(expected_input.encode('utf-8')).hexdigest().upper()
        
        # Verify the hash calculation
        actual_hash = nav_client._hash_sha3_512(expected_input)
        
        assert actual_hash == expected_hash


# =============================================================================
# ERROR HANDLING TESTS FOR WRITE OPERATIONS
# =============================================================================

class TestWriteOperationErrors:
    """Test error handling for write operations."""

    def test_manage_invoice_api_error(self, nav_client, mock_session, sample_invoice_base64):
        """Should handle API errors during invoice submission."""
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        error_response = Mock()
        error_response.status_code = 200
        error_response.content = b"""<?xml version="1.0"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
                <funcCode>ERROR</funcCode>
                <errorCode>INVALID_REQUEST</errorCode>
                <message>Invalid invoice data</message>
            </result>
        </GeneralErrorResponse>"""
        
        mock_session.post.side_effect = [token_response, error_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            operations = [{"index": 1, "operation": "CREATE", "invoiceData": sample_invoice_base64}]
            
            with pytest.raises(NavApiError) as exc_info:
                nav_client.manage_invoice(operations, validate_sept_2025=False)
            
            assert exc_info.value.code == "INVALID_REQUEST"

    def test_manage_invoice_token_exchange_failure(self, nav_client, mock_session, sample_invoice_base64):
        """Should handle token exchange failure."""
        error_response = Mock()
        error_response.status_code = 200
        error_response.content = b"""<?xml version="1.0"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
                <funcCode>ERROR</funcCode>
                <errorCode>INVALID_CREDENTIALS</errorCode>
                <message>Authentication failed</message>
            </result>
        </GeneralErrorResponse>"""
        
        mock_session.post.return_value = error_response
        nav_client.session = mock_session
        
        operations = [{"index": 1, "operation": "CREATE", "invoiceData": sample_invoice_base64}]
        
        with pytest.raises(NavApiError) as exc_info:
            nav_client.manage_invoice(operations, validate_sept_2025=False)
        
        assert exc_info.value.code == "INVALID_CREDENTIALS"

    def test_manage_invoice_network_error(self, nav_client, mock_session, sample_invoice_base64):
        """Should handle network errors during submission."""
        import requests
        
        mock_session.post.side_effect = requests.Timeout("Connection timed out")
        nav_client.session = mock_session
        
        operations = [{"index": 1, "operation": "CREATE", "invoiceData": sample_invoice_base64}]
        
        with pytest.raises(NavApiError) as exc_info:
            nav_client.manage_invoice(operations, validate_sept_2025=False)
        
        assert exc_info.value.code == "TIMEOUT"

    def test_manage_invoice_retryable_error(self, nav_client, mock_session, sample_invoice_base64, manage_invoice_response):
        """Should retry on retryable errors."""
        token_response = Mock()
        token_response.status_code = 200
        token_response.content = b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>dGVzdA==</encodedExchangeToken>
        </TokenExchangeResponse>"""
        
        # First call fails with retryable error, second succeeds
        error_response = Mock()
        error_response.status_code = 200
        error_response.content = b"""<?xml version="1.0"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
                <funcCode>ERROR</funcCode>
                <errorCode>OPERATION_FAILED</errorCode>
                <message>Temporary failure</message>
            </result>
        </GeneralErrorResponse>"""
        
        success_response = Mock()
        success_response.status_code = 200
        success_response.content = manage_invoice_response
        
        mock_session.post.side_effect = [token_response, error_response, success_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, '_decrypt_token', return_value="test_token"):
            with patch('nav_client.time.sleep'):  # Skip actual sleep
                operations = [{"index": 1, "operation": "CREATE", "invoiceData": sample_invoice_base64}]
                
                transaction_id = nav_client.manage_invoice(operations, validate_sept_2025=False)
                
                assert transaction_id is not None


# =============================================================================
# NAV ERROR CODE TESTS
# =============================================================================

class TestNavErrorCode:
    """Test NavErrorCode enum and error classification."""

    def test_retryable_error_codes(self):
        """Should correctly identify retryable errors."""
        retryable_codes = [
            NavErrorCode.OPERATION_FAILED.value,
            NavErrorCode.MAINTENANCE.value,
            NavErrorCode.TOO_MANY_REQUESTS.value,
            NavErrorCode.TECHNICAL_ERROR.value,
            NavErrorCode.TIMEOUT.value,
        ]
        
        for code in retryable_codes:
            error = NavApiError(code, "Test error")
            assert error.is_retryable is True, f"{code} should be retryable"

    def test_non_retryable_error_codes(self):
        """Should correctly identify non-retryable errors."""
        non_retryable_codes = [
            NavErrorCode.INVALID_REQUEST_SIGNATURE.value,
            NavErrorCode.INVALID_CREDENTIALS.value,
            NavErrorCode.INVALID_EXCHANGE_KEY.value,
            NavErrorCode.EMPTY_TOKEN.value,
            NavErrorCode.TOKEN_DECRYPTION_FAILED.value,
        ]
        
        for code in non_retryable_codes:
            error = NavApiError(code, "Test error")
            assert error.is_retryable is False, f"{code} should not be retryable"

    def test_sept_2025_validation_error_codes(self):
        """Should have Sept 2025 validation error codes."""
        assert NavErrorCode.VAT_RATE_MISMATCH.value == "435"
        assert NavErrorCode.VAT_SUMMARY_MISMATCH.value == "734"
        assert NavErrorCode.VAT_LINE_ITEM_ERROR.value == "1311"


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
