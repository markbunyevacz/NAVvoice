"""
Advanced Tests for NAV Online Számla API Implementation
Covers token exchange, integration workflows, and security tests.

Maps to sections: TC-INT, TC-SEC, Token Exchange
"""

import pytest
import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, MagicMock, patch
from lxml import etree

from nav_client import (
    NavClient,
    NavCredentials,
    NavApiError,
    NAMESPACES
)

# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def valid_credentials():
    return NavCredentials(
        login="test_user",
        password="test_password_123",
        signature_key="12345678901234567890123456789012",
        replacement_key="abcdefghijklmnopqrstuvwxyz123456",
        tax_number="12345678"
    )

@pytest.fixture
def nav_client(valid_credentials):
    return NavClient(
        credentials=valid_credentials,
        use_test_api=True,
        software_id="HUTEST12345-0001"
    )

@pytest.fixture
def mock_session():
    with patch('nav_client.requests.Session') as mock:
        session = MagicMock()
        mock.return_value = session
        yield session

# =============================================================================
# TOKEN EXCHANGE TESTS
# =============================================================================

class TestTokenExchange:
    """Token exchange and AES-128-ECB decryption tests."""

    def test_token_exchange_success(self, nav_client, mock_session):
        """Test successful token exchange and decryption."""
        # Simulate encrypted token response
        encrypted_token = "U29tZUVuY3J5cHRlZFRva2Vu"  # Base64 encoded
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = f"""<?xml version="1.0" encoding="UTF-8"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
                <funcCode>OK</funcCode>
            </result>
            <encodedExchangeToken>{encrypted_token}</encodedExchangeToken>
        </TokenExchangeResponse>""".encode('utf-8')
        mock_session.post.return_value = mock_response
        nav_client.session = mock_session

        # Mock the decryption to return a known value
        with patch.object(nav_client, '_decrypt_token', return_value="DECRYPTED_SESSION_TOKEN"):
            token = nav_client.token_exchange()
            
            assert token == "DECRYPTED_SESSION_TOKEN"
            assert mock_session.post.called
            
            # Verify request structure
            call_args = mock_session.post.call_args
            request_body = call_args[1]['data']
            root = etree.fromstring(request_body)
            assert root.tag.endswith("TokenExchangeRequest")

    def test_token_exchange_missing_token_error(self, nav_client, mock_session):
        """Test token exchange when server doesn't return token."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
                <funcCode>OK</funcCode>
            </result>
        </TokenExchangeResponse>"""
        mock_session.post.return_value = mock_response
        nav_client.session = mock_session

        with pytest.raises(NavApiError) as exc:
            nav_client.token_exchange()
        
        assert exc.value.code == "MISSING_TOKEN"

    def test_aes_decryption_invalid_key(self, nav_client):
        """Test AES decryption with malformed encrypted token."""
        # Test with invalid base64 token (can't be decrypted)
        with pytest.raises(NavApiError) as exc:
            nav_client._decrypt_token("!!!INVALID_BASE64!!!")
        
        assert exc.value.code == "TOKEN_DECRYPTION_FAILED"

    def test_token_exchange_request_structure(self, nav_client, mock_session):
        """Verify tokenExchange request has correct XML structure."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>TOKEN</encodedExchangeToken>
        </TokenExchangeResponse>"""
        mock_session.post.return_value = mock_response
        nav_client.session = mock_session

        with patch.object(nav_client, '_decrypt_token', return_value="TOKEN"):
            nav_client.token_exchange()
        
        # Verify endpoint
        call_args = mock_session.post.call_args
        assert "/tokenExchange" in call_args[0][0]
        
        # Verify request has user authentication
        request_body = call_args[1]['data']
        root = etree.fromstring(request_body)
        user = root.find(".//{%s}user" % NAMESPACES['common'])
        assert user is not None
        assert user.find("{%s}login" % NAMESPACES['common']).text == "test_user"

# =============================================================================
# INTEGRATION TESTS (TC-INT)
# =============================================================================

class TestIntegrationWorkflows:
    """TC-INT-*: End-to-end integration workflow tests."""

    def test_tc_int_001_end_to_end_invoice_submission(self, nav_client, mock_session):
        """
        TC-INT-001: End-to-end invoice submission workflow.
        
        Steps:
        1. tokenExchange → Obtain session token
        2. manageInvoice(CREATE) → Submit invoice, get transactionId
        3. queryTransactionStatus → Poll until DONE/ABORTED
        4. queryInvoiceData → Verify invoice stored correctly
        5. queryInvoiceDigest → Verify invoice appears in search
        """
        # Step 1: Token exchange response
        token_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <TokenExchangeResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <encodedExchangeToken>ENCRYPTED_TOKEN</encodedExchangeToken>
        </TokenExchangeResponse>""")
        
        # Step 2: manageInvoice response
        manage_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <ManageInvoiceResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <transactionId>TRANS_ABC123</transactionId>
        </ManageInvoiceResponse>""")
        
        # Step 3: queryTransactionStatus response (DONE)
        status_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <QueryTransactionStatusResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <processingResultList>
                <processingResult>
                    <index>1</index>
                    <invoiceStatus>DONE</invoiceStatus>
                </processingResult>
            </processingResultList>
        </QueryTransactionStatusResponse>""")
        
        # Step 4: queryInvoiceData response
        data_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <QueryInvoiceDataResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <invoiceDataResult>
                <invoiceData>PHRlc3Q+ZGF0YTwvdGVzdD4=</invoiceData>
                <auditData><id>TRANS_ABC123</id></auditData>
            </invoiceDataResult>
        </QueryInvoiceDataResponse>""")
        
        # Step 5: queryInvoiceDigest response
        digest_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <QueryInvoiceDigestResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <invoiceDigestResult>
                <invoiceDigest>
                    <invoiceNumber>INV-2024-001</invoiceNumber>
                    <supplierName>Test Supplier</supplierName>
                </invoiceDigest>
            </invoiceDigestResult>
        </QueryInvoiceDigestResponse>""")
        
        # manage_invoice calls token_exchange internally, so we need 2 token responses
        mock_session.post.side_effect = [
            token_response,      # Step 1: explicit token_exchange()
            token_response,      # Step 2: token_exchange() inside manage_invoice()
            manage_response,     # Step 2: actual manageInvoice call
            status_response,     # Step 3
            data_response,       # Step 4
            digest_response      # Step 5
        ]
        nav_client.session = mock_session

        # Execute full workflow
        with patch.object(nav_client, '_decrypt_token', return_value="SESSION_TOKEN"), \
             patch('time.sleep'):  # Speed up test
            # Step 1: Get token explicitly
            token = nav_client.token_exchange()
            assert token == "SESSION_TOKEN"
            
            # Step 2: Submit invoice (will call token_exchange again internally)
            invoice_ops = [{
                'index': 1,
                'operation': 'CREATE',
                'invoiceData': 'BASE64_INVOICE_DATA_HERE'
            }]
            transaction_id = nav_client.manage_invoice(invoice_ops)
            assert transaction_id == "TRANS_ABC123"
            
            # Step 3: Check status
            status = nav_client.query_transaction_status(transaction_id)
            assert status['processingResults'][0]['invoiceStatus'] == 'DONE'
            
            # Step 4: Retrieve invoice data
            invoice_data = nav_client.query_invoice_data("INV-2024-001")
            assert invoice_data['id'] == "TRANS_ABC123"
            
            # Step 5: Verify in digest
            digests = nav_client.query_invoice_digest(
                "OUTBOUND", "2024-01-01", "2024-12-31"
            )
            assert len(digests) == 1
            assert digests[0]['invoiceNumber'] == "INV-2024-001"

    def test_tc_int_002_invoice_modification_workflow(self, nav_client, mock_session):
        """
        TC-INT-002: Invoice modification workflow.
        
        Tests MODIFY operation with original invoice reference.
        """
        # Original invoice submission
        create_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <ManageInvoiceResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <transactionId>TRANS_ORIG</transactionId>
        </ManageInvoiceResponse>""")
        
        # Modification submission
        modify_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <ManageInvoiceResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <transactionId>TRANS_MODIFY</transactionId>
        </ManageInvoiceResponse>""")
        
        mock_session.post.side_effect = [create_response, modify_response]
        nav_client.session = mock_session
        
        with patch.object(nav_client, 'token_exchange', return_value="TOKEN"):
            # Create original
            original_ops = [{'index': 1, 'operation': 'CREATE', 'invoiceData': 'ORIG_DATA'}]
            trans_id_1 = nav_client.manage_invoice(original_ops)
            assert trans_id_1 == "TRANS_ORIG"
            
            # Submit modification
            modify_ops = [{'index': 1, 'operation': 'MODIFY', 'invoiceData': 'MODIFIED_DATA'}]
            trans_id_2 = nav_client.manage_invoice(modify_ops)
            assert trans_id_2 == "TRANS_MODIFY"

    def test_tc_int_003_invoice_cancellation_storno(self, nav_client, mock_session):
        """
        TC-INT-003: Invoice cancellation (STORNO) workflow.
        
        Tests STORNO operation.
        """
        storno_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <ManageInvoiceResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <transactionId>TRANS_STORNO</transactionId>
        </ManageInvoiceResponse>""")
        
        mock_session.post.return_value = storno_response
        nav_client.session = mock_session
        
        with patch.object(nav_client, 'token_exchange', return_value="TOKEN"):
            storno_ops = [{'index': 1, 'operation': 'STORNO', 'invoiceData': 'STORNO_DATA'}]
            trans_id = nav_client.manage_invoice(storno_ops)
            assert trans_id == "TRANS_STORNO"

# =============================================================================
# SECURITY TESTS (TC-SEC)
# =============================================================================

class TestSecurity:
    """TC-SEC-*: Security validation tests."""

    def test_tc_sec_003_signature_tampering_detection(self, nav_client, mock_session):
        """
        TC-SEC-003: Signature tampering detection.
        
        Verifies that modifying request after signature causes rejection.
        """
        # Generate a valid request
        request_body = nav_client._build_query_invoice_digest_request(
            invoice_direction="OUTBOUND",
            issue_date_from="2024-01-01",
            issue_date_to="2024-01-31",
            page=1
        )
        
        # Parse and tamper with request (change page number)
        root = etree.fromstring(request_body)
        page_elem = root.find(".//{%s}page" % NAMESPACES['api'])
        original_page = int(page_elem.text)
        page_elem.text = str(original_page + 1)  # Tamper!
        
        # Rebuild XML with tampered content (signature won't match)
        tampered_body = etree.tostring(root, xml_declaration=True, encoding='UTF-8')
        
        # Mock NAV rejection due to invalid signature
        error_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
                <funcCode>ERROR</funcCode>
                <errorCode>INVALID_REQUEST_SIGNATURE</errorCode>
                <message>Request signature validation failed</message>
            </result>
        </GeneralErrorResponse>""")
        mock_session.post.return_value = error_response
        nav_client.session = mock_session
        
        # Attempt to send tampered request
        with pytest.raises(NavApiError) as exc:
            nav_client._execute_with_retry("/queryInvoiceDigest", tampered_body)
        
        assert exc.value.code == "INVALID_REQUEST_SIGNATURE"

    def test_tc_sec_004_request_id_replay_prevention(self, nav_client, mock_session):
        """
        TC-SEC-004: Request ID replay prevention.
        
        Verifies that reusing same requestId is rejected by NAV.
        """
        # First request succeeds
        success_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <QueryTransactionStatusResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
        </QueryTransactionStatusResponse>""")
        
        # Second request with same ID rejected
        duplicate_response = Mock(status_code=200, content=b"""<?xml version="1.0"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common">
                <funcCode>ERROR</funcCode>
                <errorCode>DUPLICATE_REQUEST</errorCode>
                <message>Request ID already used</message>
            </result>
        </GeneralErrorResponse>""")
        
        mock_session.post.side_effect = [success_response, duplicate_response]
        nav_client.session = mock_session
        
        # First call succeeds
        nav_client.query_transaction_status("TRANS_123")
        
        # Second call (conceptually with same requestId) fails
        # Note: NavClient generates new requestId each time, so this tests
        # the error handling for DUPLICATE_REQUEST
        with pytest.raises(NavApiError) as exc:
            nav_client.query_transaction_status("TRANS_123")
        
        assert exc.value.code == "DUPLICATE_REQUEST"

    def test_request_id_uniqueness(self, nav_client):
        """Verify that NavClient generates unique request IDs."""
        ids = [nav_client._generate_request_id() for _ in range(100)]
        
        # All IDs should be unique
        assert len(set(ids)) == 100
        
        # All IDs should be 30 characters
        assert all(len(id) == 30 for id in ids)
        
        # All IDs should be alphanumeric
        assert all(id.isalnum() for id in ids)

# =============================================================================
# RESPONSE METADATA TESTS
# =============================================================================

class TestResponseMetadata:
    """Test parsing of additional response metadata fields."""

    def test_electronic_invoice_hash_parsing(self, nav_client, mock_session):
        """Test that electronicInvoiceHash is correctly parsed from response."""
        encoded_data = "PHRlc3Q+ZGF0YTwvdGVzdD4="
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = f"""<?xml version="1.0" encoding="UTF-8"?>
        <QueryInvoiceDataResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <invoiceDataResult>
                <invoiceData>{encoded_data}</invoiceData>
                <auditData>
                    <insDate>2024-01-15T10:00:00Z</insDate>
                    <id>TRANS123</id>
                    <electronicInvoiceHash>ABC123DEF456789HASH</electronicInvoiceHash>
                </auditData>
            </invoiceDataResult>
        </QueryInvoiceDataResponse>""".encode('utf-8')
        mock_session.post.return_value = mock_response
        nav_client.session = mock_session

        result = nav_client.query_invoice_data("INV-001", "OUTBOUND")
        
        # Verify electronicInvoiceHash is present
        assert 'electronicInvoiceHash' in result
        assert result['electronicInvoiceHash'] == "ABC123DEF456789HASH"
        
        # Verify other audit data
        assert result['id'] == "TRANS123"
        assert result['insDate'] == "2024-01-15T10:00:00Z"

    def test_timestamp_format_in_signature(self, nav_client):
        """
        Verify timestamp format for signature calculation is YYYYMMDDHHmmss.
        
        Per NAV spec: timestamp separators must be removed for signature calculation.
        """
        timestamp = "2024-01-15T10:30:45.123Z"
        req_id = "REQ123456789012345678901234567"
        
        # Calculate signature
        sig = nav_client._compute_request_signature(req_id, timestamp)
        
        # Manually compute expected signature with clean timestamp
        ts_clean = "20240115103045"  # YYYYMMDDHHmmss
        expected_data = req_id + ts_clean + nav_client.credentials.signature_key
        expected_sig = hashlib.sha3_512(expected_data.encode('utf-8')).hexdigest().upper()
        
        # Verify match
        assert sig == expected_sig
        
        # Verify timestamp cleaning logic
        timestamp_stripped = timestamp.replace("-", "").replace("T", "").replace(":", "").replace(".", "").replace("Z", "")[:14]
        assert timestamp_stripped == ts_clean
        assert len(timestamp_stripped) == 14

    def test_compressed_content_indicator(self, nav_client, mock_session):
        """Test handling of compressed invoice data (GZIP)."""
        import gzip
        original_data = b"<test>invoice data</test>"
        compressed = gzip.compress(original_data)
        encoded = __import__('base64').b64encode(compressed).decode('ascii')
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = f"""<?xml version="1.0"?>
        <QueryInvoiceDataResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <result xmlns="http://schemas.nav.gov.hu/NTCA/1.0/common"><funcCode>OK</funcCode></result>
            <invoiceDataResult>
                <invoiceData>{encoded}</invoiceData>
                <compressedContentIndicator>true</compressedContentIndicator>
            </invoiceDataResult>
        </QueryInvoiceDataResponse>""".encode('utf-8')
        mock_session.post.return_value = mock_response
        nav_client.session = mock_session

        result = nav_client.query_invoice_data("INV-COMPRESSED")
        
        # Client should decode base64 (but not decompress automatically)
        # User code would need to check compressedContentIndicator and decompress
        assert 'invoice_data_decoded' in result

# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

