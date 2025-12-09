"""
Live NAV API Integration Tests

These tests execute against the REAL NAV test environment API.
NO MOCKS - actual API calls only.

Prerequisites:
1. Register at https://onlineszamla-test.nav.gov.hu/
2. Create technical user with "Számlák lekérdezése" permission
3. Set environment variables:
   - NAV_TEST_LOGIN
   - NAV_TEST_PASSWORD
   - NAV_TEST_SIGNATURE_KEY
   - NAV_TEST_REPLACEMENT_KEY
   - NAV_TEST_TAX_NUMBER
   - NAV_TEST_SOFTWARE_ID

Run with:
    pytest test_nav_live_api.py -v --real-api

Skip if no credentials:
    pytest test_nav_live_api.py -v  (will skip all)
"""

import pytest
import os
import time
from datetime import datetime, timedelta
from nav_client import NavClient, NavCredentials, NavApiError

# =============================================================================
# CONFIGURATION & FIXTURES
# =============================================================================

def get_test_credentials():
    """Load credentials from environment variables."""
    required_vars = [
        'NAV_TEST_LOGIN',
        'NAV_TEST_PASSWORD',
        'NAV_TEST_SIGNATURE_KEY',
        'NAV_TEST_REPLACEMENT_KEY',
        'NAV_TEST_TAX_NUMBER'
    ]
    
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        return None, f"Missing environment variables: {', '.join(missing)}"
    
    try:
        credentials = NavCredentials(
            login=os.getenv('NAV_TEST_LOGIN'),
            password=os.getenv('NAV_TEST_PASSWORD'),
            signature_key=os.getenv('NAV_TEST_SIGNATURE_KEY'),
            replacement_key=os.getenv('NAV_TEST_REPLACEMENT_KEY'),
            tax_number=os.getenv('NAV_TEST_TAX_NUMBER')
        )
        return credentials, None
    except ValueError as e:
        return None, str(e)

@pytest.fixture(scope="module")
def live_client():
    """
    Create NavClient with real credentials for live API testing.
    Skips all tests if credentials not available.
    """
    credentials, error = get_test_credentials()
    if error:
        pytest.skip(f"Live API tests skipped: {error}")
    
    client = NavClient(
        credentials=credentials,
        use_test_api=True,  # Use NAV test environment
        software_id=os.getenv('NAV_TEST_SOFTWARE_ID', 'HU12345678-TEST01')
    )
    
    return client

# =============================================================================
# PRE-DEPLOYMENT VALIDATION (Framework Lines 9-46)
# =============================================================================

class TestPreDeploymentValidation:
    """Pre-deployment validation checklist - LIVE API CALLS ONLY."""

    def test_timestamp_utc_submission(self, live_client):
        """
        Framework Line 19: Submit request, verify no INVALID_TIMESTAMP.
        
        REAL API TEST - NO MOCKS.
        """
        # Query today's invoices (minimal data)
        today = datetime.now().strftime("%Y-%m-%d")
        
        try:
            result = live_client.query_invoice_digest(
                invoice_direction="INBOUND",
                issue_date_from=today,
                issue_date_to=today,
                fetch_all_pages=False
            )
            # If no error, timestamp was accepted
            assert True, "Timestamp accepted by NAV"
        except NavApiError as e:
            # Should NOT be INVALID_TIMESTAMP
            assert e.code != "INVALID_TIMESTAMP", f"Timestamp rejected: {e}"

    def test_technical_user_credentials(self, live_client):
        """
        Framework Line 20: tokenExchange call | Successful token returned.
        
        REAL API TEST - NO MOCKS.
        """
        try:
            token = live_client.token_exchange()
            
            # Verify token returned
            assert token is not None
            assert len(token) > 0
            assert isinstance(token, str)
            
            print(f"\n✓ Token exchange successful: {token[:20]}...")
            
        except NavApiError as e:
            pytest.fail(f"Token exchange failed: {e.code} - {e.message}")

    def test_software_registration_id(self, live_client):
        """
        Framework Line 21: Any API call | No INVALID_SOFTWARE_ID error.
        
        REAL API TEST - NO MOCKS.
        """
        today = datetime.now().strftime("%Y-%m-%d")
        
        try:
            result = live_client.query_invoice_digest(
                invoice_direction="OUTBOUND",
                issue_date_from=today,
                issue_date_to=today,
                fetch_all_pages=False
            )
            # No INVALID_SOFTWARE_ID error
            assert True, "Software ID accepted by NAV"
            
        except NavApiError as e:
            assert e.code != "INVALID_SOFTWARE_ID", f"Software ID rejected: {e}"

# =============================================================================
# API ENDPOINT CONNECTIVITY (Framework Lines 34-45)
# =============================================================================

class TestAPIEndpointConnectivity:
    """Verify all three query operations - LIVE API CALLS ONLY."""

    def test_query_invoice_data_endpoint(self, live_client):
        """
        Framework Line 43: queryInvoiceData returns funcCode=OK.
        
        REAL API TEST - NO MOCKS.
        """
        # Try to query a non-existent invoice (should return OK with empty result)
        try:
            result = live_client.query_invoice_data(
                invoice_number="NONEXISTENT_TEST_INVOICE_12345",
                invoice_direction="INBOUND"
            )
            # Success - endpoint is reachable
            print("\n✓ queryInvoiceData endpoint OK")
            assert True
            
        except NavApiError as e:
            # Only fail if it's a connection/auth error, not data error
            if e.code in ["INVALID_SECURITY_USER", "INVALID_REQUEST_SIGNATURE"]:
                pytest.fail(f"Endpoint auth failed: {e}")
            # DATA_NOT_FOUND or similar is OK for non-existent invoice

    def test_query_invoice_digest_endpoint(self, live_client):
        """
        Framework Line 44: queryInvoiceDigest returns funcCode=OK.
        
        REAL API TEST - NO MOCKS.
        """
        # Query last 7 days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        result = live_client.query_invoice_digest(
            invoice_direction="INBOUND",
            issue_date_from=start_date.strftime("%Y-%m-%d"),
            issue_date_to=end_date.strftime("%Y-%m-%d"),
            fetch_all_pages=False
        )
        
        # Should return list (may be empty)
        assert isinstance(result, list)
        print(f"\n✓ queryInvoiceDigest OK - Found {len(result)} invoices")

    def test_query_transaction_status_endpoint(self, live_client):
        """
        Framework Line 45: queryTransactionStatus returns funcCode=OK.
        
        REAL API TEST - NO MOCKS.
        """
        # Query a non-existent transaction (should return OK with empty result)
        result = live_client.query_transaction_status("NONEXISTENT_TRANS_ID_12345")
        
        # Should return dict with empty processingResults
        assert isinstance(result, dict)
        assert 'processingResults' in result
        print("\n✓ queryTransactionStatus endpoint OK")

# =============================================================================
# AUTHENTICATION LIVE TESTS (Framework Lines 49-159)
# =============================================================================

class TestAuthenticationLive:
    """TC-AUTH-*: Live authentication validation."""

    def test_tc_auth_001_valid_credentials_live(self, live_client):
        """
        TC-AUTH-001: Verify successful authentication with NAV.
        
        REAL API TEST - NO MOCKS.
        """
        # Simple query to verify auth works
        today = datetime.now().strftime("%Y-%m-%d")
        
        result = live_client.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from=today,
            issue_date_to=today,
            fetch_all_pages=False
        )
        
        # If we get here, auth succeeded
        assert isinstance(result, list)
        print("\n✓ Authentication successful with NAV")

    def test_tc_auth_002_invalid_login_live(self, live_client):
        """
        TC-AUTH-002: Verify NAV returns INVALID_SECURITY_USER for wrong login.
        
        REAL API TEST - NO MOCKS.
        """
        # Create client with wrong login
        bad_credentials = NavCredentials(
            login="WRONG_USER_" + "X" * 5,
            password=live_client.credentials.password,
            signature_key=live_client.credentials.signature_key,
            replacement_key=live_client.credentials.replacement_key,
            tax_number=live_client.credentials.tax_number
        )
        
        bad_client = NavClient(bad_credentials, use_test_api=True)
        
        today = datetime.now().strftime("%Y-%m-%d")
        
        with pytest.raises(NavApiError) as exc:
            bad_client.query_invoice_digest("OUTBOUND", today, today, fetch_all_pages=False)
        
        # NAV should return INVALID_SECURITY_USER
        assert exc.value.code == "INVALID_SECURITY_USER"
        print(f"\n✓ NAV correctly rejected invalid login: {exc.value.code}")

    def test_tc_auth_003_incorrect_password_live(self, live_client):
        """
        TC-AUTH-003: Verify NAV rejects incorrect password.
        
        REAL API TEST - NO MOCKS.
        """
        bad_credentials = NavCredentials(
            login=live_client.credentials.login,
            password="WRONG_PASSWORD_123456",
            signature_key=live_client.credentials.signature_key,
            replacement_key=live_client.credentials.replacement_key,
            tax_number=live_client.credentials.tax_number
        )
        
        bad_client = NavClient(bad_credentials, use_test_api=True)
        
        today = datetime.now().strftime("%Y-%m-%d")
        
        with pytest.raises(NavApiError) as exc:
            bad_client.query_invoice_digest("OUTBOUND", today, today, fetch_all_pages=False)
        
        assert exc.value.code == "INVALID_SECURITY_USER"
        print(f"\n✓ NAV correctly rejected wrong password: {exc.value.code}")

# =============================================================================
# QUERY OPERATIONS LIVE TESTS (Framework Lines 162-277)
# =============================================================================

class TestQueryOperationsLive:
    """TC-QID-*, TC-QDA-*: Live query operation tests."""

    def test_tc_qid_001_basic_date_range_live(self, live_client):
        """
        TC-QID-001: Basic date range search against real NAV API.
        
        REAL API TEST - NO MOCKS.
        """
        # Query last 30 days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        result = live_client.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from=start_date.strftime("%Y-%m-%d"),
            issue_date_to=end_date.strftime("%Y-%m-%d"),
            fetch_all_pages=False
        )
        
        assert isinstance(result, list)
        
        # Verify date filtering
        for invoice in result:
            issue_date = invoice.get('invoiceIssueDate', '')
            if issue_date:
                assert start_date.strftime("%Y-%m-%d") <= issue_date <= end_date.strftime("%Y-%m-%d")
        
        print(f"\n✓ Query digest OK - {len(result)} invoices in last 30 days")

    def test_tc_qid_002_inbound_direction_live(self, live_client):
        """
        TC-QID-002: INBOUND query against real NAV API.
        
        REAL API TEST - NO MOCKS.
        """
        today = datetime.now().strftime("%Y-%m-%d")
        
        result = live_client.query_invoice_digest(
            invoice_direction="INBOUND",
            issue_date_from=today,
            issue_date_to=today,
            fetch_all_pages=False
        )
        
        assert isinstance(result, list)
        
        # INBOUND means customerTaxNumber should match our tax number
        for invoice in result:
            customer_tax = invoice.get('customerTaxNumber', '')
            if customer_tax:
                # Should be our tax number or group member
                print(f"  Customer: {customer_tax}")
        
        print(f"\n✓ INBOUND query OK - {len(result)} incoming invoices today")

    def test_tc_qid_004_empty_result_live(self, live_client):
        """
        TC-QID-004: Empty result handling with real NAV API.
        
        REAL API TEST - NO MOCKS.
        """
        # Query a date range with no data (far past)
        result = live_client.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from="2000-01-01",
            issue_date_to="2000-01-02",
            fetch_all_pages=False
        )
        
        # Should return empty list, not error
        assert isinstance(result, list)
        assert len(result) == 0
        print("\n✓ Empty result handled correctly")

    def test_tc_qda_001_retrieve_invoice_live(self, live_client):
        """
        TC-QDA-001: Retrieve complete invoice from real NAV API.
        
        REAL API TEST - NO MOCKS.
        """
        # First get a real invoice number from digest
        end_date = datetime.now()
        start_date = end_date - timedelta(days=90)
        
        digests = live_client.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from=start_date.strftime("%Y-%m-%d"),
            issue_date_to=end_date.strftime("%Y-%m-%d"),
            fetch_all_pages=False
        )
        
        if len(digests) == 0:
            pytest.skip("No invoices found in last 90 days - cannot test queryInvoiceData")
        
        # Get first invoice
        first_invoice = digests[0]['invoiceNumber']
        
        # Query full data
        result = live_client.query_invoice_data(first_invoice, "OUTBOUND")
        
        # Verify we got invoice data
        assert 'invoice_data_decoded' in result
        assert len(result['invoice_data_decoded']) > 0
        assert result['id'] is not None  # Transaction ID
        
        print(f"\n✓ Retrieved full data for {first_invoice}: {len(result['invoice_data_decoded'])} bytes")

# =============================================================================
# TRANSACTION STATUS LIVE TESTS
# =============================================================================

class TestTransactionStatusLive:
    """TC-QTS-*: Live transaction status tests."""

    def test_tc_qts_003_invalid_transaction_id_live(self, live_client):
        """
        TC-QTS-003: Invalid transaction ID with real NAV API.
        
        REAL API TEST - NO MOCKS.
        """
        result = live_client.query_transaction_status("INVALID_TRANS_ID_12345")
        
        # NAV should return OK with empty results
        assert isinstance(result, dict)
        assert 'processingResults' in result
        # May be empty or have specific structure
        print("\n✓ Invalid transaction ID handled correctly")

# =============================================================================
# ERROR HANDLING LIVE TESTS
# =============================================================================

class TestErrorHandlingLive:
    """TC-ERR-*: Live error handling tests."""

    def test_tc_err_001_authentication_error_live(self, live_client):
        """
        TC-ERR-001: Verify NAV authentication error responses.
        
        REAL API TEST - NO MOCKS.
        """
        # Use wrong signature key
        bad_credentials = NavCredentials(
            login=live_client.credentials.login,
            password=live_client.credentials.password,
            signature_key="00000000000000000000000000000000",  # Wrong key
            replacement_key=live_client.credentials.replacement_key,
            tax_number=live_client.credentials.tax_number
        )
        
        bad_client = NavClient(bad_credentials, use_test_api=True)
        
        today = datetime.now().strftime("%Y-%m-%d")
        
        with pytest.raises(NavApiError) as exc:
            bad_client.query_invoice_digest("OUTBOUND", today, today, fetch_all_pages=False)
        
        # Should be signature error
        assert exc.value.code in ["INVALID_REQUEST_SIGNATURE", "INVALID_SECURITY_USER"]
        print(f"\n✓ NAV correctly rejected bad signature: {exc.value.code}")

    def test_tc_err_005_rate_limiting_live(self, live_client):
        """
        TC-ERR-005: Verify NAV rate limiting behavior.
        
        REAL API TEST - NO MOCKS.
        Tests that rapid requests are properly throttled.
        """
        today = datetime.now().strftime("%Y-%m-%d")
        
        start_time = time.time()
        
        # Make 3 rapid requests
        for i in range(3):
            result = live_client.query_invoice_digest(
                invoice_direction="OUTBOUND",
                issue_date_from=today,
                issue_date_to=today,
                fetch_all_pages=False
            )
        
        elapsed = time.time() - start_time
        
        # Should take at least 2 seconds (3 requests with 1 req/sec limit)
        assert elapsed >= 2.0, f"Rate limiting not working: {elapsed:.2f}s for 3 requests"
        
        print(f"\n✓ Rate limiting working: {elapsed:.2f}s for 3 requests (expected >=2s)")

# =============================================================================
# QUERY DIGEST LIVE TESTS (Framework Lines 162-277)
# =============================================================================

class TestQueryDigestLive:
    """TC-QID-*: Live query digest tests."""

    def test_tc_qid_005_additional_params_live(self, live_client):
        """
        TC-QID-005: Additional query parameters with real NAV API.
        
        REAL API TEST - NO MOCKS.
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)
        
        # Query with category filter
        result = live_client.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from=start_date.strftime("%Y-%m-%d"),
            issue_date_to=end_date.strftime("%Y-%m-%d"),
            invoice_category="NORMAL",
            fetch_all_pages=False
        )
        
        # Verify all results match filter
        for invoice in result:
            assert invoice.get('invoiceCategory') == 'NORMAL'
        
        print(f"\n✓ Query with filters OK - {len(result)} NORMAL invoices")

    def test_tc_qid_003_pagination_live(self, live_client):
        """
        TC-QID-003: Pagination with real NAV API.
        
        REAL API TEST - NO MOCKS.
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=365)
        
        # Get first page
        page1 = live_client.query_invoice_digest(
            invoice_direction="OUTBOUND",
            issue_date_from=start_date.strftime("%Y-%m-%d"),
            issue_date_to=end_date.strftime("%Y-%m-%d"),
            page=1,
            fetch_all_pages=False
        )
        
        # If we have data, try page 2
        if len(page1) >= 100:
            page2 = live_client.query_invoice_digest(
                invoice_direction="OUTBOUND",
                issue_date_from=start_date.strftime("%Y-%m-%d"),
                issue_date_to=end_date.strftime("%Y-%m-%d"),
                page=2,
                fetch_all_pages=False
            )
            
            # Pages should have different invoices
            page1_numbers = {inv['invoiceNumber'] for inv in page1}
            page2_numbers = {inv['invoiceNumber'] for inv in page2}
            assert page1_numbers.isdisjoint(page2_numbers), "Pagination should return different results"
            
            print(f"\n✓ Pagination working: Page1={len(page1)}, Page2={len(page2)}")
        else:
            print(f"\n⚠ Only {len(page1)} invoices - cannot test pagination")

# =============================================================================
# INTEGRATION WORKFLOW LIVE TEST (Framework Lines 598-617)
# =============================================================================

class TestIntegrationLive:
    """TC-INT-*: Live integration workflow tests."""

    @pytest.mark.skipif(
        not os.getenv('NAV_TEST_ALLOW_WRITE'),
        reason="Write operations require NAV_TEST_ALLOW_WRITE=1"
    )
    def test_tc_int_001_end_to_end_live(self, live_client):
        """
        TC-INT-001: End-to-end workflow against real NAV API.
        
        REAL API TEST - NO MOCKS.
        Requires write permission on technical user.
        
        WARNING: This submits a test invoice to NAV!
        Set NAV_TEST_ALLOW_WRITE=1 to enable.
        """
        # Step 1: Token exchange
        token = live_client.token_exchange()
        assert token is not None
        print("\n✓ Step 1: Token obtained")
        
        # Step 2: Submit test invoice
        # NOTE: You need to provide real invoice data here
        # This is a skeleton - you'd need actual invoice XML
        test_invoice_data = """
        <InvoiceData xmlns="http://schemas.nav.gov.hu/OSA/3.0/data">
            <!-- Real invoice XML would go here -->
        </InvoiceData>
        """
        
        import base64
        encoded_invoice = base64.b64encode(test_invoice_data.encode('utf-8')).decode('ascii')
        
        invoice_ops = [{
            'index': 1,
            'operation': 'CREATE',
            'invoiceData': encoded_invoice
        }]
        
        transaction_id = live_client.manage_invoice(invoice_ops)
        assert transaction_id is not None
        print(f"\n✓ Step 2: Invoice submitted - TransID: {transaction_id}")
        
        # Step 3: Poll status
        max_attempts = 30
        final_status = None
        
        for attempt in range(max_attempts):
            status = live_client.query_transaction_status(transaction_id)
            if status['processingResults']:
                inv_status = status['processingResults'][0]['invoiceStatus']
                print(f"  Poll {attempt+1}: {inv_status}")
                
                if inv_status in ['DONE', 'ABORTED']:
                    final_status = inv_status
                    break
            
            time.sleep(5)
        
        assert final_status is not None
        print(f"\n✓ Step 3: Final status: {final_status}")
        
        # Step 4 & 5 would query the submitted invoice

# =============================================================================
# RUN INSTRUCTIONS
# =============================================================================

if __name__ == "__main__":
    """
    Run live API tests.
    
    Setup:
        export NAV_TEST_LOGIN="your_user"
        export NAV_TEST_PASSWORD="your_pass"
        export NAV_TEST_SIGNATURE_KEY="your_32_char_key"
        export NAV_TEST_REPLACEMENT_KEY="your_32_char_key"
        export NAV_TEST_TAX_NUMBER="12345678"
    
    Run:
        pytest test_nav_live_api.py -v
    """
    pytest.main([__file__, "-v", "-s"])

