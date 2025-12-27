"""
Integration Tests for September 2025 NAV Validation Rules

Tests the new blocking validation rules that NAV will enforce starting Sept 2025:
- Warning 435: VAT rate doesn't match tax number status
- Warning 734: VAT summary calculation mismatch
- Warning 1311: VAT line item inconsistency

These warnings will become BLOCKING errors in September 2025.

Requirements:
    pip install pytest pytest-mock
"""

import pytest
from datetime import datetime
from typing import Dict, List, Any
from unittest.mock import Mock, patch, MagicMock
from lxml import etree

# Import the NAV client
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from nav_client import NavClient, NavCredentials, NavApiError, NavErrorCode


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def nav_credentials():
    """Valid NAV credentials for testing."""
    return NavCredentials(
        login="test_user",
        password="test_password",
        signature_key="12345678901234567890123456789012",
        replacement_key="ABCDEF0123456789ABCDEF0123456789",  # 32 hex chars
        tax_number="12345678"
    )


@pytest.fixture
def nav_client(nav_credentials):
    """NAV client instance for testing."""
    return NavClient(nav_credentials, use_test_api=True)


# =============================================================================
# SEPTEMBER 2025 VALIDATION TESTS
# =============================================================================

class TestSept2025Validation:
    """Test suite for September 2025 blocking validation rules."""

    def test_error_code_435_vat_rate_mismatch(self, nav_client):
        """
        Test Warning 435: VAT rate doesn't match tax number status.

        Scenario: Invoice has 27% VAT but vendor tax number indicates
        they should use 0% (e.g., foreign company, reverse charge).

        Expected: Starting Sept 2025, this will be BLOCKING.
        """
        # This test validates that the error code is recognized
        assert NavErrorCode.VAT_RATE_MISMATCH.value == "435"

        # Simulate NAV response with warning 435
        mock_response = b"""<?xml version="1.0" encoding="UTF-8"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <funcCode>ERROR</funcCode>
            <errorCode>435</errorCode>
            <message>VAT rate does not match tax number status</message>
        </GeneralErrorResponse>"""

        with patch.object(nav_client.session, 'post') as mock_post:
            mock_post.return_value = Mock(
                status_code=200,
                content=mock_response
            )

            # This should raise NavApiError with code 435
            with pytest.raises(NavApiError) as exc_info:
                nav_client.query_invoice_data("TEST-INV-001", "INBOUND")

            assert exc_info.value.code == "435"
            assert "VAT" in exc_info.value.message

    def test_error_code_734_vat_summary_mismatch(self, nav_client):
        """
        Test Warning 734: VAT summary calculation mismatch.

        Scenario: Sum of line item VAT amounts doesn't match
        the VAT summary section total.

        Expected: Starting Sept 2025, this will be BLOCKING.
        """
        assert NavErrorCode.VAT_SUMMARY_MISMATCH.value == "734"

        mock_response = b"""<?xml version="1.0" encoding="UTF-8"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <funcCode>ERROR</funcCode>
            <errorCode>734</errorCode>
            <message>VAT summary does not match line items</message>
        </GeneralErrorResponse>"""

        with patch.object(nav_client.session, 'post') as mock_post:
            mock_post.return_value = Mock(
                status_code=200,
                content=mock_response
            )

            with pytest.raises(NavApiError) as exc_info:
                nav_client.query_invoice_data("TEST-INV-002", "INBOUND")

            assert exc_info.value.code == "734"

    def test_error_code_1311_vat_line_item_error(self, nav_client):
        """
        Test Warning 1311: VAT line item inconsistency.

        Scenario: Line item VAT calculation is incorrect
        (e.g., net amount * VAT rate != VAT amount).

        Expected: Starting Sept 2025, this will be BLOCKING.
        """
        assert NavErrorCode.VAT_LINE_ITEM_ERROR.value == "1311"

        mock_response = b"""<?xml version="1.0" encoding="UTF-8"?>
        <GeneralErrorResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api">
            <funcCode>ERROR</funcCode>
            <errorCode>1311</errorCode>
            <message>Line item VAT calculation error</message>
        </GeneralErrorResponse>"""

        with patch.object(nav_client.session, 'post') as mock_post:
            mock_post.return_value = Mock(
                status_code=200,
                content=mock_response
            )

            with pytest.raises(NavApiError) as exc_info:
                nav_client.query_invoice_data("TEST-INV-003", "INBOUND")

            assert exc_info.value.code == "1311"

    def test_validation_errors_not_retryable(self, nav_client):
        """
        Test that Sept 2025 validation errors are NOT retryable.

        These are data quality issues that require invoice correction,
        not transient failures.
        """
        # Create errors with validation codes
        error_435 = NavApiError("435", "VAT rate mismatch")
        error_734 = NavApiError("734", "VAT summary mismatch")
        error_1311 = NavApiError("1311", "VAT line item error")

        # None of these should be retryable
        assert not error_435.is_retryable
        assert not error_734.is_retryable
        assert not error_1311.is_retryable


# =============================================================================
# PRE-SUBMISSION VALIDATION (Future Enhancement)
# =============================================================================

class TestPreSubmissionValidation:
    """
    Tests for pre-submission validation layer (not yet implemented).

    These tests define the expected behavior for a validation layer
    that should be added before submitting invoices to NAV.
    """

    @pytest.mark.skip(reason="Pre-submission validation not yet implemented")
    def test_validate_vat_rate_against_tax_number(self):
        """
        Validate VAT rate matches tax number status before submission.

        Implementation should:
        1. Check if vendor tax number is domestic or foreign
        2. Verify VAT rate is appropriate (0% for reverse charge, 27% for domestic)
        3. Raise validation error if mismatch detected
        """
        pass

    @pytest.mark.skip(reason="Pre-submission validation not yet implemented")
    def test_validate_vat_summary_calculation(self):
        """
        Validate VAT summary matches line items before submission.

        Implementation should:
        1. Sum all line item VAT amounts
        2. Compare with VAT summary total
        3. Raise validation error if mismatch > 1 HUF (rounding tolerance)
        """
        pass

    @pytest.mark.skip(reason="Pre-submission validation not yet implemented")
    def test_validate_line_item_vat_calculation(self):
        """
        Validate each line item VAT calculation before submission.

        Implementation should:
        1. For each line: net_amount * vat_rate = vat_amount
        2. Allow 1 HUF rounding tolerance
        3. Raise validation error if calculation incorrect
        """
        pass


# =============================================================================
# INTEGRATION TESTS WITH REAL NAV TEST API
# =============================================================================

class TestNAVTestAPIIntegration:
    """
    Integration tests with real NAV test API.

    These tests require:
    - Valid NAV test credentials
    - Network access to api-test.onlineszamla.nav.gov.hu
    """

    @pytest.mark.integration
    @pytest.mark.skip(reason="Requires NAV test credentials and --run-integration flag")
    def test_submit_invoice_with_vat_error_435(self, nav_client):
        """
        Submit invoice with intentional VAT rate mismatch to NAV test API.

        This test verifies that NAV test API returns warning 435.
        """
        # This would require a complete invoice XML with intentional error
        pytest.skip("Requires complete invoice XML fixture")

    @pytest.mark.integration
    def test_query_invoice_handles_validation_errors(self, nav_client):
        """
        Test that client properly handles validation errors from NAV.

        Verifies error parsing and exception raising.
        """
        # This would query a known invoice with validation errors
        pytest.skip("Requires NAV test data setup")


# =============================================================================
# VALIDATION HELPER FUNCTIONS (Future Implementation)
# =============================================================================

def validate_vat_rate_for_tax_number(
    tax_number: str,
    vat_rate: float,
    is_domestic: bool = True
) -> tuple[bool, str]:
    """
    Validate VAT rate matches tax number status.

    Args:
        tax_number: 8-digit Hungarian tax number
        vat_rate: VAT rate as percentage (e.g., 27.0)
        is_domestic: Whether vendor is domestic Hungarian company

    Returns:
        Tuple of (is_valid, error_message)

    Rules:
        - Domestic companies: 27%, 18%, 5%, or 0% (exempt)
        - Foreign companies: Usually 0% (reverse charge)
        - Special tax numbers (starting with 8): May have different rules
    """
    valid_domestic_rates = {0.0, 5.0, 18.0, 27.0}
    valid_foreign_rates = {0.0}

    if not tax_number or len(tax_number) != 8:
        return False, f"Invalid tax number format: {tax_number} (must be 8 digits)"

    is_special_tax_number = tax_number.startswith("8")

    if is_special_tax_number:
        if vat_rate not in valid_domestic_rates:
            return False, (
                f"Special tax number {tax_number} has invalid VAT rate {vat_rate}%. "
                f"Valid rates: {sorted(valid_domestic_rates)}"
            )
        return True, ""

    if is_domestic:
        if vat_rate not in valid_domestic_rates:
            return False, (
                f"Domestic company VAT rate {vat_rate}% is invalid. "
                f"Valid rates: {sorted(valid_domestic_rates)}"
            )
    else:
        if vat_rate not in valid_foreign_rates:
            return False, (
                f"Foreign company should use reverse charge (0% VAT), "
                f"but invoice shows {vat_rate}%. This triggers NAV error 435."
            )

    return True, ""


def validate_vat_summary(
    line_items: List[Dict[str, float]],
    vat_summary: Dict[str, float],
    tolerance: float = 1.0
) -> tuple[bool, str]:
    """
    Validate VAT summary matches sum of line items.

    Args:
        line_items: List of dicts with 'vat_amount' keys
        vat_summary: Dict with 'total_vat' key
        tolerance: Allowed difference in HUF (default: 1.0)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not line_items:
        return True, ""

    calculated_total = sum(item.get("vat_amount", 0.0) for item in line_items)
    summary_total = vat_summary.get("total_vat", 0.0)
    difference = abs(calculated_total - summary_total)

    if difference <= tolerance:
        return True, ""
    else:
        return False, (
            f"VAT summary mismatch: sum of line items = {calculated_total:.2f} HUF, "
            f"but summary shows {summary_total:.2f} HUF "
            f"(difference: {difference:.2f} HUF, tolerance: {tolerance:.2f} HUF). "
            f"This triggers NAV error 734."
        )


def validate_line_item_vat(
    net_amount: float,
    vat_rate: float,
    vat_amount: float,
    tolerance: float = 1.0
) -> tuple[bool, str]:
    """
    Validate line item VAT calculation.

    Args:
        net_amount: Net amount before VAT
        vat_rate: VAT rate as percentage (e.g., 27.0)
        vat_amount: Calculated VAT amount
        tolerance: Allowed difference in HUF (default: 1.0)

    Returns:
        Tuple of (is_valid, error_message)

    Formula:
        expected_vat = net_amount * (vat_rate / 100)
        is_valid = abs(expected_vat - vat_amount) <= tolerance
    """
    expected_vat = net_amount * (vat_rate / 100.0)
    difference = abs(expected_vat - vat_amount)

    if difference <= tolerance:
        return True, ""
    else:
        return False, (
            f"VAT calculation error: {net_amount} * {vat_rate}% = {expected_vat:.2f}, "
            f"but invoice shows {vat_amount:.2f} (difference: {difference:.2f} HUF)"
        )


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

def pytest_addoption(parser):
    """Add custom pytest command line options."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests with real NAV test API"
    )

