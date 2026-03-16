"""
Integration Tests for September 2025 NAV Validation Rules

Tests the 21 blocking validation rules that NAV will enforce starting Sept 15, 2025.

Two sources of error codes:
- Technical Guide (VAT calculation): 435, 734, 1311
- Sept 2025 regression matrix (formal validation): 82, 91, 330, 434, 560,
  581-584, 591, 593, 596, 620, 701, 1140, 1150, 1300, 1310

Requirements:
    pip install pytest pytest-mock lxml
"""

import pytest
from unittest.mock import Mock, patch
from lxml import etree

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from nav_client import (
    NavClient, NavCredentials, NavApiError, NavErrorCode,
    _SEPT_2025_BLOCKING_VALUES,
)


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
        replacement_key="ABCDEF0123456789ABCDEF0123456789",
        tax_number="12345678",
    )


@pytest.fixture
def nav_client(nav_credentials):
    """NAV client instance for testing."""
    return NavClient(nav_credentials, use_test_api=True)


# =============================================================================
# 1. ENUM VALUE COMPLETENESS
# =============================================================================

class TestNavErrorCodeEnumValues:
    """Verify every enum member has the correct value."""

    _ALL_VALIDATION_CODES = {
        # VAT calculation (Technical Guide, pre-existing)
        NavErrorCode.VAT_RATE_MISMATCH: "435",
        NavErrorCode.VAT_SUMMARY_MISMATCH: "734",
        NavErrorCode.VAT_LINE_ITEM_ERROR: "1311",
        # Sept 2025 confirmed blocking (15 WARN -> ERROR)
        NavErrorCode.INVALID_COMPLETION_DATE_RANGE: "330",
        NavErrorCode.MISSING_UNIT_OF_MEASURE_OWN: "434",
        NavErrorCode.MODIFICATION_NUMBER_SAME_AS_ORIGINAL: "560",
        NavErrorCode.INCORRECT_VAT_MARKING_581: "581",
        NavErrorCode.INCORRECT_VAT_MARKING_582: "582",
        NavErrorCode.INCORRECT_VAT_MARKING_583: "583",
        NavErrorCode.INCORRECT_VAT_MARKING_584: "584",
        NavErrorCode.VAT_DATA_WITH_EXEMPTION: "591",
        NavErrorCode.VAT_DATA_OUT_OF_SCOPE: "593",
        NavErrorCode.DOMESTIC_REVERSE_CHARGE_BUYER: "596",
        NavErrorCode.MISSING_PERFORMANCE_DATE_AGGREGATE: "620",
        NavErrorCode.VAT_SUMMARY_OUT_OF_SCOPE: "701",
        NavErrorCode.UNREALISTIC_MODIFICATION_SEQUENCE: "1150",
        NavErrorCode.EXCHANGE_RATE_MISMATCH: "1300",
        NavErrorCode.EXTREME_EXCHANGE_RATE: "1310",
        # Remained as WARNING (dropped from Sept 2025 blocking plan)
        NavErrorCode.INVALID_BUYER_VAT_GROUP: "82",
        NavErrorCode.TAX_NUMBER_VAT_GROUP_ISSUE: "91",
        NavErrorCode.MODIFY_CANCELLED_INVOICE: "1140",
    }

    @pytest.mark.parametrize(
        "member,expected_value",
        _ALL_VALIDATION_CODES.items(),
        ids=[m.name for m in _ALL_VALIDATION_CODES],
    )
    def test_enum_value(self, member, expected_value):
        assert member.value == expected_value

    def test_all_blocking_values_covered_by_enum(self):
        """Every value in _SEPT_2025_BLOCKING_VALUES must map to an enum member."""
        enum_values = {m.value for m in NavErrorCode}
        for code in _SEPT_2025_BLOCKING_VALUES:
            assert code in enum_values, f"Blocking code {code} has no enum member"

    def test_blocking_set_has_exactly_15_codes(self):
        """NTCA-tax confirmed exactly 15 WARN->ERROR codes (Jul 20, 2025)."""
        assert len(_SEPT_2025_BLOCKING_VALUES) == 15

    def test_dropped_codes_not_in_blocking_set(self):
        """82, 91, 1140 were removed from blocking after community consultation."""
        assert "82" not in _SEPT_2025_BLOCKING_VALUES
        assert "91" not in _SEPT_2025_BLOCKING_VALUES
        assert "1140" not in _SEPT_2025_BLOCKING_VALUES

    def test_technical_guide_codes_not_in_blocking_set(self):
        """435, 734, 1311 are pre-existing codes, not part of WARN->ERROR transition."""
        assert "435" not in _SEPT_2025_BLOCKING_VALUES
        assert "734" not in _SEPT_2025_BLOCKING_VALUES
        assert "1311" not in _SEPT_2025_BLOCKING_VALUES


# =============================================================================
# 2. is_sept_2025_blocking PROPERTY (Enum + NavApiError)
# =============================================================================

class TestIsSept2025BlockingProperty:
    """Verify the is_sept_2025_blocking property on NavErrorCode and NavApiError."""

    @pytest.mark.parametrize("code_value", sorted(_SEPT_2025_BLOCKING_VALUES, key=int))
    def test_enum_blocking_true(self, code_value):
        member = NavErrorCode(code_value)
        assert member.is_sept_2025_blocking is True

    @pytest.mark.parametrize("member", [
        NavErrorCode.OPERATION_FAILED,
        NavErrorCode.MAINTENANCE,
        NavErrorCode.TOO_MANY_REQUESTS,
        NavErrorCode.TECHNICAL_ERROR,
        NavErrorCode.TIMEOUT,
    ])
    def test_retryable_codes_not_blocking(self, member):
        assert member.is_sept_2025_blocking is False

    @pytest.mark.parametrize("member", [
        NavErrorCode.INVALID_REQUEST_SIGNATURE,
        NavErrorCode.INVALID_CREDENTIALS,
        NavErrorCode.INVALID_EXCHANGE_KEY,
        NavErrorCode.EMPTY_TOKEN,
        NavErrorCode.TOKEN_DECRYPTION_FAILED,
    ])
    def test_non_retryable_codes_not_blocking(self, member):
        assert member.is_sept_2025_blocking is False

    @pytest.mark.parametrize("member", [
        NavErrorCode.INVALID_BUYER_VAT_GROUP,
        NavErrorCode.TAX_NUMBER_VAT_GROUP_ISSUE,
        NavErrorCode.MODIFY_CANCELLED_INVOICE,
    ])
    def test_dropped_codes_not_blocking(self, member):
        """82, 91, 1140 were removed from blocking plan per NTCA-tax."""
        assert member.is_sept_2025_blocking is False

    @pytest.mark.parametrize("member", [
        NavErrorCode.VAT_RATE_MISMATCH,
        NavErrorCode.VAT_SUMMARY_MISMATCH,
        NavErrorCode.VAT_LINE_ITEM_ERROR,
    ])
    def test_technical_guide_codes_not_blocking(self, member):
        """435, 734, 1311 are pre-existing codes, not WARN->ERROR transition."""
        assert member.is_sept_2025_blocking is False

    def test_nav_api_error_blocking_true(self):
        err = NavApiError("330", "date range error")
        assert err.is_sept_2025_blocking is True

    def test_nav_api_error_blocking_false(self):
        err = NavApiError("OPERATION_FAILED", "transient")
        assert err.is_sept_2025_blocking is False

    def test_nav_api_error_retryable_and_blocking_mutually_exclusive(self):
        for code in _SEPT_2025_BLOCKING_VALUES:
            err = NavApiError(code, "test")
            assert not err.is_retryable, f"Blocking code {code} should not be retryable"


# =============================================================================
# 3. NAV RESPONSE ERROR CODE HANDLING (existing 435 / 734 / 1311 tests kept)
# =============================================================================

class TestSept2025NavResponseHandling:
    """Test that NAV API responses with Sept 2025 codes are parsed correctly."""

    def _make_error_response(self, error_code: str, message: str) -> bytes:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
        <QueryInvoiceDataResponse xmlns="http://schemas.nav.gov.hu/OSA/3.0/api"
                                  xmlns:common="http://schemas.nav.gov.hu/NTCA/1.0/common">
            <common:header>
                <common:requestId>TEST123</common:requestId>
                <common:timestamp>2024-01-01T00:00:00Z</common:timestamp>
            </common:header>
            <common:result>
                <common:funcCode>ERROR</common:funcCode>
                <common:errorCode>{error_code}</common:errorCode>
                <common:message>{message}</common:message>
            </common:result>
        </QueryInvoiceDataResponse>""".encode()

    @pytest.mark.parametrize("code,msg,blocking", [
        ("330", "Performance period end before start", True),
        ("596", "Reverse charge non-domestic buyer", True),
        ("1300", "Exchange rate mismatch", True),
        ("435", "VAT rate does not match tax number status", False),
        ("734", "VAT summary does not match line items", False),
        ("1311", "Line item VAT calculation error", False),
    ])
    def test_response_raises_nav_api_error(self, nav_client, code, msg, blocking):
        mock_response = self._make_error_response(code, msg)
        with patch.object(nav_client.session, "post") as mock_post:
            mock_post.return_value = Mock(status_code=200, content=mock_response)
            with pytest.raises(NavApiError) as exc_info:
                nav_client.query_invoice_data("TEST-INV", "INBOUND")
            assert exc_info.value.code == code
            assert exc_info.value.is_sept_2025_blocking is blocking

    def test_validation_errors_not_retryable(self):
        for code in ("435", "734", "1311", "330", "596", "1300"):
            err = NavApiError(code, "test")
            assert not err.is_retryable


# =============================================================================
# 4. PRE-SUBMISSION VALIDATION – ERROR 330 (Date range)
# =============================================================================

class TestPreValidation330:
    """[330] Performance period end date must not precede start date."""

    def test_valid_date_range_no_error(self, nav_client):
        xml = b"""<invoice>
            <line>
                <lineNumber>1</lineNumber>
                <lineDeliveryDate>2024-01-10</lineDeliveryDate>
                <lineDeliveryDateTo>2024-01-15</lineDeliveryDateTo>
            </line>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[330]" in e for e in errors)

    def test_end_before_start_triggers_330(self, nav_client):
        xml = b"""<invoice>
            <line>
                <lineNumber>1</lineNumber>
                <lineDeliveryDate>2024-01-15</lineDeliveryDate>
                <lineDeliveryDateTo>2024-01-10</lineDeliveryDateTo>
            </line>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[330]" in e for e in errors)

    def test_same_date_no_error(self, nav_client):
        xml = b"""<invoice>
            <line>
                <lineNumber>1</lineNumber>
                <lineDeliveryDate>2024-01-10</lineDeliveryDate>
                <lineDeliveryDateTo>2024-01-10</lineDeliveryDateTo>
            </line>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[330]" in e for e in errors)

    def test_missing_dates_no_error(self, nav_client):
        xml = b"""<invoice><line><lineNumber>1</lineNumber></line></invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[330]" in e for e in errors)


# =============================================================================
# 5. PRE-SUBMISSION VALIDATION – ERROR 596 (Reverse charge buyer)
# =============================================================================

class TestPreValidation596:
    """[596] Domestic reverse charge requires buyer to be domestic VAT taxpayer."""

    def test_reverse_charge_with_domestic_buyer_no_error(self, nav_client):
        xml = b"""<invoice>
            <vatExemptionCase>AAM</vatExemptionCase>
            <customerTaxNumber>
                <taxpayerId>12345678</taxpayerId>
                <vatCode>2</vatCode>
            </customerTaxNumber>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[596]" in e for e in errors)

    def test_reverse_charge_missing_buyer_tax_number(self, nav_client):
        xml = b"""<invoice>
            <vatExemptionCase>AAM</vatExemptionCase>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[596]" in e for e in errors)

    def test_reverse_charge_non_domestic_buyer(self, nav_client):
        xml = b"""<invoice>
            <vatExemptionCase>AAM</vatExemptionCase>
            <customerTaxNumber>
                <taxpayerId>12345678</taxpayerId>
                <vatCode>1</vatCode>
            </customerTaxNumber>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[596]" in e for e in errors)

    def test_non_reverse_charge_skips_check(self, nav_client):
        xml = b"""<invoice>
            <vatExemptionCase>TAM</vatExemptionCase>
            <customerTaxNumber>
                <taxpayerId>12345678</taxpayerId>
                <vatCode>1</vatCode>
            </customerTaxNumber>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[596]" in e for e in errors)


# =============================================================================
# 6. PRE-SUBMISSION VALIDATION – ERROR 560 (Modification number)
# =============================================================================

class TestPreValidation560:
    """[560] Modification invoice number must differ from original."""

    def test_different_numbers_no_error(self, nav_client):
        xml = b"""<invoice>
            <invoiceNumber>MOD-2024-001</invoiceNumber>
            <modificationReference>
                <originalInvoiceNumber>INV-2024-001</originalInvoiceNumber>
            </modificationReference>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[560]" in e for e in errors)

    def test_same_numbers_triggers_560(self, nav_client):
        xml = b"""<invoice>
            <invoiceNumber>INV-2024-001</invoiceNumber>
            <modificationReference>
                <originalInvoiceNumber>INV-2024-001</originalInvoiceNumber>
            </modificationReference>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[560]" in e for e in errors)

    def test_no_modification_reference_no_error(self, nav_client):
        xml = b"""<invoice>
            <invoiceNumber>INV-2024-001</invoiceNumber>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[560]" in e for e in errors)


# =============================================================================
# 7. PRE-SUBMISSION VALIDATION – ERRORS 1300 / 1310 (Exchange rate)
# =============================================================================

class TestPreValidation1300:
    """[1300] Exchange rate vs HUF ratio and [1310] extreme rate values."""

    def test_huf_invoice_skips_check(self, nav_client):
        xml = b"""<invoice>
            <currencyCode>HUF</currencyCode>
            <exchangeRate>1</exchangeRate>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[1300]" in e or "[1310]" in e for e in errors)

    def test_valid_eur_rate_no_error(self, nav_client):
        xml = b"""<invoice>
            <currencyCode>EUR</currencyCode>
            <exchangeRate>400</exchangeRate>
            <invoiceNetAmountHUF>400000</invoiceNetAmountHUF>
            <invoiceNetAmount>1000</invoiceNetAmount>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[1300]" in e for e in errors)

    def test_mismatched_rate_triggers_1300(self, nav_client):
        xml = b"""<invoice>
            <currencyCode>EUR</currencyCode>
            <exchangeRate>400</exchangeRate>
            <invoiceNetAmountHUF>100000</invoiceNetAmountHUF>
            <invoiceNetAmount>1000</invoiceNetAmount>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[1300]" in e for e in errors)

    def test_extreme_rate_triggers_1310(self, nav_client):
        xml = b"""<invoice>
            <currencyCode>EUR</currencyCode>
            <exchangeRate>0.01</exchangeRate>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[1310]" in e for e in errors)

    def test_negative_rate_triggers_1310(self, nav_client):
        xml = b"""<invoice>
            <currencyCode>USD</currencyCode>
            <exchangeRate>-350</exchangeRate>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[1310]" in e for e in errors)

    def test_no_exchange_rate_no_error(self, nav_client):
        xml = b"""<invoice>
            <currencyCode>EUR</currencyCode>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[1300]" in e or "[1310]" in e for e in errors)


# =============================================================================
# 8. PRE-SUBMISSION VALIDATION – EXISTING 734 / 1311
# =============================================================================

class TestPreValidation734And1311:
    """Existing VAT summary (734) and line-item (1311) checks still work."""

    def test_vat_summary_mismatch_triggers_734(self, nav_client):
        xml = b"""<invoice>
            <summaryByVatRate>
                <vatRateVatAmount>30000</vatRateVatAmount>
            </summaryByVatRate>
            <line>
                <lineNumber>1</lineNumber>
                <lineNetAmount>100000</lineNetAmount>
                <lineVatAmount>27000</lineVatAmount>
                <vatPercentage>27</vatPercentage>
            </line>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[734]" in e for e in errors)

    def test_line_item_vat_error_triggers_1311(self, nav_client):
        xml = b"""<invoice>
            <line>
                <lineNumber>1</lineNumber>
                <lineNetAmount>100000</lineNetAmount>
                <lineVatAmount>20000</lineVatAmount>
                <vatPercentage>27</vatPercentage>
            </line>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert any("[1311]" in e for e in errors)

    def test_valid_vat_no_errors(self, nav_client):
        xml = b"""<invoice>
            <line>
                <lineNumber>1</lineNumber>
                <lineNetAmount>100000</lineNetAmount>
                <lineVatAmount>27000</lineVatAmount>
                <vatPercentage>27</vatPercentage>
            </line>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        assert not any("[1311]" in e for e in errors)


# =============================================================================
# 9. COMBINED VALIDATION SCENARIOS
# =============================================================================

class TestCombinedValidation:
    """Multiple validation errors detected in a single invoice."""

    def test_multiple_errors_in_one_invoice(self, nav_client):
        xml = b"""<invoice>
            <invoiceNumber>INV-001</invoiceNumber>
            <currencyCode>EUR</currencyCode>
            <exchangeRate>-1</exchangeRate>
            <modificationReference>
                <originalInvoiceNumber>INV-001</originalInvoiceNumber>
            </modificationReference>
            <line>
                <lineNumber>1</lineNumber>
                <lineDeliveryDate>2024-06-15</lineDeliveryDate>
                <lineDeliveryDateTo>2024-06-01</lineDeliveryDateTo>
                <lineNetAmount>100000</lineNetAmount>
                <lineVatAmount>20000</lineVatAmount>
                <vatPercentage>27</vatPercentage>
            </line>
        </invoice>"""
        errors = nav_client._validate_sept_2025_rules(xml)
        codes_found = {e.split("]")[0].lstrip("[") for e in errors}
        assert "330" in codes_found
        assert "560" in codes_found
        assert "1310" in codes_found
        assert "1311" in codes_found

    def test_malformed_xml_returns_empty(self, nav_client):
        errors = nav_client._validate_sept_2025_rules(b"<not-xml")
        assert errors == []


# =============================================================================
# 10. INTEGRATION TESTS (require real credentials)
# =============================================================================

class TestNAVTestAPIIntegration:
    """Integration tests with real NAV test API (skipped by default)."""

    @pytest.mark.integration
    @pytest.mark.skip(reason="Requires NAV test credentials and --run-integration flag")
    def test_submit_invoice_with_vat_error_435(self, nav_client):
        pytest.skip("Requires complete invoice XML fixture")

    @pytest.mark.integration
    def test_query_invoice_handles_validation_errors(self, nav_client):
        pytest.skip("Requires NAV test data setup")


# =============================================================================
# PYTEST CONFIGURATION
# =============================================================================

def pytest_addoption(parser):
    """Add custom pytest command line options."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests with real NAV test API",
    )

