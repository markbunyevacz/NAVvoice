"""
Tests for the reusable invoice pre-validator and warning persistence helpers.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestInvoicePreValidator:
    def test_returns_typed_findings_for_multiple_rules(self):
        from invoice_prevalidator import InvoicePreValidator, ValidationSeverity

        validator = InvoicePreValidator()
        xml = b"""<invoice>
            <invoiceNumber>INV-2024-001</invoiceNumber>
            <modificationReference>
                <originalInvoiceNumber>INV-2024-001</originalInvoiceNumber>
            </modificationReference>
            <modificationIndex>0</modificationIndex>
            <customerTaxNumber>
                <taxpayerId>12345678</taxpayerId>
                <vatCode>1</vatCode>
            </customerTaxNumber>
            <invoiceSummary>
                <summaryByVatRate>
                    <vatRateVatAmount>2700</vatRateVatAmount>
                </summaryByVatRate>
            </invoiceSummary>
            <line>
                <lineNumber>1</lineNumber>
                <lineDeliveryDate>2024-02-10</lineDeliveryDate>
                <lineDeliveryDateTo>2024-02-01</lineDeliveryDateTo>
                <lineNetAmount>10000</lineNetAmount>
                <lineVatAmount>2700</lineVatAmount>
                <vatPercentage>27</vatPercentage>
            </line>
        </invoice>"""

        findings = validator.validate_sept_2025_rules(xml)

        codes = {finding.code for finding in findings}
        assert {"330", "435", "560", "1150"} <= codes

        by_code = {finding.code: finding for finding in findings}
        assert by_code["330"].severity == ValidationSeverity.ERROR
        assert by_code["330"].is_blocking is True
        assert by_code["435"].severity == ValidationSeverity.WARNING
        assert "vatCode=1" in by_code["435"].message

    def test_warning_only_tax_group_checks_are_inferable(self):
        from invoice_prevalidator import InvoicePreValidator, ValidationSeverity

        validator = InvoicePreValidator()
        xml = b"""<invoice>
            <customerTaxNumber>
                <taxpayerId>12345678</taxpayerId>
            </customerTaxNumber>
            <line>
                <lineNumber>1</lineNumber>
                <lineNetAmount>10000</lineNetAmount>
                <lineVatAmount>2700</lineVatAmount>
                <vatPercentage>27</vatPercentage>
            </line>
        </invoice>"""

        findings = validator.validate_sept_2025_rules(xml)

        assert [finding.code for finding in findings] == ["91"]
        assert findings[0].severity == ValidationSeverity.WARNING

    def test_invalid_xml_returns_empty_findings(self):
        from invoice_prevalidator import InvoicePreValidator

        validator = InvoicePreValidator()
        assert validator.validate_sept_2025_rules(b"<not-xml") == []

    def test_format_findings_keeps_backward_compatible_strings(self):
        from invoice_prevalidator import (
            InvoicePreValidator,
            ValidationSeverity,
            ValidationWarning,
        )

        formatted = InvoicePreValidator.format_findings(
            [
                ValidationWarning(
                    code="330",
                    message="Sample issue",
                    severity=ValidationSeverity.ERROR,
                    is_blocking=True,
                )
            ]
        )
        assert formatted == ["[330] Sample issue"]


class TestValidationWarningPersistence:
    @pytest.fixture
    def db(self, tmp_path):
        from database_manager import DatabaseManager

        db = DatabaseManager(str(tmp_path / "invoices.db"))
        db.initialize()
        db.upsert_nav_invoices(
            "tenant-001",
            [
                {
                    "invoiceNumber": "INV-001",
                    "supplierName": "Vendor",
                    "grossAmount": 127000,
                    "invoiceDate": "2024-01-10",
                }
            ],
        )
        return db

    def test_persisted_warnings_appear_on_invoice_row(self, db):
        persisted = db.replace_invoice_validation_warnings(
            "tenant-001",
            "INV-001",
            [
                {
                    "code": "330",
                    "message": "Line 1 date range invalid",
                    "pointer": "line[1].lineDeliveryDateTo",
                    "severity": "ERROR",
                    "is_blocking": True,
                },
                {
                    "code": "435",
                    "message": (
                        "Taxable VAT rates inconsistent with buyer "
                        "vatCode=1"
                    ),
                    "pointer": "customerTaxNumber/vatCode",
                    "severity": "WARNING",
                    "is_blocking": False,
                },
            ],
        )

        invoice = db.get_invoice("INV-001", tenant_id="tenant-001")
        warnings = db.get_invoice_validation_warnings("tenant-001", "INV-001")
        stats = db.get_statistics("tenant-001")

        assert persisted == 2
        assert invoice is not None
        assert invoice["has_warnings"] is True
        assert invoice["warning_count"] == 2
        assert "330" in invoice["warning_codes"]
        assert "435" in invoice["warning_codes"]
        assert invoice["has_blocking_warnings"] is True
        assert len(warnings) == 2
        assert stats["warning_invoices"] == 1
        assert stats["blocking_warning_invoices"] == 1

    def test_replacing_with_empty_list_clears_existing_warnings(self, db):
        db.replace_invoice_validation_warnings(
            "tenant-001",
            "INV-001",
            [
                {
                    "code": "330",
                    "message": "Line 1 date range invalid",
                    "severity": "ERROR",
                    "is_blocking": True,
                }
            ],
        )

        db.replace_invoice_validation_warnings("tenant-001", "INV-001", [])

        invoice = db.get_invoice("INV-001", tenant_id="tenant-001")
        warnings = db.get_invoice_validation_warnings("tenant-001", "INV-001")

        assert invoice is not None
        assert invoice["has_warnings"] is False
        assert invoice["warning_count"] == 0
        assert warnings == []
