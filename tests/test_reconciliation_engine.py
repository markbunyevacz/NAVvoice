"""
Unit tests for reconciliation_engine module.

Uses mocked NavClient, DatabaseManager, PDFScanner, InvoiceAgent, ApprovalQueue
to test the pipeline orchestration without external dependencies.
"""

import os
import sys
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from reconciliation_engine import (
    map_nav_digest_to_upsert,
    run_reconciliation,
    ReconciliationConfig,
)
from nav_client import NavCredentials


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_nav_digest():
    """Sample NAV invoice digest as returned by query_incoming_invoices."""
    return [
        {
            "invoiceNumber": "INV-2024-001",
            "supplierName": "Test Supplier Kft.",
            "supplierTaxNumber": "12345678",
            "invoiceIssueDate": "2024-01-15",
            "currency": "HUF",
            "invoiceNetAmountHUF": 100000.0,
            "invoiceVatAmountHUF": 27000.0,
        },
        {
            "invoiceNumber": "INV-2024-002",
            "supplierName": "Another Vendor Zrt.",
            "supplierTaxNumber": "87654321",
            "invoiceIssueDate": "2024-01-20",
            "currency": "HUF",
            "invoiceNetAmountHUF": 50000.0,
            "invoiceVatAmountHUF": 13500.0,
        },
        {
            "invoiceNumber": "",  # Should be skipped
            "supplierName": "Invalid",
            "supplierTaxNumber": "11111111",
        },
    ]


@pytest.fixture
def valid_nav_credentials():
    """Valid NAV credentials for testing."""
    return NavCredentials(
        login="testuser",
        password="testpass",
        signature_key="a" * 32,
        replacement_key="b" * 32,
        tax_number="12345678",
    )


@pytest.fixture
def reconciliation_config(valid_nav_credentials, tmp_path):
    """ReconciliationConfig for testing."""
    pdf_folder = tmp_path / "pdfs"
    pdf_folder.mkdir()
    return ReconciliationConfig(
        date_from="2024-01-01",
        date_to="2024-01-31",
        pdf_folder_path=str(pdf_folder),
        nav_credentials=valid_nav_credentials,
        days_old=0,
        db_path=str(tmp_path / "invoices.db"),
        approval_queue_path=str(tmp_path / "approvals.db"),
        agent_config=None,
        vendor_directory=None,
        use_test_nav_api=True,
    )


# =============================================================================
# MAP NAV DIGEST TESTS
# =============================================================================

class TestMapNavDigestToUpsert:
    """Tests for map_nav_digest_to_upsert helper."""

    def test_maps_invoice_number(self, sample_nav_digest):
        """Invoice number is correctly mapped."""
        result = map_nav_digest_to_upsert(sample_nav_digest)
        assert len(result) == 2
        assert result[0]["nav_invoice_number"] == "INV-2024-001"
        assert result[1]["nav_invoice_number"] == "INV-2024-002"

    def test_skips_empty_invoice_number(self, sample_nav_digest):
        """Entries with empty invoice number are skipped."""
        result = map_nav_digest_to_upsert(sample_nav_digest)
        assert len(result) == 2

    def test_computes_gross_amount(self, sample_nav_digest):
        """Gross amount = net + VAT."""
        result = map_nav_digest_to_upsert(sample_nav_digest)
        assert result[0]["amount"] == 127000.0
        assert result[1]["amount"] == 63500.0

    def test_maps_vendor_fields(self, sample_nav_digest):
        """Vendor name and tax number are mapped."""
        result = map_nav_digest_to_upsert(sample_nav_digest)
        assert result[0]["vendor_name"] == "Test Supplier Kft."
        assert result[0]["vendor_tax_number"] == "12345678"
        assert result[1]["vendor_name"] == "Another Vendor Zrt."

    def test_maps_invoice_date(self, sample_nav_digest):
        """Invoice date comes from invoiceIssueDate."""
        result = map_nav_digest_to_upsert(sample_nav_digest)
        assert result[0]["invoice_date"] == "2024-01-15"

    def test_handles_missing_amounts(self):
        """Missing amount fields default to 0."""
        digest = [{"invoiceNumber": "X", "supplierName": "Y"}]
        result = map_nav_digest_to_upsert(digest)
        assert result[0]["amount"] == 0.0


# =============================================================================
# RUN RECONCILIATION TESTS (MOCKED)
# =============================================================================

class TestRunReconciliation:
    """Tests for run_reconciliation with mocked components."""

    @patch("reconciliation_engine.ApprovalQueue")
    @patch("reconciliation_engine.PDFScanner")
    @patch("reconciliation_engine.DatabaseManager")
    @patch("reconciliation_engine.NavClient")
    def test_full_pipeline_success(
        self,
        mock_nav_client_cls,
        mock_db_cls,
        mock_scanner_cls,
        mock_queue_cls,
        reconciliation_config,
    ):
        """Full pipeline runs and returns summary."""
        mock_nav = MagicMock()
        mock_nav.query_incoming_invoices.return_value = [
            {
                "invoiceNumber": "INV-001",
                "supplierName": "Vendor",
                "supplierTaxNumber": "12345678",
                "invoiceIssueDate": "2024-01-10",
                "currency": "HUF",
                "invoiceNetAmountHUF": 100000.0,
                "invoiceVatAmountHUF": 27000.0,
            },
        ]
        mock_nav_client_cls.return_value = mock_nav

        mock_db = MagicMock()
        mock_db.upsert_nav_invoices.return_value = (1, 0)
        mock_db.list_projects.return_value = []
        mock_db.get_invoices_requiring_project_mapping.return_value = []
        mock_db.get_missing_invoices.return_value = [
            {
                "nav_invoice_number": "INV-001",
                "vendor_name": "Vendor",
                "vendor_tax_number": "12345678",
                "amount": 127000.0,
                "invoice_date": "2024-01-10",
            },
        ]
        mock_db_cls.return_value = mock_db

        mock_scan_result = MagicMock()
        mock_scan_result.matched = 0
        mock_scanner = MagicMock()
        mock_scanner.scan_folder.return_value = mock_scan_result
        mock_scanner_cls.return_value = mock_scanner

        mock_queue = MagicMock()
        mock_queue_cls.return_value = mock_queue

        summary = run_reconciliation("tenant-001", reconciliation_config)

        assert summary["nav_fetched"] == 1
        assert summary["inserted"] == 1
        assert summary["matched"] == 0
        assert summary["missing_count"] == 1
        assert summary["queue_added"] == 1
        assert summary["emails_generated"] == 0

    @patch("reconciliation_engine.ApprovalQueue")
    @patch("reconciliation_engine.PDFScanner")
    @patch("reconciliation_engine.DatabaseManager")
    @patch("reconciliation_engine.NavClient")
    def test_nav_api_error_returns_early(
        self,
        mock_nav_client_cls,
        mock_db_cls,
        mock_scanner_cls,
        mock_queue_cls,
        reconciliation_config,
    ):
        """NAV API error stops pipeline and returns summary with error."""
        from nav_client import NavApiError

        mock_nav = MagicMock()
        mock_nav.query_incoming_invoices.side_effect = NavApiError(
            "INVALID_CREDENTIALS", "Auth failed"
        )
        mock_nav_client_cls.return_value = mock_nav

        summary = run_reconciliation("tenant-001", reconciliation_config)

        assert summary["nav_fetched"] == 0
        assert len(summary["errors"]) == 1
        assert "INVALID_CREDENTIALS" in summary["errors"][0]
        mock_db_cls.return_value.upsert_nav_invoices.assert_not_called()

    @patch("reconciliation_engine.ApprovalQueue")
    @patch("reconciliation_engine.PDFScanner")
    @patch("reconciliation_engine.DatabaseManager")
    @patch("reconciliation_engine.NavClient")
    def test_empty_nav_result_returns_early(
        self,
        mock_nav_client_cls,
        mock_db_cls,
        mock_scanner_cls,
        mock_queue_cls,
        reconciliation_config,
    ):
        """Empty NAV result returns without running upsert or scan."""
        mock_nav = MagicMock()
        mock_nav.query_incoming_invoices.return_value = []
        mock_nav_client_cls.return_value = mock_nav

        summary = run_reconciliation("tenant-001", reconciliation_config)

        assert summary["nav_fetched"] == 0
        mock_db_cls.return_value.upsert_nav_invoices.assert_not_called()

    @patch("reconciliation_engine.ApprovalQueue")
    @patch("reconciliation_engine.PDFScanner")
    @patch("reconciliation_engine.DatabaseManager")
    @patch("reconciliation_engine.NavClient")
    def test_no_missing_invoices_skips_queue(
        self,
        mock_nav_client_cls,
        mock_db_cls,
        mock_scanner_cls,
        mock_queue_cls,
        reconciliation_config,
    ):
        """When no MISSING invoices, queue is not called."""
        mock_nav = MagicMock()
        mock_nav.query_incoming_invoices.return_value = [
            {
                "invoiceNumber": "INV-001",
                "supplierName": "Vendor",
                "supplierTaxNumber": "12345678",
                "invoiceIssueDate": "2024-01-10",
                "currency": "HUF",
                "invoiceNetAmountHUF": 100000.0,
                "invoiceVatAmountHUF": 27000.0,
            },
        ]
        mock_nav_client_cls.return_value = mock_nav

        mock_db = MagicMock()
        mock_db.upsert_nav_invoices.return_value = (1, 0)
        mock_db.list_projects.return_value = []
        mock_db.get_invoices_requiring_project_mapping.return_value = []
        mock_db.get_missing_invoices.return_value = []
        mock_db_cls.return_value = mock_db

        mock_scan_result = MagicMock()
        mock_scan_result.matched = 1
        mock_scanner = MagicMock()
        mock_scanner.scan_folder.return_value = mock_scan_result
        mock_scanner_cls.return_value = mock_scanner

        summary = run_reconciliation("tenant-001", reconciliation_config)

        assert summary["missing_count"] == 0
        assert summary["queue_added"] == 0
        mock_queue_cls.return_value.add_to_queue.assert_not_called()

    @patch("reconciliation_engine.ApprovalQueue")
    @patch("reconciliation_engine.PDFScanner")
    @patch("reconciliation_engine.DatabaseManager")
    @patch("reconciliation_engine.NavClient")
    def test_project_mapping_assigns_when_unique_match(
        self,
        mock_nav_client_cls,
        mock_db_cls,
        mock_scanner_cls,
        mock_queue_cls,
        reconciliation_config,
    ):
        """Project mapping assigns tenant project when line description matches."""
        mock_nav = MagicMock()
        mock_nav.query_incoming_invoices.return_value = [
            {
                "invoiceNumber": "INV-001",
                "supplierName": "Vendor",
                "supplierTaxNumber": "12345678",
                "invoiceIssueDate": "2024-01-10",
                "currency": "HUF",
                "invoiceNetAmountHUF": 100000.0,
                "invoiceVatAmountHUF": 27000.0,
            },
        ]
        mock_nav.query_invoice_data.return_value = {
            "line_descriptions": ["Munkaszám: PRJ-001 belső kivitelezés"],
        }
        mock_nav_client_cls.return_value = mock_nav

        mock_db = MagicMock()
        mock_db.upsert_nav_invoices.return_value = (1, 0)
        mock_db.list_projects.return_value = [
            {
                "id": 10,
                "tenant_id": "tenant-001",
                "project_code": "PRJ-001",
                "project_name": "Pilot Project",
                "aliases": "Munkaszám: PRJ-001",
                "reference_patterns": None,
                "is_active": 1,
            }
        ]
        mock_db.get_invoices_requiring_project_mapping.return_value = [
            {"nav_invoice_number": "INV-001"}
        ]
        mock_db.get_missing_invoices.return_value = []
        mock_db_cls.return_value = mock_db

        mock_scan_result = MagicMock()
        mock_scan_result.matched = 0
        mock_scanner_cls.return_value.scan_folder.return_value = mock_scan_result

        summary = run_reconciliation("tenant-001", reconciliation_config)

        assert summary["project_mapping_attempted"] == 1
        assert summary["project_mapping_assigned"] == 1
        mock_db.assign_project_to_invoice.assert_called_once_with(
            tenant_id="tenant-001",
            invoice_number="INV-001",
            project_id=10,
            user_id="reconciliation-engine",
        )

    @patch("reconciliation_engine.ApprovalQueue")
    @patch("reconciliation_engine.PDFScanner")
    @patch("reconciliation_engine.DatabaseManager")
    @patch("reconciliation_engine.NavClient")
    def test_project_mapping_failure_is_non_blocking(
        self,
        mock_nav_client_cls,
        mock_db_cls,
        mock_scanner_cls,
        mock_queue_cls,
        reconciliation_config,
    ):
        """Project mapping errors are captured without stopping the pipeline."""
        mock_nav = MagicMock()
        mock_nav.query_incoming_invoices.return_value = [
            {
                "invoiceNumber": "INV-001",
                "supplierName": "Vendor",
                "supplierTaxNumber": "12345678",
                "invoiceIssueDate": "2024-01-10",
                "currency": "HUF",
                "invoiceNetAmountHUF": 100000.0,
                "invoiceVatAmountHUF": 27000.0,
            },
        ]
        mock_nav.query_invoice_data.side_effect = Exception("parse failure")
        mock_nav_client_cls.return_value = mock_nav

        mock_db = MagicMock()
        mock_db.upsert_nav_invoices.return_value = (1, 0)
        mock_db.list_projects.return_value = [
            {
                "id": 10,
                "tenant_id": "tenant-001",
                "project_code": "PRJ-001",
                "project_name": "Pilot Project",
                "aliases": None,
                "reference_patterns": None,
                "is_active": 1,
            }
        ]
        mock_db.get_invoices_requiring_project_mapping.return_value = [
            {"nav_invoice_number": "INV-001"}
        ]
        mock_db.get_missing_invoices.return_value = []
        mock_db_cls.return_value = mock_db

        mock_scan_result = MagicMock()
        mock_scan_result.matched = 0
        mock_scanner_cls.return_value.scan_folder.return_value = mock_scan_result

        summary = run_reconciliation("tenant-001", reconciliation_config)

        assert summary["project_mapping_attempted"] == 1
        assert summary["project_mapping_assigned"] == 0
        assert any("Project mapping failed for INV-001" in err for err in summary["errors"])
        mock_db.assign_project_to_invoice.assert_not_called()


# =============================================================================
# RECONCILIATION CONFIG TESTS
# =============================================================================

class TestReconciliationConfig:
    """Tests for ReconciliationConfig dataclass."""

    def test_config_creation(self, valid_nav_credentials, tmp_path):
        """Config can be instantiated with required fields."""
        config = ReconciliationConfig(
            date_from="2024-01-01",
            date_to="2024-01-31",
            pdf_folder_path=str(tmp_path / "pdfs"),
            nav_credentials=valid_nav_credentials,
        )
        assert config.days_old == 0
        assert config.db_path == "data/invoices.db"
        assert config.use_test_nav_api is True
