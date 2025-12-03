"""
Integration tests for NAVvoice Invoice Reconciliation System.

Tests the full workflow:
1. JWT Authentication
2. Database multi-tenancy
3. PDF content scanning
4. Approval queue workflow
"""

import os
import sys
import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from database_manager import DatabaseManager, InvoiceStatus
from auth import AuthService, UserRole, Permission
from approval_queue import ApprovalQueue, ApprovalStatus
from pdf_scanner import PDFScanner, PDFContentExtractor


class TestDatabaseMultiTenancy:
    """Test database operations with tenant isolation."""

    @pytest.fixture
    def db(self, tmp_path):
        """Create a temporary database."""
        db_path = tmp_path / "test_invoices.db"
        db = DatabaseManager(str(db_path))
        db.initialize()
        return db

    def test_tenant_isolation(self, db):
        """Test that tenants cannot see each other's data."""
        # Insert invoices for tenant A
        invoices_a = [
            {"invoiceNumber": "INV-A-001", "supplierName": "Vendor A",
             "grossAmount": 100000, "invoiceDate": "2024-01-01"}
        ]
        inserted_a, _ = db.upsert_nav_invoices("tenant-a", invoices_a)
        assert inserted_a == 1

        # Insert invoices for tenant B
        invoices_b = [
            {"invoiceNumber": "INV-B-001", "supplierName": "Vendor B",
             "grossAmount": 200000, "invoiceDate": "2024-01-01"}
        ]
        inserted_b, _ = db.upsert_nav_invoices("tenant-b", invoices_b)
        assert inserted_b == 1

        # Verify tenant A only sees their invoice
        stats_a = db.get_statistics("tenant-a")
        assert stats_a["total_invoices"] == 1

        # Verify tenant B only sees their invoice
        stats_b = db.get_statistics("tenant-b")
        assert stats_b["total_invoices"] == 1

        # Verify cross-tenant lookup fails
        invoice = db.get_invoice("INV-A-001", tenant_id="tenant-b")
        assert invoice is None

    def test_duplicate_invoice_numbers_across_tenants(self, db):
        """Test same invoice number can exist in different tenants."""
        invoice_data = [
            {"invoiceNumber": "SHARED-001", "supplierName": "Vendor",
             "grossAmount": 100000, "invoiceDate": "2024-01-01"}
        ]

        # Both tenants can have same invoice number
        inserted_a, _ = db.upsert_nav_invoices("tenant-a", invoice_data)
        inserted_b, _ = db.upsert_nav_invoices("tenant-b", invoice_data)

        assert inserted_a == 1
        assert inserted_b == 1

    def test_mark_as_received_tenant_scoped(self, db):
        """Test marking invoice as received respects tenant scope."""
        invoice = [{"invoiceNumber": "INV-001", "supplierName": "Vendor",
                    "grossAmount": 100000, "invoiceDate": "2024-01-01"}]

        db.upsert_nav_invoices("tenant-a", invoice)

        # Wrong tenant cannot mark as received
        result = db.mark_as_received("tenant-b", "INV-001", "/path/to/pdf")
        assert result is False

        # Correct tenant can mark as received
        result = db.mark_as_received("tenant-a", "INV-001", "/path/to/pdf")
        assert result is True


class TestJWTAuthentication:
    """Test JWT authentication and authorization."""

    @pytest.fixture
    def auth(self, tmp_path):
        """Create auth service with temp database."""
        db_path = tmp_path / "test_auth.db"
        return AuthService(str(db_path), jwt_secret="test-secret-key-12345")

    def test_register_and_login(self, auth):
        """Test user registration and login flow."""
        # Register user
        user = auth.register(
            email="test@example.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001",
            name="Test User"
        )
        assert user is not None
        assert user.email == "test@example.com"
        assert user.role == UserRole.ACCOUNTANT

        # Login
        result = auth.login("test@example.com", "SecurePass123!")
        assert result["success"] is True
        assert "access_token" in result
        assert "refresh_token" in result

    def test_invalid_login(self, auth):
        """Test login with wrong password fails."""
        auth.register("user@test.com", "CorrectPass123!", UserRole.ADMIN, "t1", "User")

        result = auth.login("user@test.com", "WrongPassword!")
        assert result["success"] is False

    def test_token_validation(self, auth):
        """Test JWT token validation."""
        auth.register("validator@test.com", "Pass123!@#", UserRole.ACCOUNTANT, "t1", "Val")
        tokens = auth.login("validator@test.com", "Pass123!@#")

        # Validate token with correct permission
        valid, user, error = auth.validate_request(
            f"Bearer {tokens['access_token']}",
            [Permission.VIEW_INVOICES]
        )
        assert valid is True
        assert user.email == "validator@test.com"

    def test_permission_denied(self, auth):
        """Test that users without permission are denied."""
        auth.register("uploader@test.com", "Pass123!@#", UserRole.SITE_MANAGER, "t1", "Up")
        tokens = auth.login("uploader@test.com", "Pass123!@#")

        # Site manager cannot approve emails
        valid, user, error = auth.validate_request(
            f"Bearer {tokens['access_token']}",
            [Permission.APPROVE_EMAIL]
        )
        assert valid is False


class TestApprovalQueue:
    """Test human approval workflow."""

    @pytest.fixture
    def queue(self, tmp_path):
        """Create approval queue with temp database."""
        db_path = tmp_path / "test_queue.db"
        return ApprovalQueue(str(db_path))

    def test_add_and_approve(self, queue):
        """Test adding email to queue and approving."""
        item_id = queue.add_to_queue(
            tenant_id="tenant-001",
            invoice_number="INV-2024-001",
            vendor_name="Test Vendor Kft.",
            vendor_email="vendor@example.com",
            email_subject="Hiányzó számla: INV-2024-001",
            email_body="Tisztelt Partnerünk...",
            amount=125000.0,
            invoice_date="2024-01-15",
            created_by="user-001"
        )
        assert item_id is not None

        # Check pending
        pending = queue.get_pending_emails("tenant-001")
        assert len(pending) == 1
        assert pending[0].invoice_number == "INV-2024-001"

        # Approve
        result = queue.approve(item_id, "approver-001", "Looks good")
        assert result is True

        # Check approved
        approved = queue.get_approved_emails("tenant-001")
        assert len(approved) == 1
        assert approved[0].status == ApprovalStatus.APPROVED

    def test_reject_with_reason(self, queue):
        """Test rejecting an email with reason."""
        item_id = queue.add_to_queue(
            tenant_id="tenant-001",
            invoice_number="INV-2024-002",
            vendor_name="Another Vendor",
            vendor_email="other@example.com",
            email_subject="Test",
            email_body="Test body",
            amount=50000.0,
            invoice_date="2024-01-10",
            created_by="user-001"
        )

        result = queue.reject(item_id, "reviewer-001", "Wrong vendor email")
        assert result is True

        # Check no pending
        pending = queue.get_pending_emails("tenant-001")
        assert len(pending) == 0

    def test_edit_and_approve(self, queue):
        """Test editing email before approval."""
        item_id = queue.add_to_queue(
            tenant_id="tenant-001",
            invoice_number="INV-2024-003",
            vendor_name="Vendor",
            vendor_email="v@example.com",
            email_subject="Original Subject",
            email_body="Original body",
            amount=75000.0,
            invoice_date="2024-01-20",
            created_by="user-001"
        )

        result = queue.edit_and_approve(
            item_id,
            user_id="editor-001",
            new_subject="Edited Subject",
            new_body="Edited body with corrections",
            notes="Fixed typos"
        )
        assert result is True

        approved = queue.get_approved_emails("tenant-001")
        assert approved[0].email_subject == "Edited Subject"


class TestPDFContentExtractor:
    """Test PDF content extraction."""

    def test_invoice_pattern_matching(self):
        """Test regex patterns for Hungarian invoice numbers."""
        extractor = PDFContentExtractor()

        # Test various invoice formats
        test_texts = [
            ("Számlaszám: SZ-2024-0001", "SZ-2024-0001"),
            ("Invoice No: INV/2024/00123", "INV/2024/00123"),
            ("SZLA-2024-123456", "SZLA-2024-123456"),
            ("Számla száma: SZL-2024-0042", "SZL-2024-0042"),
        ]

        for text, expected in test_texts:
            numbers = extractor.find_invoice_numbers(text)
            assert len(numbers) > 0, f"Failed to find invoice in: {text}"
            assert expected in [n[0] for n in numbers], f"Expected {expected} in {numbers}"


class TestFullWorkflow:
    """Test complete reconciliation workflow."""

    @pytest.fixture
    def setup_all(self, tmp_path):
        """Set up all components."""
        db = DatabaseManager(str(tmp_path / "invoices.db"))
        db.initialize()

        auth = AuthService(str(tmp_path / "auth.db"), jwt_secret="test-secret")
        queue = ApprovalQueue(str(tmp_path / "queue.db"))

        return {"db": db, "auth": auth, "queue": queue, "tmp_path": tmp_path}

    def test_end_to_end_workflow(self, setup_all):
        """Test complete workflow from NAV import to email approval."""
        db = setup_all["db"]
        auth = setup_all["auth"]
        queue = setup_all["queue"]
        tenant_id = "test-tenant"

        # 1. Register and authenticate user
        auth.register("admin@test.com", "Admin123!@#", UserRole.ADMIN, tenant_id, "Admin")
        tokens = auth.login("admin@test.com", "Admin123!@#")
        assert tokens["success"]

        # 2. Import invoices from NAV
        nav_invoices = [
            {"invoiceNumber": "NAV-2024-001", "supplierName": "Supplier Kft.",
             "supplierTaxNumber": "12345678", "grossAmount": 250000,
             "invoiceDate": (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d")},
            {"invoiceNumber": "NAV-2024-002", "supplierName": "Another Zrt.",
             "supplierTaxNumber": "87654321", "grossAmount": 150000,
             "invoiceDate": datetime.now().strftime("%Y-%m-%d")}
        ]
        inserted, _ = db.upsert_nav_invoices(tenant_id, nav_invoices, "admin-user")
        assert inserted == 2

        # 3. Get missing invoices (older than 5 days)
        missing = db.get_missing_invoices(tenant_id, days_old=5)
        assert len(missing) == 1  # Only the 10-day old one
        assert missing[0]["nav_invoice_number"] == "NAV-2024-001"

        # 4. Add email to approval queue
        item_id = queue.add_to_queue(
            tenant_id=tenant_id,
            invoice_number="NAV-2024-001",
            vendor_name="Supplier Kft.",
            vendor_email="supplier@example.com",
            email_subject="Hiányzó számla: NAV-2024-001",
            email_body="Tisztelt Partnerünk, kérjük küldjék el...",
            amount=250000,
            invoice_date=missing[0]["invoice_date"],
            created_by="admin-user"
        )

        # 5. Approve email
        queue.approve(item_id, "admin-user", "Approved for sending")

        # 6. Mark as emailed
        db.mark_as_emailed(tenant_id, "NAV-2024-001", "admin-user")

        # 7. Verify final state
        invoice = db.get_invoice("NAV-2024-001", tenant_id)
        assert invoice["status"] == "EMAILED"
        assert invoice["email_count"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
