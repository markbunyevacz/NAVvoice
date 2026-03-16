"""Tests for sending approved queue items with upload links."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from approval_queue import ApprovalQueue, ApprovalStatus
from approval_sender import send_approved_queue_items
from database_manager import DatabaseManager


@pytest.fixture
def db(tmp_path):
    db = DatabaseManager(str(tmp_path / "sender.db"))
    db.initialize()
    db.upsert_nav_invoices(
        "t-001",
        [{
            "invoiceNumber": "INV-2024-001",
            "supplierName": "Supplier Kft",
            "grossAmount": 125000,
            "invoiceDate": "2024-01-15",
        }],
    )
    return db


@pytest.fixture
def queue(tmp_path):
    queue = ApprovalQueue(str(tmp_path / "approval.db"))
    queue.initialize()
    return queue


def _approved_item_id(queue):
    item_id = queue.add_to_queue(
        tenant_id="t-001",
        invoice_number="INV-2024-001",
        vendor_name="Supplier Kft",
        vendor_email="vendor@example.com",
        email_subject="Hiányzó számla",
        email_body="Tisztelt Partnerünk!",
        amount=125000,
        invoice_date="2024-01-15",
        created_by="tester",
    )
    assert queue.approve(item_id, user_id="tester") is True
    return item_id


class TestSendApprovedQueueItems:
    def test_successful_send_updates_queue_and_invoice(self, db, queue):
        item_id = _approved_item_id(queue)
        mailer = MagicMock()
        mailer.send_email.return_value = {"success": True}

        summary = send_approved_queue_items(
            queue=queue,
            db=db,
            user_id="tester",
            tenant_id="t-001",
            mailer=mailer,
            app_base_url="https://app.navvoice.hu",
            limit=10,
        )

        assert summary["sent"] == 1
        sent_body = mailer.send_email.call_args.kwargs["body"]
        assert "Számla feltöltése az alábbi linken:" in sent_body
        assert queue.get_item(item_id).status == ApprovalStatus.SENT
        assert db.get_invoice("INV-2024-001", "t-001")["status"] == "EMAILED"
        token_rows = db.get_upload_tokens_for_invoice("t-001", "INV-2024-001")
        assert len(token_rows) == 1
        assert token_rows[0]["used_at"] is None

    def test_failed_send_invalidates_created_token(self, db, queue):
        item_id = _approved_item_id(queue)
        mailer = MagicMock()
        mailer.send_email.return_value = {"success": False, "error": "SMTP unavailable"}

        summary = send_approved_queue_items(
            queue=queue,
            db=db,
            user_id="tester",
            tenant_id="t-001",
            mailer=mailer,
            app_base_url="https://app.navvoice.hu",
            limit=10,
        )

        assert summary["failed"] == 1
        assert queue.get_item(item_id).status == ApprovalStatus.APPROVED
        assert db.get_invoice("INV-2024-001", "t-001")["status"] == "MISSING"
        token_rows = db.get_upload_tokens_for_invoice("t-001", "INV-2024-001")
        assert len(token_rows) == 1
        assert token_rows[0]["invalidated_at"] is not None
