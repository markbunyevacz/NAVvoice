"""
Tests for api/approval.py -- list pending, approve, reject.

ApprovalQueue is mocked; AuthService is real (in-memory).
"""

import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from api import deps
from auth import AuthService, AuthConfig, UserRole
from approval_queue import QueueItem, ApprovalStatus, Priority


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _make_queue_item(item_id="q-1", tenant_id="t-001", status=ApprovalStatus.PENDING):
    return QueueItem(
        id=item_id,
        tenant_id=tenant_id,
        invoice_number="INV-001",
        vendor_name="Supplier Kft",
        vendor_email="info@supplier.hu",
        email_subject="Hiányzó számla",
        email_body="Tisztelt Partner...",
        email_tone="polite",
        amount=50000.0,
        invoice_date="2024-01-15",
        status=status,
        priority=Priority.NORMAL,
        created_at=datetime(2024, 1, 20),
        updated_at=datetime(2024, 1, 20),
    )


# -------------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset():
    deps.reset_singletons()
    yield
    deps.reset_singletons()


@pytest.fixture
def auth_service():
    svc = AuthService(AuthConfig(secret_key="test-key-approval"))
    svc.register(
        email="acc@test.hu",
        password="Passw0rd!Strong",
        role=UserRole.ACCOUNTANT,
        tenant_id="t-001",
    )
    svc.register(
        email="site@test.hu",
        password="Passw0rd!Strong",
        role=UserRole.SITE_MANAGER,
        tenant_id="t-001",
    )
    return svc


@pytest.fixture
def mock_queue():
    return MagicMock()


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.initialize = MagicMock()
    return db


@pytest.fixture
def client(auth_service, mock_queue, mock_db):
    app.dependency_overrides[deps.get_auth_service] = lambda: auth_service
    app.dependency_overrides[deps.get_approval_queue] = lambda: mock_queue
    app.dependency_overrides[deps.get_db] = lambda: mock_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def accountant_token(auth_service):
    return auth_service.login("acc@test.hu", "Passw0rd!Strong")["access_token"]


@pytest.fixture
def site_manager_token(auth_service):
    return auth_service.login("site@test.hu", "Passw0rd!Strong")["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# -------------------------------------------------------------------------
# GET /api/v1/approval-queue
# -------------------------------------------------------------------------

class TestListPending:
    def test_returns_pending_items(self, client, accountant_token, mock_queue):
        mock_queue.get_pending_emails.return_value = [_make_queue_item()]

        resp = client.get("/api/v1/approval-queue", headers=_auth(accountant_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["items"][0]["invoice_number"] == "INV-001"

    def test_empty_queue(self, client, accountant_token, mock_queue):
        mock_queue.get_pending_emails.return_value = []
        resp = client.get("/api/v1/approval-queue", headers=_auth(accountant_token))
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_requires_auth(self, client):
        resp = client.get("/api/v1/approval-queue")
        assert resp.status_code == 401

    def test_site_manager_forbidden(self, client, site_manager_token):
        resp = client.get("/api/v1/approval-queue", headers=_auth(site_manager_token))
        assert resp.status_code == 403


# -------------------------------------------------------------------------
# POST /api/v1/approval-queue/{id}/approve
# -------------------------------------------------------------------------

class TestApprove:
    def test_approve_success(self, client, accountant_token, mock_queue):
        mock_queue.get_item.return_value = _make_queue_item("q-1")
        mock_queue.approve.return_value = True

        resp = client.post(
            "/api/v1/approval-queue/q-1/approve",
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["new_status"] == "approved"

    def test_approve_not_found(self, client, accountant_token, mock_queue):
        mock_queue.get_item.return_value = None
        resp = client.post(
            "/api/v1/approval-queue/q-999/approve",
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 404

    def test_approve_wrong_tenant(self, client, accountant_token, mock_queue):
        mock_queue.get_item.return_value = _make_queue_item("q-1", tenant_id="other-tenant")
        resp = client.post(
            "/api/v1/approval-queue/q-1/approve",
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 404

    def test_approve_already_approved(self, client, accountant_token, mock_queue):
        mock_queue.get_item.return_value = _make_queue_item("q-1")
        mock_queue.approve.return_value = False
        resp = client.post(
            "/api/v1/approval-queue/q-1/approve",
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 409

    def test_approve_forbidden_for_site_manager(self, client, site_manager_token):
        resp = client.post(
            "/api/v1/approval-queue/q-1/approve",
            headers=_auth(site_manager_token),
        )
        assert resp.status_code == 403


# -------------------------------------------------------------------------
# POST /api/v1/approval-queue/{id}/reject
# -------------------------------------------------------------------------

class TestReject:
    def test_reject_success(self, client, accountant_token, mock_queue):
        mock_queue.get_item.return_value = _make_queue_item("q-1")
        mock_queue.reject.return_value = True

        resp = client.post(
            "/api/v1/approval-queue/q-1/reject",
            json={"reason": "Email content is incorrect"},
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["new_status"] == "rejected"

    def test_reject_not_found(self, client, accountant_token, mock_queue):
        mock_queue.get_item.return_value = None
        resp = client.post(
            "/api/v1/approval-queue/q-999/reject",
            json={"reason": "Some valid reason here"},
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 404

    def test_reject_reason_too_short(self, client, accountant_token):
        resp = client.post(
            "/api/v1/approval-queue/q-1/reject",
            json={"reason": "no"},
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 422

    def test_reject_missing_reason(self, client, accountant_token):
        resp = client.post(
            "/api/v1/approval-queue/q-1/reject",
            json={},
            headers=_auth(accountant_token),
        )
        assert resp.status_code == 422


class TestSendApproved:
    def test_send_approved_success(self, client, accountant_token):
        with patch("api.approval.send_approved_queue_items") as mock_send:
            mock_send.return_value = {
                "processed": 1,
                "sent": 1,
                "failed": 0,
                "skipped": 0,
                "items": [
                    {
                        "item_id": "q-1",
                        "invoice_number": "INV-001",
                        "status": "sent",
                        "detail": "Email sent",
                        "upload_url": "https://example.com/upload",
                    }
                ],
            }
            resp = client.post(
                "/api/v1/approval-queue/send-approved",
                headers=_auth(accountant_token),
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["sent"] == 1
        assert data["items"][0]["status"] == "sent"

    def test_send_approved_forbidden_for_site_manager(self, client, site_manager_token):
        resp = client.post(
            "/api/v1/approval-queue/send-approved",
            headers=_auth(site_manager_token),
        )
        assert resp.status_code == 403
