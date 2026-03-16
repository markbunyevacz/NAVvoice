"""
Tests for api/stats.py -- dashboard statistics endpoint.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from api import deps
from auth import AuthService, AuthConfig, UserRole
from approval_queue import QueueStatistics


@pytest.fixture(autouse=True)
def _reset():
    deps.reset_singletons()
    yield
    deps.reset_singletons()


@pytest.fixture
def auth_service():
    svc = AuthService(AuthConfig(secret_key="test-key-stats"))
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
def mock_db():
    db = MagicMock()
    db.get_statistics.return_value = {
        "tenant_id": "t-001",
        "total_invoices": 42,
        "critical_missing": 3,
        "by_status": {
            "MISSING": {"count": 10, "total_amount": 500000},
            "RECEIVED": {"count": 30, "total_amount": 2000000},
            "EMAILED": {"count": 2, "total_amount": 100000},
        },
    }
    return db


@pytest.fixture
def mock_queue():
    q = MagicMock()
    q.get_statistics.return_value = QueueStatistics(
        total=15,
        pending=5,
        approved=4,
        rejected=2,
        sent=3,
        expired=1,
        avg_approval_time_hours=2.5,
        oldest_pending_hours=12.0,
    )
    return q


@pytest.fixture
def client(auth_service, mock_db, mock_queue):
    app.dependency_overrides[deps.get_auth_service] = lambda: auth_service
    app.dependency_overrides[deps.get_db] = lambda: mock_db
    app.dependency_overrides[deps.get_approval_queue] = lambda: mock_queue
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


class TestDashboardStats:
    def test_returns_combined_stats(self, client, accountant_token, mock_db, mock_queue):
        resp = client.get("/api/v1/stats", headers=_auth(accountant_token))
        assert resp.status_code == 200
        data = resp.json()

        assert data["invoices"]["total_invoices"] == 42
        assert data["invoices"]["critical_missing"] == 3
        assert "MISSING" in data["invoices"]["by_status"]

        assert data["approval_queue"]["total"] == 15
        assert data["approval_queue"]["pending"] == 5
        assert data["approval_queue"]["avg_approval_time_hours"] == 2.5

    def test_requires_auth(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 401

    def test_site_manager_can_view(self, client, site_manager_token):
        resp = client.get("/api/v1/stats", headers=_auth(site_manager_token))
        assert resp.status_code == 200
