"""
Tests for api/projects.py -- tenant-scoped project listing and maintenance.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import app
from api import deps
from auth import AuthService, AuthConfig, UserRole


def _make_auth_service():
    return AuthService(AuthConfig(secret_key="test-key-projects"))


def _register_and_token(svc, email, password, role, tenant_id="t-001"):
    svc.register(email=email, password=password, role=role, tenant_id=tenant_id, name="Test")
    return svc.login(email, password)["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _reset():
    deps.reset_singletons()
    yield
    deps.reset_singletons()


@pytest.fixture
def auth_service():
    return _make_auth_service()


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.db_path = "data/invoices.db"
    db.initialize = MagicMock()
    return db


@pytest.fixture
def client(auth_service, mock_db):
    app.dependency_overrides[deps.get_auth_service] = lambda: auth_service
    app.dependency_overrides[deps.get_db] = lambda: mock_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def accountant_token(auth_service):
    return _register_and_token(
        auth_service, "acc-project@test.hu", "Passw0rd!Strong", UserRole.ACCOUNTANT
    )


@pytest.fixture
def site_manager_token(auth_service):
    return _register_and_token(
        auth_service, "site-project@test.hu", "Passw0rd!Strong", UserRole.SITE_MANAGER
    )


class TestProjectsApi:
    def test_list_projects_returns_items(self, client, accountant_token, mock_db):
        mock_db.list_projects.return_value = [
            {
                "id": 1,
                "tenant_id": "t-001",
                "project_code": "PRJ-001",
                "project_name": "Pilot Project",
                "aliases": "Munkaszám 001",
                "reference_patterns": "MSZ-001",
                "is_active": 1,
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-02T00:00:00",
            }
        ]

        resp = client.get("/api/v1/projects", headers=_auth(accountant_token))

        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["items"][0]["project_code"] == "PRJ-001"
        mock_db.list_projects.assert_called_once_with("t-001", include_inactive=False)

    def test_create_project(self, client, accountant_token, mock_db):
        mock_db.create_project.return_value = {
            "id": 2,
            "tenant_id": "t-001",
            "project_code": "PRJ-002",
            "project_name": "New Project",
            "aliases": None,
            "reference_patterns": None,
            "is_active": 1,
            "created_at": "2024-01-01T00:00:00",
            "updated_at": "2024-01-01T00:00:00",
        }

        resp = client.post(
            "/api/v1/projects",
            headers=_auth(accountant_token),
            json={"project_code": "PRJ-002", "project_name": "New Project"},
        )

        assert resp.status_code == 201
        assert resp.json()["project_code"] == "PRJ-002"
        mock_db.create_project.assert_called_once()

    def test_update_project(self, client, accountant_token, mock_db):
        mock_db.update_project.return_value = {
            "id": 2,
            "tenant_id": "t-001",
            "project_code": "PRJ-002",
            "project_name": "Updated Project",
            "aliases": None,
            "reference_patterns": None,
            "is_active": 1,
            "created_at": "2024-01-01T00:00:00",
            "updated_at": "2024-01-03T00:00:00",
        }

        resp = client.patch(
            "/api/v1/projects/2",
            headers=_auth(accountant_token),
            json={"project_name": "Updated Project"},
        )

        assert resp.status_code == 200
        assert resp.json()["project_name"] == "Updated Project"

    def test_site_manager_cannot_create_project(self, client, site_manager_token):
        resp = client.post(
            "/api/v1/projects",
            headers=_auth(site_manager_token),
            json={"project_code": "PRJ-003", "project_name": "Forbidden"},
        )

        assert resp.status_code == 403
