"""
Tests for api/auth.py -- login and refresh endpoints.

All tests use a real in-memory AuthService (no external deps).
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from api import deps
from auth import AuthService, AuthConfig, UserRole


@pytest.fixture(autouse=True)
def _reset():
    deps.reset_singletons()
    yield
    deps.reset_singletons()


@pytest.fixture
def auth_service():
    svc = AuthService(AuthConfig(secret_key="test-secret-key-fixed"))
    svc.register(
        email="accountant@test.hu",
        password="Passw0rd!Strong",
        role=UserRole.ACCOUNTANT,
        tenant_id="t-001",
        name="Test Accountant",
    )
    return svc


@pytest.fixture
def client(auth_service):
    app.dependency_overrides[deps.get_auth_service] = lambda: auth_service
    yield TestClient(app)
    app.dependency_overrides.clear()


class TestLogin:
    def test_login_success(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "accountant@test.hu", "password": "Passw0rd!Strong"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0
        assert data["user"]["email"] == "accountant@test.hu"
        assert data["user"]["role"] == "accountant"

    def test_login_wrong_password(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "accountant@test.hu", "password": "WrongPass1!"},
        )
        assert resp.status_code == 401
        assert "Invalid" in resp.json()["detail"]

    def test_login_unknown_user(self, client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@test.hu", "password": "Whatever1!"},
        )
        assert resp.status_code == 401

    def test_login_missing_fields(self, client):
        resp = client.post("/api/v1/auth/login", json={"email": "x@x.com"})
        assert resp.status_code == 422


class TestRefresh:
    def test_refresh_success(self, client):
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"email": "accountant@test.hu", "password": "Passw0rd!Strong"},
        )
        refresh_token = login_resp.json()["refresh_token"]

        resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_refresh_invalid_token(self, client):
        resp = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "bad.token.value"},
        )
        assert resp.status_code == 401

    def test_refresh_missing_field(self, client):
        resp = client.post("/api/v1/auth/refresh", json={})
        assert resp.status_code == 422
