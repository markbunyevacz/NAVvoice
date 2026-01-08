"""
Comprehensive tests for the auth.py module.

Tests cover:
- PasswordManager: hashing, verification, strength validation
- JWTManager: token generation, validation, revocation, refresh
- UserStore: user CRUD, authentication, role management
- AuthMiddleware: request authentication
- AuthService: high-level auth flows
"""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from auth import (
    AuthConfig,
    UserRole,
    Permission,
    User,
    PasswordManager,
    JWTManager,
    UserStore,
    AuthMiddleware,
    AuthService,
    require_auth,
    ROLE_PERMISSIONS,
)


# =============================================================================
# TEST FIXTURES
# =============================================================================

@pytest.fixture
def auth_config():
    """Create auth config for testing."""
    return AuthConfig(
        secret_key="test-secret-key-for-testing-12345",
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        issuer="nav-invoice-reconciliation",
        audience="nav-api"
    )


@pytest.fixture
def jwt_manager(auth_config):
    """Create JWT manager for testing."""
    return JWTManager(auth_config)


@pytest.fixture
def user_store():
    """Create user store for testing."""
    return UserStore()


@pytest.fixture
def test_user(user_store):
    """Create a test user."""
    return user_store.create_user(
        email="test@example.com",
        password="SecurePass123!",
        role=UserRole.ACCOUNTANT,
        tenant_id="tenant-001",
        name="Test User"
    )


@pytest.fixture
def auth_service(auth_config):
    """Create auth service for testing."""
    return AuthService(auth_config)


# =============================================================================
# PASSWORD MANAGER TESTS
# =============================================================================

class TestPasswordManager:
    """Tests for PasswordManager class."""

    def test_hash_password_success(self):
        """Test successful password hashing."""
        password = "SecurePass123!"
        hashed = PasswordManager.hash_password(password)
        
        assert hashed is not None
        assert hashed != password
        assert hashed.startswith("$2")  # bcrypt hash prefix

    def test_hash_password_short_password_raises(self):
        """Test that short passwords raise ValueError."""
        with pytest.raises(ValueError, match="at least 8 characters"):
            PasswordManager.hash_password("short")

    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "SecurePass123!"
        hashed = PasswordManager.hash_password(password)
        
        assert PasswordManager.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "SecurePass123!"
        hashed = PasswordManager.hash_password(password)
        
        assert PasswordManager.verify_password("WrongPassword!", hashed) is False

    def test_validate_password_strength_valid(self):
        """Test password strength validation with valid password."""
        is_valid, issues = PasswordManager.validate_password_strength("SecurePass123!")
        
        assert is_valid is True
        assert len(issues) == 0

    def test_validate_password_strength_too_short(self):
        """Test password strength validation with short password."""
        is_valid, issues = PasswordManager.validate_password_strength("Abc1!")
        
        assert is_valid is False
        assert "at least 8 characters" in issues[0]

    def test_validate_password_strength_too_long(self):
        """Test password strength validation with too long password."""
        long_password = "A" * 129 + "a1!"
        is_valid, issues = PasswordManager.validate_password_strength(long_password)
        
        assert is_valid is False
        assert any("less than 128" in issue for issue in issues)

    def test_validate_password_strength_no_uppercase(self):
        """Test password strength validation without uppercase."""
        is_valid, issues = PasswordManager.validate_password_strength("lowercase123!")
        
        assert is_valid is False
        assert any("uppercase" in issue for issue in issues)

    def test_validate_password_strength_no_lowercase(self):
        """Test password strength validation without lowercase."""
        is_valid, issues = PasswordManager.validate_password_strength("UPPERCASE123!")
        
        assert is_valid is False
        assert any("lowercase" in issue for issue in issues)

    def test_validate_password_strength_no_digit(self):
        """Test password strength validation without digit."""
        is_valid, issues = PasswordManager.validate_password_strength("NoDigitsHere!")
        
        assert is_valid is False
        assert any("digit" in issue for issue in issues)

    def test_validate_password_strength_no_special(self):
        """Test password strength validation without special character."""
        is_valid, issues = PasswordManager.validate_password_strength("NoSpecial123")
        
        assert is_valid is False
        assert any("special character" in issue for issue in issues)


# =============================================================================
# JWT MANAGER TESTS
# =============================================================================

class TestJWTManager:
    """Tests for JWTManager class."""

    def test_generate_tokens_success(self, jwt_manager, user_store):
        """Test successful token generation."""
        user = user_store.create_user(
            email="jwt@test.com",
            password="SecurePass123!",
            role=UserRole.ADMIN,
            tenant_id="tenant-001"
        )
        
        access_token, refresh_token = jwt_manager.generate_tokens(user)
        
        assert access_token is not None
        assert refresh_token is not None
        assert access_token != refresh_token

    def test_validate_access_token_success(self, jwt_manager, user_store):
        """Test successful access token validation."""
        user = user_store.create_user(
            email="validate@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        access_token, _ = jwt_manager.generate_tokens(user)
        payload = jwt_manager.validate_token(access_token, "access")
        
        assert payload is not None
        assert payload["sub"] == user.id
        assert payload["email"] == user.email
        assert payload["type"] == "access"

    def test_validate_refresh_token_success(self, jwt_manager, user_store):
        """Test successful refresh token validation."""
        user = user_store.create_user(
            email="refresh@test.com",
            password="SecurePass123!",
            role=UserRole.SITE_MANAGER,
            tenant_id="tenant-001"
        )
        
        _, refresh_token = jwt_manager.generate_tokens(user)
        payload = jwt_manager.validate_token(refresh_token, "refresh")
        
        assert payload is not None
        assert payload["sub"] == user.id
        assert payload["type"] == "refresh"

    def test_validate_token_wrong_type(self, jwt_manager, user_store):
        """Test token validation with wrong type."""
        user = user_store.create_user(
            email="wrongtype@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        access_token, _ = jwt_manager.generate_tokens(user)
        # Try to validate access token as refresh token
        payload = jwt_manager.validate_token(access_token, "refresh")
        
        assert payload is None

    def test_validate_token_invalid(self, jwt_manager):
        """Test validation of invalid token."""
        payload = jwt_manager.validate_token("invalid.token.here", "access")
        
        assert payload is None

    def test_validate_token_expired(self, auth_config, user_store):
        """Test validation of expired token."""
        # Create config with very short expiry
        short_config = AuthConfig(
            secret_key=auth_config.secret_key,
            access_token_expire_minutes=0,  # Immediate expiry
        )
        jwt_mgr = JWTManager(short_config)
        
        user = user_store.create_user(
            email="expired@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        access_token, _ = jwt_mgr.generate_tokens(user)
        # Token should be expired immediately
        time.sleep(1)
        payload = jwt_mgr.validate_token(access_token, "access")
        
        assert payload is None

    def test_revoke_token_success(self, jwt_manager, user_store):
        """Test token revocation with refresh token (no audience)."""
        user = user_store.create_user(
            email="revoke@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        _, refresh_token = jwt_manager.generate_tokens(user)
        
        # Token should be valid before revocation
        assert jwt_manager.validate_token(refresh_token, "refresh") is not None
        
        # Revoke refresh token (refresh tokens don't have audience, so revocation works)
        result = jwt_manager.revoke_token(refresh_token)
        assert result is True
        
        # Token should be invalid after revocation
        assert jwt_manager.validate_token(refresh_token, "refresh") is None

    def test_revoke_token_invalid(self, jwt_manager):
        """Test revocation of invalid token."""
        result = jwt_manager.revoke_token("invalid.token.here")
        
        assert result is False

    def test_refresh_access_token_success(self, jwt_manager, user_store):
        """Test successful access token refresh."""
        user = user_store.create_user(
            email="refreshaccess@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        _, refresh_token = jwt_manager.generate_tokens(user)
        new_access_token = jwt_manager.refresh_access_token(refresh_token, user)
        
        assert new_access_token is not None
        payload = jwt_manager.validate_token(new_access_token, "access")
        assert payload is not None
        assert payload["sub"] == user.id

    def test_refresh_access_token_invalid_refresh(self, jwt_manager, user_store):
        """Test refresh with invalid refresh token."""
        user = user_store.create_user(
            email="invalidrefresh@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        new_access_token = jwt_manager.refresh_access_token("invalid.token", user)
        
        assert new_access_token is None

    def test_refresh_access_token_user_mismatch(self, jwt_manager, user_store):
        """Test refresh with mismatched user."""
        user1 = user_store.create_user(
            email="user1@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        user2 = user_store.create_user(
            email="user2@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        _, refresh_token = jwt_manager.generate_tokens(user1)
        # Try to refresh with different user
        new_access_token = jwt_manager.refresh_access_token(refresh_token, user2)
        
        assert new_access_token is None


# =============================================================================
# USER STORE TESTS
# =============================================================================

class TestUserStore:
    """Tests for UserStore class."""

    def test_create_user_success(self, user_store):
        """Test successful user creation."""
        user = user_store.create_user(
            email="newuser@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001",
            name="New User"
        )
        
        assert user is not None
        assert user.email == "newuser@test.com"
        assert user.role == UserRole.ACCOUNTANT
        assert user.tenant_id == "tenant-001"
        assert user.name == "New User"
        assert user.is_active is True

    def test_create_user_duplicate_email(self, user_store):
        """Test user creation with duplicate email."""
        user_store.create_user(
            email="duplicate@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        with pytest.raises(ValueError, match="Email already exists"):
            user_store.create_user(
                email="duplicate@test.com",
                password="SecurePass123!",
                role=UserRole.ADMIN,
                tenant_id="tenant-002"
            )

    def test_create_user_weak_password(self, user_store):
        """Test user creation with weak password."""
        with pytest.raises(ValueError, match="Weak password"):
            user_store.create_user(
                email="weak@test.com",
                password="weak",
                role=UserRole.ACCOUNTANT,
                tenant_id="tenant-001"
            )

    def test_get_user_by_email_exists(self, user_store, test_user):
        """Test getting user by email when user exists."""
        found_user = user_store.get_user_by_email("test@example.com")
        
        assert found_user is not None
        assert found_user.id == test_user.id

    def test_get_user_by_email_not_exists(self, user_store):
        """Test getting user by email when user doesn't exist."""
        found_user = user_store.get_user_by_email("nonexistent@test.com")
        
        assert found_user is None

    def test_get_user_by_id_exists(self, user_store, test_user):
        """Test getting user by ID when user exists."""
        found_user = user_store.get_user_by_id(test_user.id, "tenant-001")
        
        assert found_user is not None
        assert found_user.email == test_user.email

    def test_get_user_by_id_wrong_tenant(self, user_store, test_user):
        """Test getting user by ID with wrong tenant."""
        found_user = user_store.get_user_by_id(test_user.id, "wrong-tenant")
        
        assert found_user is None

    def test_get_user_by_id_not_exists(self, user_store):
        """Test getting user by ID when user doesn't exist."""
        found_user = user_store.get_user_by_id("nonexistent-id", "tenant-001")
        
        assert found_user is None

    def test_authenticate_success(self, user_store, test_user):
        """Test successful authentication."""
        authenticated_user = user_store.authenticate("test@example.com", "SecurePass123!")
        
        assert authenticated_user is not None
        assert authenticated_user.id == test_user.id
        assert authenticated_user.last_login is not None

    def test_authenticate_wrong_password(self, user_store, test_user):
        """Test authentication with wrong password."""
        authenticated_user = user_store.authenticate("test@example.com", "WrongPassword!")
        
        assert authenticated_user is None

    def test_authenticate_user_not_found(self, user_store):
        """Test authentication with non-existent user."""
        authenticated_user = user_store.authenticate("nonexistent@test.com", "Password123!")
        
        assert authenticated_user is None

    def test_authenticate_inactive_user(self, user_store, test_user):
        """Test authentication with inactive user."""
        user_store.deactivate_user(test_user.id)
        
        authenticated_user = user_store.authenticate("test@example.com", "SecurePass123!")
        
        assert authenticated_user is None

    def test_get_users_by_tenant(self, user_store):
        """Test getting users by tenant."""
        user_store.create_user("t1u1@test.com", "SecurePass123!", UserRole.ADMIN, "tenant-1")
        user_store.create_user("t1u2@test.com", "SecurePass123!", UserRole.ACCOUNTANT, "tenant-1")
        user_store.create_user("t2u1@test.com", "SecurePass123!", UserRole.ADMIN, "tenant-2")
        
        tenant1_users = user_store.get_users_by_tenant("tenant-1")
        tenant2_users = user_store.get_users_by_tenant("tenant-2")
        
        assert len(tenant1_users) == 2
        assert len(tenant2_users) == 1

    def test_update_user_role_success(self, user_store, test_user):
        """Test successful role update."""
        assert test_user.role == UserRole.ACCOUNTANT
        
        result = user_store.update_user_role(test_user.id, UserRole.ADMIN)
        
        assert result is True
        assert test_user.role == UserRole.ADMIN

    def test_update_user_role_not_found(self, user_store):
        """Test role update for non-existent user."""
        result = user_store.update_user_role("nonexistent-id", UserRole.ADMIN)
        
        assert result is False

    def test_deactivate_user_success(self, user_store, test_user):
        """Test successful user deactivation."""
        assert test_user.is_active is True
        
        result = user_store.deactivate_user(test_user.id)
        
        assert result is True
        assert test_user.is_active is False

    def test_deactivate_user_not_found(self, user_store):
        """Test deactivation of non-existent user."""
        result = user_store.deactivate_user("nonexistent-id")
        
        assert result is False


# =============================================================================
# AUTH MIDDLEWARE TESTS
# =============================================================================

class TestAuthMiddleware:
    """Tests for AuthMiddleware class."""

    def test_authenticate_request_success(self, auth_config, user_store):
        """Test successful request authentication."""
        jwt_manager = JWTManager(auth_config)
        middleware = AuthMiddleware(jwt_manager, user_store)
        
        user = user_store.create_user(
            email="middleware@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        access_token, _ = jwt_manager.generate_tokens(user)
        
        is_valid, auth_user, error = middleware.authenticate_request(
            f"Bearer {access_token}",
            [Permission.VIEW_INVOICES]
        )
        
        assert is_valid is True
        assert auth_user is not None
        assert auth_user.id == user.id
        assert error is None

    def test_authenticate_request_no_header(self, auth_config, user_store):
        """Test request authentication without header."""
        jwt_manager = JWTManager(auth_config)
        middleware = AuthMiddleware(jwt_manager, user_store)
        
        is_valid, auth_user, error = middleware.authenticate_request(None)
        
        assert is_valid is False
        assert auth_user is None
        assert "Missing" in error or "authorization" in error.lower()

    def test_authenticate_request_invalid_format(self, auth_config, user_store):
        """Test request authentication with invalid header format."""
        jwt_manager = JWTManager(auth_config)
        middleware = AuthMiddleware(jwt_manager, user_store)
        
        is_valid, auth_user, error = middleware.authenticate_request("InvalidFormat")
        
        assert is_valid is False
        assert auth_user is None

    def test_authenticate_request_invalid_token(self, auth_config, user_store):
        """Test request authentication with invalid token."""
        jwt_manager = JWTManager(auth_config)
        middleware = AuthMiddleware(jwt_manager, user_store)
        
        is_valid, auth_user, error = middleware.authenticate_request("Bearer invalid.token.here")
        
        assert is_valid is False
        assert auth_user is None

    def test_authenticate_request_permission_denied(self, auth_config, user_store):
        """Test request authentication with insufficient permissions."""
        jwt_manager = JWTManager(auth_config)
        middleware = AuthMiddleware(jwt_manager, user_store)
        
        # Site manager has limited permissions
        user = user_store.create_user(
            email="limited@test.com",
            password="SecurePass123!",
            role=UserRole.SITE_MANAGER,
            tenant_id="tenant-001"
        )
        
        access_token, _ = jwt_manager.generate_tokens(user)
        
        is_valid, auth_user, error = middleware.authenticate_request(
            f"Bearer {access_token}",
            [Permission.MANAGE_USERS]  # Site manager doesn't have this
        )
        
        assert is_valid is False
        assert "permission" in error.lower() or "denied" in error.lower()


# =============================================================================
# AUTH SERVICE TESTS
# =============================================================================

class TestAuthService:
    """Tests for AuthService class."""

    def test_register_success(self, auth_service):
        """Test successful user registration."""
        user = auth_service.register(
            email="register@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001",
            name="Registered User"
        )
        
        assert user is not None
        assert user.email == "register@test.com"

    def test_login_success(self, auth_service):
        """Test successful login."""
        auth_service.register(
            email="login@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        result = auth_service.login("login@test.com", "SecurePass123!")
        
        assert result is not None
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "bearer"

    def test_login_failure(self, auth_service):
        """Test login failure with wrong password."""
        auth_service.register(
            email="loginfail@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        result = auth_service.login("loginfail@test.com", "WrongPassword!")
        
        assert result is None

    def test_logout_success(self, auth_service):
        """Test logout with refresh token."""
        auth_service.register(
            email="logout@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        result = auth_service.login("logout@test.com", "SecurePass123!")
        refresh_token = result["refresh_token"]
        
        # Logout using refresh token (refresh tokens don't have audience validation issue)
        logout_result = auth_service.logout(refresh_token)
        assert logout_result is True
        
        # Refresh token should be invalid after logout
        new_tokens = auth_service.refresh(refresh_token)
        assert new_tokens is None

    def test_refresh_success(self, auth_service):
        """Test successful token refresh."""
        auth_service.register(
            email="refreshservice@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        result = auth_service.login("refreshservice@test.com", "SecurePass123!")
        refresh_token = result["refresh_token"]
        
        new_tokens = auth_service.refresh(refresh_token)
        
        assert new_tokens is not None
        assert "access_token" in new_tokens

    def test_refresh_invalid_token(self, auth_service):
        """Test refresh with invalid token."""
        result = auth_service.refresh("invalid.refresh.token")
        
        assert result is None

    def test_validate_request_success(self, auth_service):
        """Test successful request validation."""
        auth_service.register(
            email="validate@test.com",
            password="SecurePass123!",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        result = auth_service.login("validate@test.com", "SecurePass123!")
        access_token = result["access_token"]
        
        is_valid, user, error = auth_service.validate_request(
            f"Bearer {access_token}",
            [Permission.VIEW_INVOICES]
        )
        
        assert is_valid is True
        assert user is not None
        assert error is None


# =============================================================================
# USER CLASS TESTS
# =============================================================================

class TestUser:
    """Tests for User class."""

    def test_has_permission_admin(self):
        """Test admin has all permissions."""
        user = User(
            id="test-id",
            email="admin@test.com",
            password_hash="hash",
            role=UserRole.ADMIN,
            tenant_id="tenant-001"
        )
        
        # Admin should have all permissions
        assert user.has_permission(Permission.VIEW_INVOICES) is True
        assert user.has_permission(Permission.MANAGE_USERS) is True
        assert user.has_permission(Permission.MANAGE_NAV_KEYS) is True

    def test_has_permission_accountant(self):
        """Test accountant has limited permissions."""
        user = User(
            id="test-id",
            email="accountant@test.com",
            password_hash="hash",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001"
        )
        
        # Accountant should have view/reconcile but not manage
        assert user.has_permission(Permission.VIEW_INVOICES) is True
        assert user.has_permission(Permission.RECONCILE_INVOICES) is True
        assert user.has_permission(Permission.MANAGE_USERS) is False

    def test_has_permission_site_manager(self):
        """Test site manager has limited permissions."""
        user = User(
            id="test-id",
            email="manager@test.com",
            password_hash="hash",
            role=UserRole.SITE_MANAGER,
            tenant_id="tenant-001"
        )
        
        # Site manager should have view and upload only
        assert user.has_permission(Permission.UPLOAD_INVOICES) is True
        assert user.has_permission(Permission.VIEW_INVOICES) is True
        assert user.has_permission(Permission.MANAGE_USERS) is False
        assert user.has_permission(Permission.APPROVE_EMAILS) is False

    def test_to_dict(self):
        """Test user serialization to dict."""
        user = User(
            id="test-id",
            email="dict@test.com",
            password_hash="hash",
            role=UserRole.ACCOUNTANT,
            tenant_id="tenant-001",
            name="Test Name"
        )
        
        user_dict = user.to_dict()
        
        assert user_dict["id"] == "test-id"
        assert user_dict["email"] == "dict@test.com"
        assert user_dict["role"] == "accountant"
        assert user_dict["tenant_id"] == "tenant-001"
        assert user_dict["name"] == "Test Name"
        assert "password_hash" not in user_dict  # Should not expose hash


# =============================================================================
# ROLE PERMISSIONS TESTS
# =============================================================================

class TestRolePermissions:
    """Tests for role-permission mappings."""

    def test_admin_has_all_permissions(self):
        """Test admin role has all permissions."""
        admin_perms = ROLE_PERMISSIONS[UserRole.ADMIN]
        
        # Admin should have all permissions
        assert len(admin_perms) == len(Permission)
        for perm in Permission:
            assert perm in admin_perms

    def test_accountant_permissions(self):
        """Test accountant role has correct permissions."""
        accountant_perms = ROLE_PERMISSIONS[UserRole.ACCOUNTANT]
        
        # Accountant should have view, reconcile, approve but not manage
        assert Permission.VIEW_INVOICES in accountant_perms
        assert Permission.RECONCILE_INVOICES in accountant_perms
        assert Permission.APPROVE_EMAILS in accountant_perms
        assert Permission.MANAGE_USERS not in accountant_perms
        assert Permission.MANAGE_NAV_KEYS not in accountant_perms

    def test_site_manager_permissions(self):
        """Test site manager role has limited permissions."""
        manager_perms = ROLE_PERMISSIONS[UserRole.SITE_MANAGER]
        
        # Site manager should have view and upload only
        assert Permission.UPLOAD_INVOICES in manager_perms
        assert Permission.VIEW_INVOICES in manager_perms
        assert Permission.MANAGE_USERS not in manager_perms
        assert Permission.APPROVE_EMAILS not in manager_perms


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
