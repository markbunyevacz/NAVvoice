"""
Comprehensive Unit Tests for NAV Secret Manager Module

Tests cover:
- SecretManagerConfig: Configuration and secret name generation
- CachedSecret: TTL-based caching with expiration
- NavSecretManager: Credential storage, retrieval, rotation, and caching
- Custom exceptions: SecretNotFoundError, SecretAccessError, SecretParseError

Run with: pytest test_nav_secret_manager.py -v
"""

import pytest
import json
import time
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from datetime import datetime, timedelta
from threading import Thread

from nav_client import NavCredentials


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def valid_credentials():
    """Valid NAV credentials for testing."""
    return NavCredentials(
        login="test_user",
        password="test_password",
        signature_key="12345678901234567890123456789012",
        replacement_key="abcdefghijklmnopqrstuvwxyz123456",
        tax_number="12345678"
    )


@pytest.fixture
def credentials_json():
    """JSON representation of credentials."""
    return json.dumps({
        "login": "test_user",
        "password": "test_password",
        "signature_key": "12345678901234567890123456789012",
        "replacement_key": "abcdefghijklmnopqrstuvwxyz123456",
        "tax_number": "12345678",
        "stored_at": "2024-01-15T10:00:00"
    })


@pytest.fixture
def mock_secret_manager_client():
    """Mock Google Cloud Secret Manager client."""
    with patch('nav_secret_manager.secretmanager.SecretManagerServiceClient') as mock_class:
        mock_client = MagicMock()
        mock_class.return_value = mock_client
        yield mock_client


# =============================================================================
# SECRET MANAGER CONFIG TESTS
# =============================================================================

class TestSecretManagerConfig:
    """Test SecretManagerConfig dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        from nav_secret_manager import SecretManagerConfig
        
        config = SecretManagerConfig(project_id="test-project")
        
        assert config.project_id == "test-project"
        assert config.cache_ttl_seconds == 300
        assert config.enable_caching is True
        assert config.secret_prefix == "nav-credentials"

    def test_custom_values(self):
        """Should accept custom values."""
        from nav_secret_manager import SecretManagerConfig
        
        config = SecretManagerConfig(
            project_id="custom-project",
            cache_ttl_seconds=600,
            enable_caching=False,
            secret_prefix="custom-prefix"
        )
        
        assert config.project_id == "custom-project"
        assert config.cache_ttl_seconds == 600
        assert config.enable_caching is False
        assert config.secret_prefix == "custom-prefix"

    def test_get_secret_name(self):
        """Should generate correct secret resource name."""
        from nav_secret_manager import SecretManagerConfig
        
        config = SecretManagerConfig(project_id="my-project")
        secret_name = config.get_secret_name("tenant-123")
        
        assert secret_name == "projects/my-project/secrets/nav-credentials-tenant-123/versions/latest"

    def test_get_secret_name_custom_prefix(self):
        """Should use custom prefix in secret name."""
        from nav_secret_manager import SecretManagerConfig
        
        config = SecretManagerConfig(project_id="my-project", secret_prefix="custom")
        secret_name = config.get_secret_name("tenant-456")
        
        assert secret_name == "projects/my-project/secrets/custom-tenant-456/versions/latest"

    def test_get_secret_id(self):
        """Should generate correct secret ID without version."""
        from nav_secret_manager import SecretManagerConfig
        
        config = SecretManagerConfig(project_id="my-project")
        secret_id = config.get_secret_id("tenant-789")
        
        assert secret_id == "nav-credentials-tenant-789"


# =============================================================================
# CACHED SECRET TESTS
# =============================================================================

class TestCachedSecret:
    """Test CachedSecret TTL-based caching."""

    def test_is_expired_false_when_fresh(self, valid_credentials):
        """Should not be expired when freshly created."""
        from nav_secret_manager import CachedSecret
        
        cached = CachedSecret(
            credentials=valid_credentials,
            fetched_at=datetime.now(),
            ttl_seconds=300
        )
        
        assert cached.is_expired is False

    def test_is_expired_true_after_ttl(self, valid_credentials):
        """Should be expired after TTL passes."""
        from nav_secret_manager import CachedSecret
        
        cached = CachedSecret(
            credentials=valid_credentials,
            fetched_at=datetime.now() - timedelta(seconds=400),
            ttl_seconds=300
        )
        
        assert cached.is_expired is True

    def test_is_expired_boundary(self, valid_credentials):
        """Should handle boundary conditions correctly."""
        from nav_secret_manager import CachedSecret
        
        # Exactly at TTL boundary - should be expired
        cached = CachedSecret(
            credentials=valid_credentials,
            fetched_at=datetime.now() - timedelta(seconds=300),
            ttl_seconds=300
        )
        
        assert cached.is_expired is True

    def test_stores_credentials(self, valid_credentials):
        """Should store credentials correctly."""
        from nav_secret_manager import CachedSecret
        
        cached = CachedSecret(
            credentials=valid_credentials,
            fetched_at=datetime.now(),
            ttl_seconds=300
        )
        
        assert cached.credentials.login == "test_user"
        assert cached.credentials.tax_number == "12345678"


# =============================================================================
# NAV SECRET MANAGER TESTS
# =============================================================================

class TestNavSecretManager:
    """Test NavSecretManager credential management."""

    @pytest.fixture
    def secret_manager(self, mock_secret_manager_client):
        """NavSecretManager instance with mocked GCP client."""
        from nav_secret_manager import SecretManagerConfig, NavSecretManager
        
        config = SecretManagerConfig(
            project_id="test-project",
            cache_ttl_seconds=300,
            enable_caching=True
        )
        return NavSecretManager(config)

    @pytest.fixture
    def secret_manager_no_cache(self, mock_secret_manager_client):
        """NavSecretManager instance with caching disabled."""
        from nav_secret_manager import SecretManagerConfig, NavSecretManager
        
        config = SecretManagerConfig(
            project_id="test-project",
            enable_caching=False
        )
        return NavSecretManager(config)

    # =========================================================================
    # CREDENTIAL RETRIEVAL TESTS
    # =========================================================================

    def test_get_credentials_success(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should retrieve credentials successfully."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        credentials = secret_manager.get_credentials("tenant-001")
        
        assert credentials.login == "test_user"
        assert credentials.password == "test_password"
        assert credentials.tax_number == "12345678"

    def test_get_credentials_uses_cache(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should use cached credentials on second call."""
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # First call - fetches from Secret Manager
        secret_manager.get_credentials("tenant-001")
        
        # Second call - should use cache
        secret_manager.get_credentials("tenant-001")
        
        # Should only call Secret Manager once
        assert mock_secret_manager_client.access_secret_version.call_count == 1

    def test_get_credentials_bypass_cache(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should bypass cache when requested."""
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # First call
        secret_manager.get_credentials("tenant-001")
        
        # Second call with bypass_cache=True
        secret_manager.get_credentials("tenant-001", bypass_cache=True)
        
        # Should call Secret Manager twice
        assert mock_secret_manager_client.access_secret_version.call_count == 2

    def test_get_credentials_no_cache(self, secret_manager_no_cache, mock_secret_manager_client, credentials_json):
        """Should not use cache when caching is disabled."""
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # Multiple calls
        secret_manager_no_cache.get_credentials("tenant-001")
        secret_manager_no_cache.get_credentials("tenant-001")
        
        # Should call Secret Manager each time
        assert mock_secret_manager_client.access_secret_version.call_count == 2

    def test_get_credentials_not_found(self, secret_manager, mock_secret_manager_client):
        """Should raise SecretNotFoundError when credentials don't exist."""
        from google.api_core import exceptions as gcp_exceptions
        from nav_secret_manager import SecretNotFoundError
        
        mock_secret_manager_client.access_secret_version.side_effect = gcp_exceptions.NotFound("Not found")
        
        with pytest.raises(SecretNotFoundError) as exc_info:
            secret_manager.get_credentials("nonexistent-tenant")
        
        assert "nonexistent-tenant" in str(exc_info.value)

    def test_get_credentials_access_denied(self, secret_manager, mock_secret_manager_client):
        """Should raise SecretAccessError when access is denied."""
        from google.api_core import exceptions as gcp_exceptions
        from nav_secret_manager import SecretAccessError
        
        mock_secret_manager_client.access_secret_version.side_effect = gcp_exceptions.PermissionDenied("Access denied")
        
        with pytest.raises(SecretAccessError) as exc_info:
            secret_manager.get_credentials("restricted-tenant")
        
        assert "restricted-tenant" in str(exc_info.value)

    def test_get_credentials_invalid_json(self, secret_manager, mock_secret_manager_client):
        """Should raise SecretParseError for invalid JSON."""
        from nav_secret_manager import SecretParseError
        
        mock_response = MagicMock()
        mock_response.payload.data = b"invalid json"
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        with pytest.raises(SecretParseError):
            secret_manager.get_credentials("tenant-001")

    def test_get_credentials_missing_fields(self, secret_manager, mock_secret_manager_client):
        """Should raise SecretParseError for missing required fields."""
        from nav_secret_manager import SecretParseError
        
        incomplete_json = json.dumps({"login": "user"})  # Missing other fields
        mock_response = MagicMock()
        mock_response.payload.data = incomplete_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        with pytest.raises(SecretParseError):
            secret_manager.get_credentials("tenant-001")

    # =========================================================================
    # CREDENTIAL STORAGE TESTS
    # =========================================================================

    def test_store_credentials_new_secret(self, secret_manager, mock_secret_manager_client, valid_credentials):
        """Should create new secret when it doesn't exist."""
        from google.api_core import exceptions as gcp_exceptions
        
        # Secret doesn't exist
        mock_secret_manager_client.get_secret.side_effect = gcp_exceptions.NotFound("Not found")
        
        # Mock version response
        mock_version = MagicMock()
        mock_version.name = "projects/test-project/secrets/nav-credentials-tenant-001/versions/1"
        mock_secret_manager_client.add_secret_version.return_value = mock_version
        
        version = secret_manager.store_credentials("tenant-001", valid_credentials)
        
        # Should create secret first
        mock_secret_manager_client.create_secret.assert_called_once()
        # Then add version
        mock_secret_manager_client.add_secret_version.assert_called_once()
        assert "versions/1" in version

    def test_store_credentials_existing_secret(self, secret_manager, mock_secret_manager_client, valid_credentials):
        """Should add new version to existing secret."""
        # Secret exists
        mock_secret_manager_client.get_secret.return_value = MagicMock()
        
        mock_version = MagicMock()
        mock_version.name = "projects/test-project/secrets/nav-credentials-tenant-001/versions/2"
        mock_secret_manager_client.add_secret_version.return_value = mock_version
        
        version = secret_manager.store_credentials("tenant-001", valid_credentials)
        
        # Should not create secret
        mock_secret_manager_client.create_secret.assert_not_called()
        # Should add version
        mock_secret_manager_client.add_secret_version.assert_called_once()
        assert "versions/2" in version

    def test_store_credentials_with_labels(self, secret_manager, mock_secret_manager_client, valid_credentials):
        """Should include custom labels when creating secret."""
        from google.api_core import exceptions as gcp_exceptions
        
        mock_secret_manager_client.get_secret.side_effect = gcp_exceptions.NotFound("Not found")
        mock_version = MagicMock()
        mock_version.name = "projects/test-project/secrets/test/versions/1"
        mock_secret_manager_client.add_secret_version.return_value = mock_version
        
        secret_manager.store_credentials(
            "tenant-001",
            valid_credentials,
            labels={"environment": "production"}
        )
        
        # Verify labels were passed
        call_args = mock_secret_manager_client.create_secret.call_args
        secret_config = call_args[1]['secret']
        assert "environment" in secret_config['labels']

    def test_store_credentials_invalidates_cache(self, secret_manager, mock_secret_manager_client, valid_credentials, credentials_json):
        """Should invalidate cache after storing credentials."""
        # Setup initial cached credentials
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # Populate cache
        secret_manager.get_credentials("tenant-001")
        
        # Store new credentials
        mock_secret_manager_client.get_secret.return_value = MagicMock()
        mock_version = MagicMock()
        mock_version.name = "projects/test-project/secrets/test/versions/1"
        mock_secret_manager_client.add_secret_version.return_value = mock_version
        
        secret_manager.store_credentials("tenant-001", valid_credentials)
        
        # Next get should fetch from Secret Manager again
        secret_manager.get_credentials("tenant-001")
        
        # Should have called access_secret_version twice
        assert mock_secret_manager_client.access_secret_version.call_count == 2

    # =========================================================================
    # ROTATION TESTS
    # =========================================================================

    def test_rotate_credentials(self, secret_manager, mock_secret_manager_client, valid_credentials):
        """Should rotate credentials by adding new version."""
        mock_secret_manager_client.get_secret.return_value = MagicMock()
        mock_version = MagicMock()
        mock_version.name = "projects/test-project/secrets/test/versions/3"
        mock_secret_manager_client.add_secret_version.return_value = mock_version
        
        version = secret_manager.rotate_credentials("tenant-001", valid_credentials)
        
        assert "versions/3" in version
        mock_secret_manager_client.add_secret_version.assert_called_once()

    def test_rotate_credentials_adds_rotation_label(self, secret_manager, mock_secret_manager_client, valid_credentials):
        """Should add rotation timestamp label."""
        from google.api_core import exceptions as gcp_exceptions
        
        # Secret doesn't exist (will be created)
        mock_secret_manager_client.get_secret.side_effect = gcp_exceptions.NotFound("Not found")
        mock_version = MagicMock()
        mock_version.name = "projects/test-project/secrets/test/versions/1"
        mock_secret_manager_client.add_secret_version.return_value = mock_version
        
        secret_manager.rotate_credentials("tenant-001", valid_credentials)
        
        # Verify rotated-at label was added
        call_args = mock_secret_manager_client.create_secret.call_args
        secret_config = call_args[1]['secret']
        assert "rotated-at" in secret_config['labels']

    # =========================================================================
    # CACHE MANAGEMENT TESTS
    # =========================================================================

    def test_invalidate_cache_specific_tenant(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should invalidate cache for specific tenant."""
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # Populate cache for multiple tenants
        secret_manager.get_credentials("tenant-001")
        secret_manager.get_credentials("tenant-002")
        
        # Invalidate only tenant-001
        secret_manager.invalidate_cache("tenant-001")
        
        # tenant-001 should fetch again
        secret_manager.get_credentials("tenant-001")
        # tenant-002 should use cache
        secret_manager.get_credentials("tenant-002")
        
        # Should have 3 calls: initial tenant-001, initial tenant-002, re-fetch tenant-001
        assert mock_secret_manager_client.access_secret_version.call_count == 3

    def test_invalidate_cache_all(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should invalidate cache for all tenants."""
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # Populate cache
        secret_manager.get_credentials("tenant-001")
        secret_manager.get_credentials("tenant-002")
        
        # Invalidate all
        secret_manager.invalidate_cache()
        
        # Both should fetch again
        secret_manager.get_credentials("tenant-001")
        secret_manager.get_credentials("tenant-002")
        
        # Should have 4 calls total
        assert mock_secret_manager_client.access_secret_version.call_count == 4

    def test_cache_expiration(self, mock_secret_manager_client, credentials_json):
        """Should fetch again after cache expires."""
        from nav_secret_manager import SecretManagerConfig, NavSecretManager
        
        # Very short TTL for testing
        config = SecretManagerConfig(
            project_id="test-project",
            cache_ttl_seconds=1,  # 1 second TTL
            enable_caching=True
        )
        secret_manager = NavSecretManager(config)
        
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # First call
        secret_manager.get_credentials("tenant-001")
        
        # Wait for cache to expire
        time.sleep(1.5)
        
        # Second call should fetch again
        secret_manager.get_credentials("tenant-001")
        
        assert mock_secret_manager_client.access_secret_version.call_count == 2

    # =========================================================================
    # HELPER METHOD TESTS
    # =========================================================================

    def test_create_nav_client(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should create NavClient with stored credentials."""
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # Patch where NavClient is imported (inside the method)
        with patch('nav_client.NavClient') as mock_nav_client:
            secret_manager.create_nav_client("tenant-001", use_test_api=True)
            
            mock_nav_client.assert_called_once()
            call_kwargs = mock_nav_client.call_args[1]
            assert call_kwargs['use_test_api'] is True

    def test_create_nav_client_with_software_id(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should pass software_id to NavClient."""
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        # Patch where NavClient is imported (inside the method)
        with patch('nav_client.NavClient') as mock_nav_client:
            secret_manager.create_nav_client(
                "tenant-001",
                software_id="CUSTOM-SOFTWARE-ID"
            )
            
            call_kwargs = mock_nav_client.call_args[1]
            assert call_kwargs['software_id'] == "CUSTOM-SOFTWARE-ID"

    def test_list_tenants(self, secret_manager, mock_secret_manager_client):
        """Should list all tenants with stored credentials."""
        # Mock list_secrets response with proper name attribute
        mock_secret1 = MagicMock()
        mock_secret1.name = "projects/test-project/secrets/nav-credentials-tenant-001"
        mock_secret2 = MagicMock()
        mock_secret2.name = "projects/test-project/secrets/nav-credentials-tenant-002"
        mock_secret3 = MagicMock()
        mock_secret3.name = "projects/test-project/secrets/other-secret"  # Should be filtered out
        
        mock_secret_manager_client.list_secrets.return_value = [mock_secret1, mock_secret2, mock_secret3]
        
        tenants = secret_manager.list_tenants()
        
        assert len(tenants) == 2
        assert "tenant-001" in tenants
        assert "tenant-002" in tenants

    def test_delete_credentials(self, secret_manager, mock_secret_manager_client, credentials_json):
        """Should delete credentials for tenant."""
        # Setup cache
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        secret_manager.get_credentials("tenant-001")
        
        # Delete
        secret_manager.delete_credentials("tenant-001")
        
        mock_secret_manager_client.delete_secret.assert_called_once()
        
        # Cache should be invalidated - next get should fetch again
        secret_manager.get_credentials("tenant-001")
        assert mock_secret_manager_client.access_secret_version.call_count == 2

    def test_delete_credentials_not_found(self, secret_manager, mock_secret_manager_client):
        """Should handle deletion of non-existent credentials gracefully."""
        from google.api_core import exceptions as gcp_exceptions
        
        mock_secret_manager_client.delete_secret.side_effect = gcp_exceptions.NotFound("Not found")
        
        # Should not raise exception
        secret_manager.delete_credentials("nonexistent-tenant")

    # =========================================================================
    # THREAD SAFETY TESTS
    # =========================================================================

    def test_cache_thread_safety(self, mock_secret_manager_client, credentials_json):
        """Should handle concurrent cache access safely."""
        from nav_secret_manager import SecretManagerConfig, NavSecretManager
        
        config = SecretManagerConfig(project_id="test-project")
        secret_manager = NavSecretManager(config)
        
        mock_response = MagicMock()
        mock_response.payload.data = credentials_json.encode('UTF-8')
        mock_secret_manager_client.access_secret_version.return_value = mock_response
        
        results = []
        errors = []
        
        def get_credentials():
            try:
                creds = secret_manager.get_credentials("tenant-001")
                results.append(creds.login)
            except Exception as e:
                errors.append(str(e))
        
        # Create multiple threads
        threads = [Thread(target=get_credentials) for _ in range(10)]
        
        # Start all threads
        for t in threads:
            t.start()
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        # All should succeed
        assert len(errors) == 0
        assert len(results) == 10
        assert all(r == "test_user" for r in results)


# =============================================================================
# CUSTOM EXCEPTION TESTS
# =============================================================================

class TestCustomExceptions:
    """Test custom exception classes."""

    def test_secret_manager_error_base(self):
        """SecretManagerError should be base exception."""
        from nav_secret_manager import SecretManagerError
        
        error = SecretManagerError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_secret_not_found_error(self):
        """SecretNotFoundError should inherit from SecretManagerError."""
        from nav_secret_manager import SecretManagerError, SecretNotFoundError
        
        error = SecretNotFoundError("Tenant not found")
        assert isinstance(error, SecretManagerError)
        assert "Tenant not found" in str(error)

    def test_secret_access_error(self):
        """SecretAccessError should inherit from SecretManagerError."""
        from nav_secret_manager import SecretManagerError, SecretAccessError
        
        error = SecretAccessError("Access denied")
        assert isinstance(error, SecretManagerError)
        assert "Access denied" in str(error)

    def test_secret_parse_error(self):
        """SecretParseError should inherit from SecretManagerError."""
        from nav_secret_manager import SecretManagerError, SecretParseError
        
        error = SecretParseError("Invalid JSON")
        assert isinstance(error, SecretManagerError)
        assert "Invalid JSON" in str(error)


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
