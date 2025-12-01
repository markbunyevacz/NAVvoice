"""
Secure Credential Storage for NAV API Client

Uses Google Cloud Secret Manager with:
- Encryption at rest (CMEK support)
- Automatic rotation support
- In-memory caching with TTL
- Multi-tenant isolation

Requirements:
    pip install google-cloud-secret-manager

Setup:
    1. Enable Secret Manager API in GCP Console
    2. Create service account with roles/secretmanager.secretAccessor
    3. Set GOOGLE_APPLICATION_CREDENTIALS environment variable
"""

import os
import json
import time
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from threading import Lock

from google.cloud import secretmanager
from google.api_core import exceptions as gcp_exceptions

from nav_client import NavCredentials

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class SecretManagerConfig:
    """Configuration for Secret Manager integration."""
    project_id: str
    cache_ttl_seconds: int = 300  # 5 minutes cache
    enable_caching: bool = True
    secret_prefix: str = "nav-credentials"
    
    # Multi-tenancy: each client gets isolated secrets
    # Format: projects/{project}/secrets/{prefix}-{tenant_id}/versions/latest
    
    def get_secret_name(self, tenant_id: str) -> str:
        """Generate full secret resource name for a tenant."""
        return f"projects/{self.project_id}/secrets/{self.secret_prefix}-{tenant_id}/versions/latest"
    
    def get_secret_id(self, tenant_id: str) -> str:
        """Generate secret ID (without version) for creation."""
        return f"{self.secret_prefix}-{tenant_id}"


@dataclass
class CachedSecret:
    """In-memory cached secret with TTL."""
    credentials: NavCredentials
    fetched_at: datetime
    ttl_seconds: int
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        expiry = self.fetched_at + timedelta(seconds=self.ttl_seconds)
        return datetime.now() > expiry


# =============================================================================
# SECRET MANAGER CLIENT
# =============================================================================

class NavSecretManager:
    """
    Secure credential storage using Google Cloud Secret Manager.
    
    Provides:
    - Secure storage for NAV technical user credentials
    - Multi-tenant isolation (one secret per tenant)
    - In-memory caching with configurable TTL
    - Automatic credential rotation support
    - Thread-safe operations
    
    Usage:
        config = SecretManagerConfig(project_id="my-gcp-project")
        secret_mgr = NavSecretManager(config)
        
        # Store credentials for a tenant
        secret_mgr.store_credentials("tenant-123", credentials)
        
        # Retrieve credentials (cached)
        creds = secret_mgr.get_credentials("tenant-123")
        
        # Create NavClient with stored credentials
        client = secret_mgr.create_nav_client("tenant-123")
    """
    
    def __init__(self, config: SecretManagerConfig):
        """
        Initialize Secret Manager client.
        
        Args:
            config: Secret Manager configuration
        """
        self.config = config
        self._client = secretmanager.SecretManagerServiceClient()
        self._cache: Dict[str, CachedSecret] = {}
        self._cache_lock = Lock()
        
        logger.info(f"NavSecretManager initialized for project: {config.project_id}")
    
    # =========================================================================
    # CREDENTIAL RETRIEVAL
    # =========================================================================
    
    def get_credentials(
        self,
        tenant_id: str,
        bypass_cache: bool = False
    ) -> NavCredentials:
        """
        Retrieve NAV credentials for a tenant.
        
        Args:
            tenant_id: Unique tenant identifier
            bypass_cache: Force fetch from Secret Manager
            
        Returns:
            NavCredentials instance
            
        Raises:
            SecretNotFoundError: If credentials don't exist
            SecretAccessError: If access denied
        """
        # Check cache first
        if self.config.enable_caching and not bypass_cache:
            cached = self._get_from_cache(tenant_id)
            if cached:
                logger.debug(f"Cache hit for tenant: {tenant_id}")
                return cached
        
        # Fetch from Secret Manager
        logger.info(f"Fetching credentials from Secret Manager for tenant: {tenant_id}")
        credentials = self._fetch_from_secret_manager(tenant_id)
        
        # Update cache
        if self.config.enable_caching:
            self._update_cache(tenant_id, credentials)
        
        return credentials
    
    def _get_from_cache(self, tenant_id: str) -> Optional[NavCredentials]:
        """Get credentials from cache if not expired."""
        with self._cache_lock:
            cached = self._cache.get(tenant_id)
            if cached and not cached.is_expired:
                return cached.credentials
            elif cached:
                # Remove expired entry
                del self._cache[tenant_id]
            return None
    
    def _update_cache(self, tenant_id: str, credentials: NavCredentials) -> None:
        """Update cache with new credentials."""
        with self._cache_lock:
            self._cache[tenant_id] = CachedSecret(
                credentials=credentials,
                fetched_at=datetime.now(),
                ttl_seconds=self.config.cache_ttl_seconds
            )

    def _fetch_from_secret_manager(self, tenant_id: str) -> NavCredentials:
        """Fetch and parse credentials from Secret Manager."""
        secret_name = self.config.get_secret_name(tenant_id)

        try:
            response = self._client.access_secret_version(name=secret_name)
            secret_data = response.payload.data.decode("UTF-8")

            # Parse JSON credential data
            cred_dict = json.loads(secret_data)

            return NavCredentials(
                login=cred_dict["login"],
                password=cred_dict["password"],
                signature_key=cred_dict["signature_key"],
                replacement_key=cred_dict["replacement_key"],
                tax_number=cred_dict["tax_number"]
            )

        except gcp_exceptions.NotFound:
            raise SecretNotFoundError(f"Credentials not found for tenant: {tenant_id}")
        except gcp_exceptions.PermissionDenied:
            raise SecretAccessError(f"Access denied to credentials for tenant: {tenant_id}")
        except (json.JSONDecodeError, KeyError) as e:
            raise SecretParseError(f"Invalid credential format for tenant {tenant_id}: {e}")

    # =========================================================================
    # CREDENTIAL STORAGE
    # =========================================================================

    def store_credentials(
        self,
        tenant_id: str,
        credentials: NavCredentials,
        labels: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Store NAV credentials for a tenant.

        Creates a new secret if it doesn't exist, or adds a new version
        to an existing secret (for rotation).

        Args:
            tenant_id: Unique tenant identifier
            credentials: NAV credentials to store
            labels: Optional labels for the secret

        Returns:
            Secret version name
        """
        secret_id = self.config.get_secret_id(tenant_id)
        parent = f"projects/{self.config.project_id}"

        # Serialize credentials to JSON
        cred_data = json.dumps({
            "login": credentials.login,
            "password": credentials.password,
            "signature_key": credentials.signature_key,
            "replacement_key": credentials.replacement_key,
            "tax_number": credentials.tax_number,
            "stored_at": datetime.now().isoformat()
        }).encode("UTF-8")

        # Create secret if it doesn't exist
        try:
            secret_path = f"{parent}/secrets/{secret_id}"
            self._client.get_secret(name=secret_path)
            logger.info(f"Adding new version to existing secret for tenant: {tenant_id}")
        except gcp_exceptions.NotFound:
            logger.info(f"Creating new secret for tenant: {tenant_id}")
            self._create_secret(parent, secret_id, labels or {})

        # Add new version
        secret_path = f"{parent}/secrets/{secret_id}"
        response = self._client.add_secret_version(
            parent=secret_path,
            payload={"data": cred_data}
        )

        # Invalidate cache
        self.invalidate_cache(tenant_id)

        logger.info(f"Stored credentials version: {response.name}")
        return response.name

    def _create_secret(
        self,
        parent: str,
        secret_id: str,
        labels: Dict[str, str]
    ) -> None:
        """Create a new secret resource."""
        secret = {
            "replication": {"automatic": {}},
            "labels": {
                "app": "nav-invoice-reconciliation",
                "managed-by": "nav-secret-manager",
                **labels
            }
        }

        self._client.create_secret(
            parent=parent,
            secret_id=secret_id,
            secret=secret
        )

    # =========================================================================
    # ROTATION SUPPORT
    # =========================================================================

    def rotate_credentials(
        self,
        tenant_id: str,
        new_credentials: NavCredentials
    ) -> str:
        """
        Rotate credentials by adding a new version.

        The old version remains accessible but 'latest' points to new.
        Old versions can be disabled/destroyed via GCP Console.

        Args:
            tenant_id: Unique tenant identifier
            new_credentials: New NAV credentials

        Returns:
            New secret version name
        """
        logger.info(f"Rotating credentials for tenant: {tenant_id}")
        return self.store_credentials(
            tenant_id=tenant_id,
            credentials=new_credentials,
            labels={"rotated-at": datetime.now().strftime("%Y%m%d")}
        )

    # =========================================================================
    # CACHE MANAGEMENT
    # =========================================================================

    def invalidate_cache(self, tenant_id: Optional[str] = None) -> None:
        """
        Invalidate cached credentials.

        Args:
            tenant_id: Specific tenant to invalidate, or None for all
        """
        with self._cache_lock:
            if tenant_id:
                self._cache.pop(tenant_id, None)
                logger.debug(f"Invalidated cache for tenant: {tenant_id}")
            else:
                self._cache.clear()
                logger.debug("Invalidated all cached credentials")

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def create_nav_client(
        self,
        tenant_id: str,
        use_test_api: bool = False,
        software_id: Optional[str] = None
    ):
        """
        Create a NavClient instance with stored credentials.

        Args:
            tenant_id: Tenant whose credentials to use
            use_test_api: Use NAV test environment
            software_id: Override software ID

        Returns:
            Configured NavClient instance
        """
        from nav_client import NavClient

        credentials = self.get_credentials(tenant_id)
        return NavClient(
            credentials=credentials,
            use_test_api=use_test_api,
            software_id=software_id
        )

    def list_tenants(self) -> list:
        """List all tenants with stored credentials."""
        parent = f"projects/{self.config.project_id}"
        prefix = self.config.secret_prefix

        tenants = []
        for secret in self._client.list_secrets(parent=parent):
            secret_id = secret.name.split("/")[-1]
            if secret_id.startswith(prefix):
                tenant_id = secret_id[len(prefix) + 1:]  # Remove prefix and dash
                tenants.append(tenant_id)

        return tenants

    def delete_credentials(self, tenant_id: str) -> None:
        """
        Delete all credentials for a tenant.

        WARNING: This permanently deletes the secret and all versions.
        """
        secret_id = self.config.get_secret_id(tenant_id)
        secret_path = f"projects/{self.config.project_id}/secrets/{secret_id}"

        try:
            self._client.delete_secret(name=secret_path)
            self.invalidate_cache(tenant_id)
            logger.warning(f"Deleted all credentials for tenant: {tenant_id}")
        except gcp_exceptions.NotFound:
            logger.warning(f"No credentials found to delete for tenant: {tenant_id}")


# =============================================================================
# CUSTOM EXCEPTIONS
# =============================================================================

class SecretManagerError(Exception):
    """Base exception for Secret Manager errors."""
    pass


class SecretNotFoundError(SecretManagerError):
    """Raised when credentials don't exist for a tenant."""
    pass


class SecretAccessError(SecretManagerError):
    """Raised when access to secret is denied."""
    pass


class SecretParseError(SecretManagerError):
    """Raised when credential data cannot be parsed."""
    pass


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    """Example usage of NavSecretManager."""
    import os

    # Configuration
    config = SecretManagerConfig(
        project_id=os.getenv("GCP_PROJECT_ID", "your-project-id"),
        cache_ttl_seconds=300,
        enable_caching=True
    )

    secret_mgr = NavSecretManager(config)

    # Example: Store credentials for a tenant
    tenant_id = "demo-client-001"

    credentials = NavCredentials(
        login="demo_technical_user",
        password="demo_password",
        signature_key="12345678901234567890123456789012",
        replacement_key="abcdefghijklmnopqrstuvwxyz123456",
        tax_number="12345678"
    )

    try:
        # Store
        version = secret_mgr.store_credentials(tenant_id, credentials)
        print(f"✓ Stored credentials: {version}")

        # Retrieve
        retrieved = secret_mgr.get_credentials(tenant_id)
        print(f"✓ Retrieved credentials for: {retrieved.login}")

        # Create client
        client = secret_mgr.create_nav_client(tenant_id, use_test_api=True)
        print(f"✓ Created NavClient for tenant: {tenant_id}")

        # List tenants
        tenants = secret_mgr.list_tenants()
        print(f"✓ Found {len(tenants)} tenants with stored credentials")

    except SecretManagerError as e:
        print(f"✗ Error: {e}")

