"""
JWT Authentication and Authorization System

Implements secure authentication for the NAV Invoice Reconciliation system:
- JWT token generation and validation
- Role-Based Access Control (RBAC)
- Password hashing with bcrypt
- Refresh token support
- Multi-tenant user management

Roles:
- ADMIN: Full access, manage NAV keys, billing, users
- ACCOUNTANT: View/Reconcile invoices, override AI actions
- SITE_MANAGER: Upload PDFs only

Requirements:
    pip install PyJWT bcrypt
"""

import os
import re
import logging
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps

try:
    import jwt
except ImportError:
    jwt = None
    logging.warning("PyJWT not installed. Run: pip install PyJWT")

try:
    import bcrypt
except ImportError:
    bcrypt = None
    logging.warning("bcrypt not installed. Run: pip install bcrypt")

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class AuthConfig:
    """Authentication configuration."""
    secret_key: str = field(default_factory=lambda: os.environ.get(
        "JWT_SECRET_KEY", secrets.token_urlsafe(32)
    ))
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    issuer: str = "nav-invoice-reconciliation"
    audience: str = "nav-api"


# =============================================================================
# ENUMS
# =============================================================================

class UserRole(Enum):
    """User roles with hierarchical permissions."""
    ADMIN = "admin"           # Full access
    ACCOUNTANT = "accountant" # View, reconcile, approve emails
    SITE_MANAGER = "site_manager"  # Upload only


class Permission(Enum):
    """Granular permissions."""
    # Invoice operations
    VIEW_INVOICES = "view_invoices"
    UPLOAD_INVOICES = "upload_invoices"
    RECONCILE_INVOICES = "reconcile_invoices"
    DELETE_INVOICES = "delete_invoices"
    
    # Email operations
    VIEW_EMAILS = "view_emails"
    APPROVE_EMAILS = "approve_emails"
    SEND_EMAILS = "send_emails"
    
    # Admin operations
    MANAGE_USERS = "manage_users"
    MANAGE_NAV_KEYS = "manage_nav_keys"
    MANAGE_TENANTS = "manage_tenants"
    VIEW_AUDIT_LOG = "view_audit_log"
    
    # NAV operations
    QUERY_NAV = "query_nav"


# Role-Permission mapping
ROLE_PERMISSIONS: Dict[UserRole, List[Permission]] = {
    UserRole.ADMIN: list(Permission),  # All permissions
    
    UserRole.ACCOUNTANT: [
        Permission.VIEW_INVOICES,
        Permission.UPLOAD_INVOICES,
        Permission.RECONCILE_INVOICES,
        Permission.VIEW_EMAILS,
        Permission.APPROVE_EMAILS,
        Permission.QUERY_NAV,
        Permission.VIEW_AUDIT_LOG,
    ],
    
    UserRole.SITE_MANAGER: [
        Permission.VIEW_INVOICES,
        Permission.UPLOAD_INVOICES,
    ],
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class User:
    """User account representation."""
    id: str
    email: str
    password_hash: str
    role: UserRole
    tenant_id: str
    name: str = ""
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        return permission in ROLE_PERMISSIONS.get(self.role, [])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding sensitive data)."""
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role.value,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "is_active": self.is_active,
            "mfa_enabled": self.mfa_enabled,
        }


@dataclass
class TokenPayload:
    """JWT token payload."""
    user_id: str
    email: str
    role: str
    tenant_id: str
    permissions: List[str]
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for revocation
    token_type: str = "access"  # access or refresh


# =============================================================================
# PASSWORD HASHING
# =============================================================================

class PasswordManager:
    """Secure password hashing using bcrypt."""

    # Work factor for bcrypt (higher = more secure but slower)
    BCRYPT_ROUNDS = 12

    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash a password using bcrypt.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        if bcrypt is None:
            raise ImportError("bcrypt not installed")

        # Validate password strength
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        salt = bcrypt.gensalt(rounds=cls.BCRYPT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    @classmethod
    def verify_password(cls, password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password
            password_hash: Stored hash

        Returns:
            True if password matches
        """
        if bcrypt is None:
            raise ImportError("bcrypt not installed")

        return bcrypt.checkpw(
            password.encode('utf-8'),
            password_hash.encode('utf-8')
        )

    @classmethod
    def validate_password_strength(cls, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password meets security requirements.

        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []

        if len(password) < 8:
            issues.append("Password must be at least 8 characters")
        if len(password) > 128:
            issues.append("Password must be less than 128 characters")
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")

        return len(issues) == 0, issues


# =============================================================================
# JWT TOKEN MANAGER
# =============================================================================

class JWTManager:
    """
    JWT token generation and validation.

    Usage:
        config = AuthConfig(secret_key="your-secret-key")
        jwt_mgr = JWTManager(config)

        # Generate tokens
        access_token, refresh_token = jwt_mgr.generate_tokens(user)

        # Validate token
        payload = jwt_mgr.validate_token(access_token)
    """

    # Token revocation list (in production, use Redis)
    _revoked_tokens: set = set()

    def __init__(self, config: AuthConfig):
        """Initialize JWT manager."""
        if jwt is None:
            raise ImportError("PyJWT not installed")

        self.config = config
        logger.info("JWTManager initialized")

    def generate_tokens(self, user: User) -> Tuple[str, str]:
        """
        Generate access and refresh tokens for a user.

        Args:
            user: User object

        Returns:
            Tuple of (access_token, refresh_token)
        """
        now = datetime.now(timezone.utc)

        # Get user permissions
        permissions = [p.value for p in ROLE_PERMISSIONS.get(user.role, [])]

        # Access token (short-lived)
        access_payload = {
            "sub": user.id,
            "email": user.email,
            "role": user.role.value,
            "tenant_id": user.tenant_id,
            "permissions": permissions,
            "iat": now,
            "exp": now + timedelta(minutes=self.config.access_token_expire_minutes),
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "jti": secrets.token_urlsafe(16),
            "type": "access"
        }

        access_token = jwt.encode(
            access_payload,
            self.config.secret_key,
            algorithm=self.config.algorithm
        )

        # Refresh token (long-lived)
        refresh_payload = {
            "sub": user.id,
            "tenant_id": user.tenant_id,
            "iat": now,
            "exp": now + timedelta(days=self.config.refresh_token_expire_days),
            "iss": self.config.issuer,
            "jti": secrets.token_urlsafe(16),
            "type": "refresh"
        }

        refresh_token = jwt.encode(
            refresh_payload,
            self.config.secret_key,
            algorithm=self.config.algorithm
        )

        logger.info(f"Generated tokens for user {user.email}")
        return access_token, refresh_token

    def validate_token(
        self,
        token: str,
        token_type: str = "access"
    ) -> Optional[Dict[str, Any]]:
        """
        Validate a JWT token.

        Args:
            token: JWT token string
            token_type: Expected token type ("access" or "refresh")

        Returns:
            Token payload if valid, None otherwise
        """
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience if token_type == "access" else None,
                issuer=self.config.issuer
            )

            # Check token type
            if payload.get("type") != token_type:
                logger.warning(f"Token type mismatch: expected {token_type}")
                return None

            # Check if revoked
            if payload.get("jti") in self._revoked_tokens:
                logger.warning(f"Token has been revoked: {payload.get('jti')}")
                return None

            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None

    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token (logout).

        Args:
            token: JWT token to revoke

        Returns:
            True if revoked successfully
        """
        try:
            # Decode without verification to get JTI
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                options={"verify_exp": False}
            )

            jti = payload.get("jti")
            if jti:
                self._revoked_tokens.add(jti)
                logger.info(f"Token revoked: {jti}")
                return True

        except jwt.InvalidTokenError:
            pass

        return False

    def refresh_access_token(
        self,
        refresh_token: str,
        user: User
    ) -> Optional[str]:
        """
        Generate new access token using refresh token.

        Args:
            refresh_token: Valid refresh token
            user: User object

        Returns:
            New access token or None if refresh token invalid
        """
        payload = self.validate_token(refresh_token, token_type="refresh")

        if not payload:
            return None

        # Verify user matches
        if payload.get("sub") != user.id:
            logger.warning("Refresh token user mismatch")
            return None

        # Generate new access token only
        access_token, _ = self.generate_tokens(user)
        return access_token


# =============================================================================
# AUTHENTICATION DECORATOR
# =============================================================================

def require_auth(permissions: Optional[List[Permission]] = None):
    """
    Decorator to require authentication and optional permissions.

    Usage:
        @require_auth()
        def protected_endpoint(current_user):
            ...

        @require_auth([Permission.MANAGE_USERS])
        def admin_only_endpoint(current_user):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # This would be integrated with your web framework
            # For Flask: use request.headers.get('Authorization')
            # For FastAPI: use Depends(get_current_user)
            raise NotImplementedError(
                "Integrate with your web framework. "
                "See AuthMiddleware for implementation."
            )
        return wrapper
    return decorator


class AuthMiddleware:
    """
    Authentication middleware for web frameworks.

    Provides request authentication and user injection.

    Usage with Flask:
        app = Flask(__name__)
        auth = AuthMiddleware(jwt_manager, user_store)

        @app.before_request
        def authenticate():
            auth.authenticate_request(request)
    """

    def __init__(self, jwt_manager: JWTManager, user_store: 'UserStore'):
        """
        Initialize middleware.

        Args:
            jwt_manager: JWTManager instance
            user_store: UserStore for user lookup
        """
        self.jwt_manager = jwt_manager
        self.user_store = user_store

    def authenticate_request(
        self,
        authorization_header: Optional[str],
        required_permissions: Optional[List[Permission]] = None
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Authenticate a request.

        Args:
            authorization_header: "Bearer <token>" header value
            required_permissions: Required permissions for this endpoint

        Returns:
            Tuple of (is_authenticated, user, error_message)
        """
        if not authorization_header:
            return False, None, "Missing Authorization header"

        # Extract token
        parts = authorization_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False, None, "Invalid Authorization header format"

        token = parts[1]

        # Validate token
        payload = self.jwt_manager.validate_token(token)
        if not payload:
            return False, None, "Invalid or expired token"

        # Get user
        user = self.user_store.get_user_by_id(
            payload["sub"],
            payload["tenant_id"]
        )

        if not user:
            return False, None, "User not found"

        if not user.is_active:
            return False, None, "User account is disabled"

        # Check permissions
        if required_permissions:
            for perm in required_permissions:
                if not user.has_permission(perm):
                    return False, user, f"Missing permission: {perm.value}"

        return True, user, None


# =============================================================================
# USER STORE (In-Memory for Demo, use Database in Production)
# =============================================================================

class UserStore:
    """
    User storage and management.

    In production, replace with database-backed implementation.
    """

    def __init__(self):
        """Initialize user store."""
        self._users: Dict[str, User] = {}  # user_id -> User
        self._email_index: Dict[str, str] = {}  # email -> user_id

    def create_user(
        self,
        email: str,
        password: str,
        role: UserRole,
        tenant_id: str,
        name: str = ""
    ) -> User:
        """
        Create a new user.

        Args:
            email: User email (unique)
            password: Plain text password (will be hashed)
            role: User role
            tenant_id: Tenant ID for multi-tenancy
            name: Display name

        Returns:
            Created User object

        Raises:
            ValueError: If email already exists
        """
        # Check email uniqueness
        if email.lower() in self._email_index:
            raise ValueError(f"Email already exists: {email}")

        # Validate password
        is_valid, issues = PasswordManager.validate_password_strength(password)
        if not is_valid:
            raise ValueError(f"Weak password: {', '.join(issues)}")

        # Create user
        user_id = secrets.token_urlsafe(16)
        password_hash = PasswordManager.hash_password(password)

        user = User(
            id=user_id,
            email=email.lower(),
            password_hash=password_hash,
            role=role,
            tenant_id=tenant_id,
            name=name
        )

        self._users[user_id] = user
        self._email_index[email.lower()] = user_id

        logger.info(f"Created user: {email} with role {role.value}")
        return user

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        user_id = self._email_index.get(email.lower())
        return self._users.get(user_id) if user_id else None

    def get_user_by_id(self, user_id: str, tenant_id: str) -> Optional[User]:
        """Get user by ID with tenant verification."""
        user = self._users.get(user_id)
        if user and user.tenant_id == tenant_id:
            return user
        return None

    def authenticate(self, email: str, password: str) -> Optional[User]:
        """
        Authenticate user with email and password.

        Args:
            email: User email
            password: Plain text password

        Returns:
            User if authentication successful, None otherwise
        """
        user = self.get_user_by_email(email)

        if not user:
            logger.warning(f"Authentication failed: user not found: {email}")
            return None

        if not user.is_active:
            logger.warning(f"Authentication failed: user inactive: {email}")
            return None

        if not PasswordManager.verify_password(password, user.password_hash):
            logger.warning(f"Authentication failed: wrong password: {email}")
            return None

        # Update last login
        user.last_login = datetime.now()
        logger.info(f"User authenticated: {email}")

        return user

    def get_users_by_tenant(self, tenant_id: str) -> List[User]:
        """Get all users for a tenant."""
        return [u for u in self._users.values() if u.tenant_id == tenant_id]

    def update_user_role(self, user_id: str, new_role: UserRole) -> bool:
        """Update user's role."""
        user = self._users.get(user_id)
        if user:
            user.role = new_role
            logger.info(f"Updated user {user.email} role to {new_role.value}")
            return True
        return False

    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate a user account."""
        user = self._users.get(user_id)
        if user:
            user.is_active = False
            logger.info(f"Deactivated user: {user.email}")
            return True
        return False


# =============================================================================
# AUTHENTICATION SERVICE
# =============================================================================

class AuthService:
    """
    High-level authentication service.

    Combines JWT management and user store for complete auth flows.

    Usage:
        auth_service = AuthService()

        # Register new user
        user = auth_service.register("user@example.com", "Password123!",
                                     UserRole.ACCOUNTANT, "tenant-1")

        # Login
        result = auth_service.login("user@example.com", "Password123!")
        access_token = result["access_token"]

        # Protected operation
        is_valid, user, error = auth_service.validate_request(
            f"Bearer {access_token}",
            [Permission.VIEW_INVOICES]
        )
    """

    def __init__(self, config: Optional[AuthConfig] = None):
        """Initialize auth service."""
        self.config = config or AuthConfig()
        self.jwt_manager = JWTManager(self.config)
        self.user_store = UserStore()
        self.middleware = AuthMiddleware(self.jwt_manager, self.user_store)

        logger.info("AuthService initialized")

    def register(
        self,
        email: str,
        password: str,
        role: UserRole,
        tenant_id: str,
        name: str = ""
    ) -> User:
        """Register a new user."""
        return self.user_store.create_user(
            email=email,
            password=password,
            role=role,
            tenant_id=tenant_id,
            name=name
        )

    def login(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user and return tokens.

        Returns:
            Dict with access_token, refresh_token, user info
            or None if authentication fails
        """
        user = self.user_store.authenticate(email, password)

        if not user:
            return None

        access_token, refresh_token = self.jwt_manager.generate_tokens(user)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.config.access_token_expire_minutes * 60,
            "user": user.to_dict()
        }

    def logout(self, token: str) -> bool:
        """Logout (revoke token)."""
        return self.jwt_manager.revoke_token(token)

    def refresh(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refresh access token."""
        payload = self.jwt_manager.validate_token(refresh_token, "refresh")
        if not payload:
            return None

        user = self.user_store.get_user_by_id(
            payload["sub"],
            payload["tenant_id"]
        )

        if not user:
            return None

        new_access_token = self.jwt_manager.refresh_access_token(
            refresh_token, user
        )

        if not new_access_token:
            return None

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": self.config.access_token_expire_minutes * 60
        }

    def validate_request(
        self,
        authorization_header: Optional[str],
        required_permissions: Optional[List[Permission]] = None
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """Validate request authentication and permissions."""
        return self.middleware.authenticate_request(
            authorization_header,
            required_permissions
        )


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("JWT Authentication System Demo")
    print("=" * 60)

    # Initialize auth service
    auth = AuthService()

    # Register users
    print("\n1. Registering users...")
    admin = auth.register(
        email="admin@company.hu",
        password="AdminPass123!",
        role=UserRole.ADMIN,
        tenant_id="tenant-001",
        name="System Admin"
    )
    print(f"   ✓ Admin: {admin.email}")

    accountant = auth.register(
        email="accountant@company.hu",
        password="AccountPass123!",
        role=UserRole.ACCOUNTANT,
        tenant_id="tenant-001",
        name="Main Accountant"
    )
    print(f"   ✓ Accountant: {accountant.email}")

    # Login
    print("\n2. Login...")
    result = auth.login("accountant@company.hu", "AccountPass123!")
    if result:
        print(f"   ✓ Login successful")
        print(f"   ✓ Access token: {result['access_token'][:50]}...")
        print(f"   ✓ Expires in: {result['expires_in']} seconds")

    # Validate request
    print("\n3. Validating protected request...")
    is_valid, user, error = auth.validate_request(
        f"Bearer {result['access_token']}",
        [Permission.VIEW_INVOICES]
    )
    print(f"   ✓ Valid: {is_valid}")
    print(f"   ✓ User: {user.email if user else 'None'}")

    # Check permission denied
    print("\n4. Testing permission denial...")
    is_valid, user, error = auth.validate_request(
        f"Bearer {result['access_token']}",
        [Permission.MANAGE_USERS]  # Accountant doesn't have this
    )
    print(f"   ✓ Valid: {is_valid}")
    print(f"   ✓ Error: {error}")

    # Refresh token
    print("\n5. Refreshing token...")
    new_tokens = auth.refresh(result['refresh_token'])
    if new_tokens:
        print(f"   ✓ New access token: {new_tokens['access_token'][:50]}...")

    # Logout
    print("\n6. Logging out...")
    auth.logout(result['access_token'])
    print("   ✓ Token revoked")

    # Verify revoked token fails
    is_valid, _, error = auth.validate_request(
        f"Bearer {result['access_token']}"
    )
    print(f"   ✓ Revoked token rejected: {not is_valid}")