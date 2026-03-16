"""
FastAPI dependency injection providers.

Wires the existing AuthService, DatabaseManager, and ApprovalQueue
into FastAPI's Depends() system. Tenant isolation is enforced by
extracting tenant_id from the JWT payload automatically.
"""

import os
import logging
from typing import Optional, Callable

from fastapi import Depends, HTTPException, Header, status

from auth import AuthService, AuthConfig, User, Permission
from database_manager import DatabaseManager
from approval_queue import ApprovalQueue

logger = logging.getLogger(__name__)

_auth_service: Optional[AuthService] = None
_db: Optional[DatabaseManager] = None
_approval_queue: Optional[ApprovalQueue] = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService(AuthConfig())
    return _auth_service


def get_db() -> DatabaseManager:
    global _db
    if _db is None:
        db_path = os.getenv("NAVVOICE_DB_PATH", "data/invoices.db")
        _db = DatabaseManager(db_path)
        _db.initialize()
    return _db


def get_approval_queue() -> ApprovalQueue:
    global _approval_queue
    if _approval_queue is None:
        db_path = os.getenv("NAVVOICE_APPROVAL_DB_PATH", "data/approvals.db")
        _approval_queue = ApprovalQueue(db_path)
        _approval_queue.initialize()
    return _approval_queue


def get_current_user(
    authorization: Optional[str] = Header(None),
    auth_service: AuthService = Depends(get_auth_service),
) -> User:
    """Extract and validate JWT from Authorization header, return User."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    is_valid, user, error = auth_service.validate_request(authorization)

    if not is_valid or user is None:
        code = (
            status.HTTP_403_FORBIDDEN
            if user is not None
            else status.HTTP_401_UNAUTHORIZED
        )
        raise HTTPException(
            status_code=code,
            detail=error or "Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_permission(*permissions: Permission) -> Callable:
    """Higher-order dependency that checks user permissions."""

    def checker(user: User = Depends(get_current_user)) -> User:
        for perm in permissions:
            if not user.has_permission(perm):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing permission: {perm.value}",
                )
        return user

    return checker


def reset_singletons() -> None:
    """Reset cached singletons (used in tests)."""
    global _auth_service, _db, _approval_queue
    _auth_service = None
    _db = None
    _approval_queue = None
