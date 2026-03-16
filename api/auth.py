"""
Auth router -- JWT login and token refresh.

Wraps AuthService.login() and AuthService.refresh() as REST endpoints.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from auth import AuthService
from api.deps import get_auth_service
from api.schemas import (
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    RefreshResponse,
    UserInfo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Authenticate with email + password, receive JWT tokens."""
    result = auth_service.login(body.email, body.password)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    return TokenResponse(
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        token_type=result["token_type"],
        expires_in=result["expires_in"],
        user=UserInfo(**result["user"]),
    )


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    body: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Exchange a valid refresh token for a new access token."""
    result = auth_service.refresh(body.refresh_token)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    return RefreshResponse(**result)
