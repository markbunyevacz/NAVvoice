"""
DB-backed upload link generation and validation.

Vendors receive a one-time, time-limited link that maps to a row in the
main database. The token itself is opaque random data; the server validates
its lifecycle state from persisted metadata.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from database_manager import DatabaseManager

logger = logging.getLogger(__name__)

DEFAULT_EXPIRY_HOURS = 168  # 7 days


def generate_upload_token(
) -> str:
    """Create an opaque token suitable for URL-safe public links."""
    return secrets.token_urlsafe(24)


def get_upload_link_expiry_hours() -> int:
    """Read and sanitize upload token expiry configuration."""
    raw = os.getenv(
        "UPLOAD_LINK_EXPIRY_HOURS",
        str(DEFAULT_EXPIRY_HOURS),
    ).strip()
    try:
        hours = int(raw)
    except ValueError:
        logger.warning("Invalid UPLOAD_LINK_EXPIRY_HOURS=%r, using default", raw)
        return DEFAULT_EXPIRY_HOURS
    return max(1, hours)


def create_upload_link(
    db: DatabaseManager,
    base_url: str,
    tenant_id: str,
    invoice_number: str,
    queue_item_id: Optional[str] = None,
    vendor_email: Optional[str] = None,
    created_by: str = "system",
    expires_hours: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Persist a one-time upload token and return its public URL plus metadata.
    """
    token = generate_upload_token()
    ttl_hours = (
        expires_hours
        if expires_hours is not None
        else get_upload_link_expiry_hours()
    )
    expires_at = datetime.now() + timedelta(hours=ttl_hours)
    token_row = db.create_upload_token(
        tenant_id=tenant_id,
        invoice_number=invoice_number,
        token=token,
        expires_at=expires_at,
        queue_item_id=queue_item_id,
        vendor_email=vendor_email,
        created_by=created_by,
    )
    return {
        "token": token,
        "url": generate_upload_link(base_url, tenant_id, token),
        "expires_at": token_row.get("expires_at", expires_at),
        "invoice_number": invoice_number,
        "tenant_id": tenant_id,
    }


def validate_upload_token(
    db: DatabaseManager,
    token: str,
) -> Optional[Dict[str, Any]]:
    """Validate a persisted upload token and enforce one-time lifecycle rules."""
    token_row = db.get_upload_token(token)
    if token_row is None:
        logger.info("Upload token not found")
        return None

    expires_at = token_row.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at_dt = datetime.fromisoformat(expires_at)
        except ValueError:
            logger.warning("Upload token expiry parse failed for %s", token)
            return None
    else:
        if not isinstance(expires_at, datetime):
            return None
        expires_at_dt = expires_at

    if expires_at_dt is None or datetime.now() > expires_at_dt:
        logger.info(
            "Upload token expired for %s / %s",
            token_row.get("tenant_id"),
            token_row.get("invoice_number"),
        )
        return None
    if token_row.get("used_at") is not None:
        logger.info(
            "Upload token already used for %s",
            token_row.get("invoice_number"),
        )
        return None
    if token_row.get("invalidated_at") is not None:
        logger.info(
            "Upload token already invalidated for %s",
            token_row.get("invoice_number"),
        )
        return None

    return token_row


def generate_upload_link(
    base_url: str,
    tenant_id: str,
    token: str,
) -> str:
    """Build the public upload page URL for a token."""
    base = base_url.rstrip("/")
    return f"{base}/api/v1/public/upload/{tenant_id}/{token}"
