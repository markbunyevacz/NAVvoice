"""
Tenant-Scoped Upload Link Generation and Validation

Generates HMAC-signed, time-limited tokens that vendors can use to upload
invoice PDFs without authenticating.  The token encodes the tenant ID,
invoice number, and an expiry timestamp; the HMAC prevents tampering.

Usage:
    link = generate_upload_link(
        base_url="https://app.navvoice.hu",
        tenant_id="t-001",
        invoice_number="INV-2024-001",
        secret="my-secret-key",
    )
    # link = "https://app.navvoice.hu/api/v1/public/upload/t-001/<token>"
"""

import base64
import hashlib
import hmac
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_EXPIRY_HOURS = 168  # 7 days


def generate_upload_token(
    tenant_id: str,
    invoice_number: str,
    secret: str,
    expires_hours: int = DEFAULT_EXPIRY_HOURS,
) -> str:
    """
    Create an HMAC-SHA256 signed token encoding tenant, invoice, and expiry.

    Token format: ``<base64url(payload)>.<signature_hex[:16]>``

    Args:
        tenant_id: Tenant identifier.
        invoice_number: NAV invoice number.
        secret: Server-side signing secret.
        expires_hours: Hours until the token expires (default 168 = 7 days).

    Returns:
        URL-safe token string.
    """
    expiry = int(time.time()) + expires_hours * 3600
    payload = f"{tenant_id}:{invoice_number}:{expiry}"
    sig = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    encoded = base64.urlsafe_b64encode(
        payload.encode("utf-8"),
    ).decode("ascii").rstrip("=")
    return f"{encoded}.{sig}"


def validate_upload_token(
    token: str,
    secret: str,
) -> Optional[Dict[str, Any]]:
    """
    Validate and decode an upload token.

    Returns:
        Dict with ``tenant_id``, ``invoice_number``, ``expiry`` on success,
        or ``None`` if the token is invalid, expired, or tampered with.
    """
    if not token or "." not in token:
        return None

    parts = token.split(".", 1)
    if len(parts) != 2:
        return None

    encoded_payload, provided_sig = parts

    try:
        padded = encoded_payload + "=" * (-len(encoded_payload) % 4)
        raw = padded.encode("ascii")
        payload = base64.urlsafe_b64decode(raw).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        logger.warning("Upload token base64 decode failed")
        return None

    segments = payload.split(":")
    if len(segments) != 3:
        logger.warning("Upload token payload has wrong segment count")
        return None

    tenant_id, invoice_number, expiry_str = segments

    try:
        expiry = int(expiry_str)
    except ValueError:
        logger.warning("Upload token expiry is not an integer")
        return None

    expected_sig = hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]  # truncated for URL brevity

    if not hmac.compare_digest(provided_sig, expected_sig):
        logger.warning("Upload token HMAC mismatch")
        return None

    if time.time() > expiry:
        logger.info("Upload token expired for %s / %s", tenant_id, invoice_number)
        return None

    return {
        "tenant_id": tenant_id,
        "invoice_number": invoice_number,
        "expiry": expiry,
    }


def generate_upload_link(
    base_url: str,
    tenant_id: str,
    invoice_number: str,
    secret: str,
    expires_hours: int = DEFAULT_EXPIRY_HOURS,
) -> str:
    """
    Build a full upload URL for inclusion in chasing emails.

    Args:
        base_url: Application root URL (e.g. ``https://app.navvoice.hu``).
        tenant_id: Tenant identifier.
        invoice_number: NAV invoice number.
        secret: Server-side signing secret.
        expires_hours: Token lifetime in hours.

    Returns:
        Full URL string.
    """
    token = generate_upload_token(
        tenant_id, invoice_number, secret, expires_hours,
    )
    base = base_url.rstrip("/")
    return f"{base}/api/v1/public/upload/{tenant_id}/{token}"
