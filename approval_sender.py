"""
Helpers for sending approved queue items with persisted vendor upload links.
"""

import os
import re
from typing import Any, Dict, Optional

from approval_queue import ApprovalQueue
from database_manager import DatabaseManager
from invoice_agent import Mailer
from email_backend import create_email_backend
from upload_links import create_upload_link

_UPLOAD_LINK_PATTERN = re.compile(
    r"Számla feltöltése az alábbi linken:\s*\S+",
    re.IGNORECASE,
)


def create_mailer_from_env() -> Mailer:
    """Create a mailer using the configured email backend environment."""
    backend_type = os.getenv("EMAIL_BACKEND", "gmail")
    backend = create_email_backend(
        backend_type,
        sender_email=os.getenv("SMTP_EMAIL", ""),
        sender_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_server=os.getenv("SMTP_SERVER", "smtp.gmail.com"),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        sender_name=os.getenv("SMTP_SENDER_NAME", "NAVvoice"),
    )
    return Mailer(backend)


def _inject_upload_link(email_body: str, link: str) -> str:
    """Append or replace the upload-link footer in an email body."""
    line = f"Számla feltöltése az alábbi linken: {link}"
    if _UPLOAD_LINK_PATTERN.search(email_body):
        return _UPLOAD_LINK_PATTERN.sub(line, email_body)
    return f"{email_body.rstrip()}\n\n{line}"


def send_approved_queue_items(
    queue: ApprovalQueue,
    db: DatabaseManager,
    user_id: str = "system",
    tenant_id: Optional[str] = None,
    limit: int = 50,
    mailer: Optional[Mailer] = None,
    app_base_url: Optional[str] = None,
    expires_hours: Optional[int] = None,
) -> Dict[str, Any]:
    """Send approved emails and close queue/invoice lifecycle transitions."""
    resolved_mailer = mailer or create_mailer_from_env()
    resolved_base_url = app_base_url or os.getenv(
        "APP_BASE_URL",
        "https://app.navvoice.hu",
    )
    base_url = resolved_base_url.rstrip("/")

    approved_items = queue.get_approved_emails(tenant_id=tenant_id, limit=limit)
    summary: Dict[str, Any] = {
        "processed": 0,
        "sent": 0,
        "failed": 0,
        "skipped": 0,
        "items": [],
    }

    for item in approved_items:
        summary["processed"] += 1
        invoice = db.get_invoice(item.invoice_number, item.tenant_id)
        if not invoice:
            summary["skipped"] += 1
            summary["items"].append(
                {
                    "item_id": item.id,
                    "invoice_number": item.invoice_number,
                    "status": "skipped",
                    "detail": "Invoice no longer exists",
                }
            )
            continue
        if invoice.get("status") == "RECEIVED":
            db.invalidate_upload_tokens(
                tenant_id=item.tenant_id,
                invoice_number=item.invoice_number,
                reason="Invoice already received before email send",
                user_id=user_id,
            )
            summary["skipped"] += 1
            summary["items"].append(
                {
                    "item_id": item.id,
                    "invoice_number": item.invoice_number,
                    "status": "skipped",
                    "detail": "Invoice already received",
                }
            )
            continue

        upload = create_upload_link(
            db=db,
            base_url=base_url,
            tenant_id=item.tenant_id,
            invoice_number=item.invoice_number,
            queue_item_id=item.id,
            vendor_email=item.vendor_email,
            created_by=user_id,
            expires_hours=expires_hours,
        )
        email_body = _inject_upload_link(item.email_body, upload["url"])
        send_result = resolved_mailer.send_email(
            to_email=item.vendor_email,
            subject=item.email_subject,
            body=email_body,
        )
        if not send_result.get("success"):
            db.invalidate_upload_tokens(
                tenant_id=item.tenant_id,
                token=upload["token"],
                reason=(
                    "Email delivery failed: "
                    f"{send_result.get('error', 'unknown error')}"
                ),
                user_id=user_id,
            )
            summary["failed"] += 1
            summary["items"].append(
                {
                    "item_id": item.id,
                    "invoice_number": item.invoice_number,
                    "status": "failed",
                    "detail": send_result.get("error", "Email delivery failed"),
                }
            )
            continue

        queue.mark_as_sent(item.id, user_id=user_id)
        db.mark_as_emailed(
            item.tenant_id,
            item.invoice_number,
            user_id=user_id,
        )
        summary["sent"] += 1
        summary["items"].append(
            {
                "item_id": item.id,
                "invoice_number": item.invoice_number,
                "status": "sent",
                "detail": f"Email sent to {item.vendor_email}",
                "upload_url": upload["url"],
            }
        )

    return summary
