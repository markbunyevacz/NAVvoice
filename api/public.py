"""
Public (unauthenticated) routes for vendor self-service.

The only endpoint here is the token-protected PDF upload that vendors
reach via the link embedded in chasing emails.  No JWT is required;
authorization is provided by the HMAC upload token.
"""

import os
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status

from database_manager import DatabaseManager
from pdf_scanner import PDFMalwareScanner
from upload_links import validate_upload_token
from api.deps import get_db
from api.schemas import PublicUploadResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/public", tags=["public"])

_MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post(
    "/upload/{tenant_id}/{token}",
    response_model=PublicUploadResponse,
)
async def public_upload_pdf(
    tenant_id: str,
    token: str,
    file: UploadFile = File(...),
    db: DatabaseManager = Depends(get_db),
):
    """
    Public endpoint for vendors to upload invoice PDFs.

    Authorization is provided by the HMAC token embedded in the chasing
    email link -- no JWT required.
    """
    secret = os.getenv("UPLOAD_LINK_SECRET", "")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Upload link signing secret not configured",
        )

    token_data = validate_upload_token(token, secret)
    if token_data is None or token_data["tenant_id"] != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired upload link",
        )

    invoice_number = token_data["invoice_number"]

    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Only PDF files are accepted",
        )

    content = await file.read()
    if len(content) > _MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="File exceeds 50 MB limit",
        )

    pdf_dir = Path("data") / "pdfs" / tenant_id
    pdf_dir.mkdir(parents=True, exist_ok=True)
    dest = pdf_dir / file.filename
    dest.write_bytes(content)

    scanner = PDFMalwareScanner()
    is_safe, warnings = scanner.scan_file(dest)
    if not is_safe:
        dest.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"PDF failed security scan: {'; '.join(warnings)}",
        )

    invoice = db.get_invoice(invoice_number, tenant_id)
    matched = False
    if invoice:
        db.mark_as_received(
            tenant_id,
            invoice_number,
            pdf_path=str(dest),
            user_id="vendor-upload",
        )
        matched = True
        detail = f"PDF matched to invoice {invoice_number}"
    else:
        detail = (
            f"PDF saved but no invoice '{invoice_number}' found for tenant"
        )

    return PublicUploadResponse(
        filename=file.filename,
        matched=matched,
        invoice_number=invoice_number if matched else None,
        detail=detail,
    )
