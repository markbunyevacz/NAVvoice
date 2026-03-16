"""
Public (unauthenticated) routes for vendor self-service.

Vendors access a token-protected page from their reminder email, then
upload the missing PDF without authenticating.
"""

import html
import logging
import re
from pathlib import Path
from typing import List

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse

from approval_queue import ApprovalQueue
from database_manager import DatabaseManager
from pdf_scanner import PDFMalwareScanner, PDFContentExtractor
from upload_links import validate_upload_token
from api.deps import get_approval_queue, get_db
from api.schemas import PublicUploadResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/public", tags=["public"])

_MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB


def _safe_upload_filename(invoice_number: str, original_name: str) -> str:
    """Normalize vendor filenames to avoid traversal and overwrites."""
    original = Path(original_name or "upload.pdf").name
    stem = Path(original).stem or "upload"
    safe_stem = (
        re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "upload"
    )
    safe_invoice = (
        re.sub(r"[^A-Za-z0-9._-]+", "_", invoice_number).strip("._")
        or "invoice"
    )
    return f"{safe_invoice}_{safe_stem}.pdf"


def _render_upload_page(
    tenant_id: str,
    token: str,
    invoice_number: str,
    expires_at: object,
    detail: str = "",
    disabled: bool = False,
) -> HTMLResponse:
    """Render a tiny self-service upload page for vendors."""
    safe_invoice = html.escape(invoice_number)
    safe_detail = html.escape(detail) if detail else ""
    safe_expiry = html.escape(str(expires_at))
    submit_disabled = "disabled" if disabled else ""
    detail_block = (
        f"<p id='result'>{safe_detail}</p>"
        if safe_detail
        else "<p id='result'></p>"
    )
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html lang="hu">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Számla feltöltése</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; }}
    main {{ max-width: 36rem; margin: 0 auto; }}
    form {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 1.25rem; }}
    input, button {{ display: block; margin-top: 0.75rem; }}
    button {{ padding: 0.65rem 1rem; cursor: pointer; }}
    .muted {{ color: #6b7280; font-size: 0.95rem; }}
  </style>
</head>
<body>
  <main>
    <h1>Hiányzó számla feltöltése</h1>
    <p>A keresett számla: <strong>{safe_invoice}</strong></p>
    <p class="muted">A link lejárata: {safe_expiry}</p>
    <form id="upload-form" method="post" enctype="multipart/form-data"
          action="/api/v1/public/upload/{tenant_id}/{token}">
      <label for="file">PDF kiválasztása</label>
      <input id="file" name="file" type="file" accept="application/pdf,.pdf"
             {submit_disabled} required>
      <button type="submit" {submit_disabled}>Feltöltés</button>
    </form>
    {detail_block}
  </main>
  <script>
    const form = document.getElementById("upload-form");
    const result = document.getElementById("result");
    form?.addEventListener("submit", async (event) => {{
      event.preventDefault();
      result.textContent = "Feltöltés folyamatban...";
      const response = await fetch(form.action, {{
        method: "POST",
        body: new FormData(form),
      }});
      const data = await response.json();
      result.textContent = data.detail || "Ismeretlen válasz érkezett.";
    }});
  </script>
</body>
</html>"""
    )


def _get_valid_token_or_403(
    db: DatabaseManager,
    tenant_id: str,
    token: str,
):
    token_data = validate_upload_token(db, token)
    if token_data is None or token_data["tenant_id"] != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired upload link",
        )
    return token_data


@router.get(
    "/upload/{tenant_id}/{token}",
    response_class=HTMLResponse,
)
def public_upload_page(
    tenant_id: str,
    token: str,
    db: DatabaseManager = Depends(get_db),
):
    """Render the vendor-facing upload page."""
    token_data = validate_upload_token(db, token)
    if token_data is None or token_data["tenant_id"] != tenant_id:
        return _render_upload_page(
            tenant_id=tenant_id,
            token=token,
            invoice_number="ismeretlen",
            expires_at="lejart",
            detail="A feltoltesi link ervenytelen vagy mar lejart.",
            disabled=True,
        )

    return _render_upload_page(
        tenant_id=tenant_id,
        token=token,
        invoice_number=token_data["invoice_number"],
        expires_at=token_data["expires_at"],
    )


@router.post(
    "/upload/{tenant_id}/{token}",
    response_model=PublicUploadResponse,
)
async def public_upload_pdf(
    request: Request,
    tenant_id: str,
    token: str,
    file: UploadFile = File(...),
    db: DatabaseManager = Depends(get_db),
    queue: ApprovalQueue = Depends(get_approval_queue),
):
    """
    Public endpoint for vendors to upload invoice PDFs.

    Authorization is provided by the one-time upload token embedded in
    the chasing email link -- no JWT required.
    """
    token_data = _get_valid_token_or_403(db, tenant_id, token)
    invoice_number = token_data["invoice_number"]

    if not file.filename or not file.filename.lower().endswith(".pdf"):
        db.log_upload_attempt(
            token=token,
            tenant_id=tenant_id,
            action="UPLOAD_REJECTED",
            details="Rejected non-PDF upload",
            error="Only PDF files are accepted",
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Only PDF files are accepted",
        )

    content = await file.read()
    if len(content) > _MAX_UPLOAD_SIZE:
        db.log_upload_attempt(
            token=token,
            tenant_id=tenant_id,
            action="UPLOAD_REJECTED",
            details="Rejected oversized upload",
            upload_filename=file.filename,
            error="File exceeds 50 MB limit",
        )
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="File exceeds 50 MB limit",
        )

    pdf_dir = Path("data") / "pdfs" / tenant_id
    pdf_dir.mkdir(parents=True, exist_ok=True)
    dest = pdf_dir / _safe_upload_filename(invoice_number, file.filename)
    dest.write_bytes(content)

    scanner = PDFMalwareScanner()
    is_safe, warnings = scanner.scan_file(dest)
    if not is_safe:
        dest.unlink(missing_ok=True)
        db.log_upload_attempt(
            token=token,
            tenant_id=tenant_id,
            action="UPLOAD_REJECTED",
            details="PDF failed malware scan",
            upload_filename=file.filename,
            error="; ".join(warnings),
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"PDF failed security scan: {'; '.join(warnings)}",
        )

    invoice = db.get_invoice(invoice_number, tenant_id)
    matched = False
    extracted_invoice_data = PDFContentExtractor().extract_invoice_data(dest)
    extracted_candidates = extracted_invoice_data.get("invoice_numbers")
    extracted_numbers: List[str] = []
    if isinstance(extracted_candidates, list):
        extracted_numbers = [
            item[0]
            for item in extracted_candidates
            if isinstance(item, tuple) and item
        ]
    if invoice:
        if extracted_numbers and invoice_number not in extracted_numbers:
            detail = (
                "PDF elmentve, de a tartalomban nem talalhato a "
                f"{invoice_number} szamlaazonosito."
            )
            db.log_upload_attempt(
                token=token,
                tenant_id=tenant_id,
                action="UPLOAD_UNMATCHED",
                details=detail,
                upload_filename=file.filename,
                upload_path=str(dest),
                error=detail,
            )
        else:
            db.mark_as_received(
                tenant_id,
                invoice_number,
                pdf_path=str(dest),
                user_id="vendor-upload",
            )
            db.mark_upload_token_used(
                token=token,
                tenant_id=tenant_id,
                upload_ip=request.client.host if request.client else None,
                upload_filename=file.filename,
                upload_path=str(dest),
            )
            queue_item_id = token_data.get("queue_item_id")
            if queue_item_id:
                queue.close_item(
                    queue_item_id,
                    user_id="vendor-upload",
                    notes="Vendor upload received",
                )
            else:
                queue.close_for_invoice(
                    tenant_id=tenant_id,
                    invoice_number=invoice_number,
                    user_id="vendor-upload",
                    notes="Vendor upload received",
                )
            matched = True
            detail = f"PDF matched to invoice {invoice_number}"
    else:
        detail = (
            f"PDF saved but no invoice '{invoice_number}' found for tenant"
        )
        db.log_upload_attempt(
            token=token,
            tenant_id=tenant_id,
            action="UPLOAD_UNMATCHED",
            details=detail,
            upload_filename=file.filename,
            upload_path=str(dest),
            error=detail,
        )

    return PublicUploadResponse(
        filename=dest.name,
        matched=matched,
        invoice_number=invoice_number if matched else None,
        detail=detail,
    )
