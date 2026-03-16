"""
Invoice router -- list, NAV sync, and PDF upload.

Wraps DatabaseManager queries and the reconciliation engine.
Tenant isolation is enforced via the JWT-extracted user.tenant_id.
"""

import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter, Depends, HTTPException,
    Query, UploadFile, File, status,
)

from auth import User, Permission
from database_manager import DatabaseManager, InvoiceStatus
from api.deps import get_db, require_permission
from api.schemas import (
    InvoiceResponse,
    InvoiceListResponse,
    SyncRequest,
    SyncResponse,
    UploadResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/invoices", tags=["invoices"])

_VALID_STATUSES = {s.value for s in InvoiceStatus}


@router.get("", response_model=InvoiceListResponse)
def list_invoices(
    status_filter: Optional[str] = Query(None, alias="status", description="MISSING|RECEIVED|EMAILED|ESCALATED"),
    date_from: Optional[str] = Query(None, description="Earliest invoice_date YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="Latest invoice_date YYYY-MM-DD"),
    query: Optional[str] = Query(None, description="Free-text search (invoice number / vendor)"),
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(require_permission(Permission.VIEW_INVOICES)),
    db: DatabaseManager = Depends(get_db),
):
    """List invoices for the authenticated tenant with optional filters."""
    tenant_id = user.tenant_id

    if query:
        rows = db.search_invoices(tenant_id, query, limit=limit)
    elif status_filter:
        if status_filter not in _VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid status. Must be one of: {', '.join(sorted(_VALID_STATUSES))}",
            )
        rows = db.get_invoices_by_status(tenant_id, InvoiceStatus(status_filter))
    else:
        rows = db.search_invoices(tenant_id, "", limit=limit)

    if date_from:
        rows = [r for r in rows if r.get("invoice_date", "") >= date_from]
    if date_to:
        rows = [r for r in rows if r.get("invoice_date", "") <= date_to]

    items = [InvoiceResponse(**r) for r in rows]
    return InvoiceListResponse(items=items, count=len(items))


@router.post("/sync", response_model=SyncResponse)
def sync_invoices(
    body: Optional[SyncRequest] = None,
    user: User = Depends(require_permission(Permission.RECONCILE_INVOICES)),
    db: DatabaseManager = Depends(get_db),
):
    """Trigger NAV synchronisation for the authenticated tenant."""
    from nav_client import NavCredentials
    from reconciliation_engine import run_reconciliation, ReconciliationConfig
    from invoice_agent import AgentConfig, VendorDirectory

    body = body or SyncRequest()
    tenant_id = user.tenant_id

    today = datetime.now().strftime("%Y-%m-%d")
    date_from = body.date_from or (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    date_to = body.date_to or today
    pdf_folder = body.pdf_folder_path or os.path.join("data", "pdfs", tenant_id)

    nav_login = os.getenv("NAV_TECHNICAL_USER") or os.getenv("NAV_LOGIN")
    nav_password = os.getenv("NAV_PASSWORD")
    sig_key = os.getenv("NAV_SIGNATURE_KEY")
    repl_key = os.getenv("NAV_REPLACEMENT_KEY")
    tax = os.getenv("NAV_TAX_NUMBER")

    if not all([nav_login, nav_password, sig_key, repl_key, tax]):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NAV credentials not configured on the server",
        )

    nav_credentials = NavCredentials(
        login=nav_login,
        password=nav_password,
        signature_key=sig_key,
        replacement_key=repl_key,
        tax_number=tax,
    )

    agent_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    agent_config = AgentConfig(api_key=agent_api_key) if agent_api_key else None

    config = ReconciliationConfig(
        date_from=date_from,
        date_to=date_to,
        pdf_folder_path=pdf_folder,
        nav_credentials=nav_credentials,
        days_old=0,
        db_path=str(db.db_path),
        approval_queue_path=os.getenv("NAVVOICE_APPROVAL_DB_PATH", "data/approvals.db"),
        agent_config=agent_config,
        vendor_directory=VendorDirectory(),
        use_test_nav_api=os.getenv("NAV_USE_TEST_API", "true").lower() == "true",
    )

    summary = run_reconciliation(tenant_id=tenant_id, config=config, user_id=user.id)

    return SyncResponse(tenant_id=tenant_id, status="complete", summary=summary)


_MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post("/{invoice_id}/upload", response_model=UploadResponse)
async def upload_pdf(
    invoice_id: str,
    file: UploadFile = File(...),
    user: User = Depends(require_permission(Permission.UPLOAD_INVOICES)),
    db: DatabaseManager = Depends(get_db),
):
    """Upload a PDF and match it to an existing invoice."""
    tenant_id = user.tenant_id

    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Only PDF files are accepted",
        )

    content = await file.read()
    if len(content) > _MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds 50 MB limit",
        )

    from pdf_scanner import PDFMalwareScanner

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

    invoice = db.get_invoice(invoice_id, tenant_id)
    matched = False
    if invoice:
        db.mark_as_received(tenant_id, invoice_id, pdf_path=str(dest), user_id=user.id)
        matched = True
        detail = f"PDF matched to invoice {invoice_id}"
    else:
        detail = f"PDF saved but no invoice '{invoice_id}' found for tenant"

    return UploadResponse(
        filename=file.filename,
        saved_path=str(dest),
        matched=matched,
        invoice_number=invoice_id if matched else None,
        detail=detail,
    )
