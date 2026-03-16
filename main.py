"""
NAVvoice FastAPI Application

REST API for NAV Invoice Reconciliation.
MVP: Manual and webhook-triggered reconciliation.
Phase 2: Scheduled background jobs (APScheduler / Celery Beat).
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from nav_client import NavCredentials
from reconciliation_engine import (
    run_reconciliation,
    ReconciliationConfig,
)
from invoice_agent import AgentConfig, VendorDirectory

from api.auth import router as auth_router
from api.invoices import router as invoices_router
from api.approval import router as approval_router
from api.stats import router as stats_router
from api.public import router as public_router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="NAVvoice API",
    description="NAV Invoice Reconciliation Middleware",
    version="0.2.0",
)

app.include_router(auth_router)
app.include_router(invoices_router)
app.include_router(approval_router)
app.include_router(stats_router)
app.include_router(public_router)


# =============================================================================
# REQUEST / RESPONSE MODELS
# =============================================================================


class ReconcileRequest(BaseModel):
    """Optional parameters for reconciliation run."""

    date_from: Optional[str] = Field(
        None,
        description="Start date YYYY-MM-DD (default: 30 days ago)",
    )
    date_to: Optional[str] = Field(
        None,
        description="End date YYYY-MM-DD (default: today)",
    )
    pdf_folder_path: Optional[str] = Field(
        None,
        description="PDF folder to scan (default: data/pdfs/{tenant_id})",
    )


# =============================================================================
# CREDENTIALS
# =============================================================================


def _get_nav_credentials() -> NavCredentials:
    """Load NAV credentials from environment variables."""
    login = os.getenv("NAV_TECHNICAL_USER") or os.getenv("NAV_LOGIN")
    password = os.getenv("NAV_PASSWORD")
    sig_key = os.getenv("NAV_SIGNATURE_KEY")
    repl_key = os.getenv("NAV_REPLACEMENT_KEY")
    tax = os.getenv("NAV_TAX_NUMBER")

    if not all([login, password, sig_key, repl_key, tax]):
        raise HTTPException(
            status_code=503,
            detail=(
                "NAV credentials not configured. Set NAV_TECHNICAL_USER, "
                "NAV_PASSWORD, NAV_SIGNATURE_KEY, NAV_REPLACEMENT_KEY, "
                "NAV_TAX_NUMBER"
            ),
        )

    if len(sig_key) != 32 or len(repl_key) != 32:
        raise HTTPException(
            status_code=503,
            detail="NAV_SIGNATURE_KEY and NAV_REPLACEMENT_KEY must be 32 chars",
        )

    if not tax.isdigit() or len(tax) != 8:
        raise HTTPException(
            status_code=503,
            detail="NAV_TAX_NUMBER must be 8 digits",
        )

    return NavCredentials(
        login=login,
        password=password,
        signature_key=sig_key,
        replacement_key=repl_key,
        tax_number=tax,
    )


# =============================================================================
# ENDPOINTS
# =============================================================================


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "navvoice"}


@app.post("/api/v1/tenants/{tenant_id}/reconcile")
def reconcile(
    tenant_id: str,
    body: Optional[ReconcileRequest] = None,
):
    """
    Trigger reconciliation for a tenant.

    Fetches incoming invoices from NAV, upserts to DB, scans PDF folder
    for matches, and queues AI-generated chasing emails for MISSING items.
    """
    body = body or ReconcileRequest()

    today = datetime.now().strftime("%Y-%m-%d")
    date_from = body.date_from or (
        datetime.now() - timedelta(days=30)
    ).strftime("%Y-%m-%d")
    date_to = body.date_to or today

    pdf_folder = body.pdf_folder_path or os.path.join(
        "data", "pdfs", tenant_id
    )

    nav_credentials = _get_nav_credentials()

    agent_api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    agent_config = None
    if agent_api_key:
        agent_config = AgentConfig(api_key=agent_api_key)

    config = ReconciliationConfig(
        date_from=date_from,
        date_to=date_to,
        pdf_folder_path=pdf_folder,
        nav_credentials=nav_credentials,
        days_old=0,
        db_path=os.getenv("NAVVOICE_DB_PATH", "data/invoices.db"),
        approval_queue_path=os.getenv(
            "NAVVOICE_APPROVAL_DB_PATH", "data/approvals.db"
        ),
        agent_config=agent_config,
        vendor_directory=VendorDirectory(),
        use_test_nav_api=os.getenv("NAV_USE_TEST_API", "true").lower()
        == "true",
    )

    summary = run_reconciliation(
        tenant_id=tenant_id,
        config=config,
        user_id="api",
    )

    return {
        "tenant_id": tenant_id,
        "status": "complete",
        "summary": summary,
    }


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
