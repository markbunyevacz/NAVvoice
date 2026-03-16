"""
Pydantic request / response models for the NAVvoice REST API.

These are thin serialisation boundaries -- business logic lives in the
service modules (auth, database_manager, approval_queue).
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="Plain-text password")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token issued at login")


class UserInfo(BaseModel):
    id: str
    email: str
    role: str
    tenant_id: str
    name: str
    is_active: bool
    mfa_enabled: bool


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserInfo


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ---------------------------------------------------------------------------
# Invoices
# ---------------------------------------------------------------------------

class InvoiceResponse(BaseModel):
    id: Optional[int] = None
    tenant_id: str
    nav_invoice_number: str
    vendor_name: str
    vendor_tax_number: Optional[str] = None
    amount: float
    currency: str = "HUF"
    invoice_date: str
    status: str
    last_updated: Optional[str] = None
    email_count: int = 0
    pdf_path: Optional[str] = None
    notes: Optional[str] = None
    project_id: Optional[int] = None
    project_code: Optional[str] = None
    project_name: Optional[str] = None
    has_warnings: bool = False
    warning_count: int = 0
    warning_codes: Optional[str] = None
    has_blocking_warnings: bool = False
    last_validated_at: Optional[str] = None


class InvoiceListResponse(BaseModel):
    items: List[InvoiceResponse]
    count: int


class SyncRequest(BaseModel):
    date_from: Optional[str] = Field(
        None, description="Start date YYYY-MM-DD (default: 30 days ago)"
    )
    date_to: Optional[str] = Field(
        None, description="End date YYYY-MM-DD (default: today)"
    )
    pdf_folder_path: Optional[str] = Field(
        None, description="PDF folder to scan (default: data/pdfs/{tenant_id})"
    )


class SyncResponse(BaseModel):
    tenant_id: str
    status: str
    summary: Dict[str, Any]


class InvoiceProjectAssignmentRequest(BaseModel):
    project_id: Optional[int] = Field(
        None,
        description="Tenant-scoped project ID. Use null to clear assignment.",
    )


class UploadResponse(BaseModel):
    filename: str
    saved_path: str
    matched: bool
    invoice_number: Optional[str] = None
    detail: str


class PublicUploadResponse(BaseModel):
    """Response for the unauthenticated vendor upload endpoint."""
    filename: str
    matched: bool
    invoice_number: Optional[str] = None
    detail: str


class ProjectResponse(BaseModel):
    id: int
    tenant_id: str
    project_code: str
    project_name: str
    aliases: Optional[str] = None
    reference_patterns: Optional[str] = None
    is_active: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ProjectListResponse(BaseModel):
    items: List[ProjectResponse]
    count: int


class ProjectCreateRequest(BaseModel):
    project_code: str = Field(..., min_length=1, max_length=100)
    project_name: str = Field(..., min_length=1, max_length=200)
    aliases: Optional[str] = Field(
        None,
        description="Optional aliases or free-form references for matching.",
    )
    reference_patterns: Optional[str] = Field(
        None,
        description="Optional matching hints or project reference patterns.",
    )
    is_active: bool = True


class ProjectUpdateRequest(BaseModel):
    project_code: Optional[str] = Field(None, min_length=1, max_length=100)
    project_name: Optional[str] = Field(None, min_length=1, max_length=200)
    aliases: Optional[str] = None
    reference_patterns: Optional[str] = None
    is_active: Optional[bool] = None


# ---------------------------------------------------------------------------
# Approval Queue
# ---------------------------------------------------------------------------

class QueueItemResponse(BaseModel):
    id: str
    tenant_id: str
    invoice_number: str
    vendor_name: str
    vendor_email: str
    email_subject: str
    email_body: str
    email_tone: str
    amount: float
    invoice_date: Optional[str] = None
    status: str
    priority: int
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    expires_at: Optional[str] = None
    created_by: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    rejection_reason: Optional[str] = None
    attempt_number: int = 1


class ApprovalListResponse(BaseModel):
    items: List[QueueItemResponse]
    count: int


class RejectRequest(BaseModel):
    reason: str = Field(
        ..., min_length=5, description="Rejection reason (min 5 chars)"
    )


class ApproveRequest(BaseModel):
    notes: Optional[str] = Field(None, description="Optional approval notes")


class ApprovalActionResponse(BaseModel):
    success: bool
    item_id: str
    new_status: str
    detail: str


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class InvoiceStatsBlock(BaseModel):
    tenant_id: str
    total_invoices: int
    critical_missing: int
    by_status: Dict[str, Any]
    warning_invoices: int = 0
    blocking_warning_invoices: int = 0


class QueueStatsBlock(BaseModel):
    total: int
    pending: int
    approved: int
    rejected: int
    sent: int
    expired: int
    avg_approval_time_hours: float
    oldest_pending_hours: float


class StatsResponse(BaseModel):
    invoices: InvoiceStatsBlock
    approval_queue: QueueStatsBlock
