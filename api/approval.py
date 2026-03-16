"""
Approval-queue router -- list pending emails, approve, reject.

Wraps ApprovalQueue methods with RBAC enforcement.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from auth import User, Permission
from approval_queue import ApprovalQueue
from api.deps import get_approval_queue, require_permission
from api.schemas import (
    QueueItemResponse,
    ApprovalListResponse,
    ApproveRequest,
    RejectRequest,
    ApprovalActionResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/approval-queue", tags=["approval-queue"])


@router.get("", response_model=ApprovalListResponse)
def list_pending(
    limit: int = Query(50, ge=1, le=200),
    user: User = Depends(require_permission(Permission.VIEW_EMAILS)),
    queue: ApprovalQueue = Depends(get_approval_queue),
):
    """List pending approval-queue items for the authenticated tenant."""
    items = queue.get_pending_emails(tenant_id=user.tenant_id, limit=limit)
    converted = [QueueItemResponse(**item.to_dict()) for item in items]
    return ApprovalListResponse(items=converted, count=len(converted))


@router.post("/{item_id}/approve", response_model=ApprovalActionResponse)
def approve_item(
    item_id: str,
    body: Optional[ApproveRequest] = None,
    user: User = Depends(require_permission(Permission.APPROVE_EMAILS)),
    queue: ApprovalQueue = Depends(get_approval_queue),
):
    """Approve a pending email for sending."""
    body = body or ApproveRequest()

    existing = queue.get_item(item_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Queue item not found")
    if existing.tenant_id != user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Queue item not found")

    ok = queue.approve(item_id, user_id=user.id, notes=body.notes)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Item cannot be approved (not in PENDING status)",
        )

    return ApprovalActionResponse(
        success=True,
        item_id=item_id,
        new_status="approved",
        detail="Email approved for sending",
    )


@router.post("/{item_id}/reject", response_model=ApprovalActionResponse)
def reject_item(
    item_id: str,
    body: RejectRequest,
    user: User = Depends(require_permission(Permission.APPROVE_EMAILS)),
    queue: ApprovalQueue = Depends(get_approval_queue),
):
    """Reject a pending email (will not be sent)."""
    existing = queue.get_item(item_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Queue item not found")
    if existing.tenant_id != user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Queue item not found")

    ok = queue.reject(item_id, user_id=user.id, reason=body.reason)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Item cannot be rejected (not in PENDING status or reason too short)",
        )

    return ApprovalActionResponse(
        success=True,
        item_id=item_id,
        new_status="rejected",
        detail="Email rejected",
    )
