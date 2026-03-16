"""
Stats router -- dashboard statistics combining invoice and queue data.
"""

import logging
from dataclasses import asdict

from fastapi import APIRouter, Depends

from auth import User, Permission
from database_manager import DatabaseManager
from approval_queue import ApprovalQueue
from api.deps import get_db, get_approval_queue, require_permission
from api.schemas import StatsResponse, InvoiceStatsBlock, QueueStatsBlock

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])


@router.get("", response_model=StatsResponse)
def dashboard_stats(
    user: User = Depends(require_permission(Permission.VIEW_INVOICES)),
    db: DatabaseManager = Depends(get_db),
    queue: ApprovalQueue = Depends(get_approval_queue),
):
    """Return combined invoice + approval-queue statistics for the tenant."""
    tenant_id = user.tenant_id

    inv_stats = db.get_statistics(tenant_id)
    q_stats = queue.get_statistics(tenant_id)

    return StatsResponse(
        invoices=InvoiceStatsBlock(**inv_stats),
        approval_queue=QueueStatsBlock(**asdict(q_stats)),
    )
