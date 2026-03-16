"""
Project router -- tenant-scoped project listing and maintenance.
"""

import logging
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query, status

from auth import User, Permission
from database_manager import DatabaseManager
from api.deps import get_db, require_permission
from api.schemas import (
    ProjectCreateRequest,
    ProjectListResponse,
    ProjectResponse,
    ProjectUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


@router.get("", response_model=ProjectListResponse)
def list_projects(
    include_inactive: bool = Query(False, description="Include inactive tenant projects"),
    user: User = Depends(require_permission(Permission.VIEW_INVOICES)),
    db: DatabaseManager = Depends(get_db),
):
    """List projects for the authenticated tenant."""
    rows = db.list_projects(user.tenant_id, include_inactive=include_inactive)
    items = [ProjectResponse(**row) for row in rows]
    return ProjectListResponse(items=items, count=len(items))


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    body: ProjectCreateRequest,
    user: User = Depends(require_permission(Permission.RECONCILE_INVOICES)),
    db: DatabaseManager = Depends(get_db),
):
    """Create a tenant-scoped project."""
    try:
        project = db.create_project(
            tenant_id=user.tenant_id,
            project_code=body.project_code,
            project_name=body.project_name,
            aliases=body.aliases,
            reference_patterns=body.reference_patterns,
            is_active=body.is_active,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Project code already exists for tenant",
        ) from exc

    return ProjectResponse(**project)


@router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: int,
    body: ProjectUpdateRequest,
    user: User = Depends(require_permission(Permission.RECONCILE_INVOICES)),
    db: DatabaseManager = Depends(get_db),
):
    """Update a tenant-scoped project."""
    try:
        project = db.update_project(
            tenant_id=user.tenant_id,
            project_id=project_id,
            project_code=body.project_code,
            project_name=body.project_name,
            aliases=body.aliases,
            reference_patterns=body.reference_patterns,
            is_active=body.is_active,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Project code already exists for tenant",
        ) from exc

    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found for tenant",
        )

    return ProjectResponse(**project)
