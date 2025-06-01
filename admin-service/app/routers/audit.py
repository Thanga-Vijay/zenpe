from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.admin import AdminUser
from app.schemas.admin import AuditLogCreate, AuditLog as AuditLogSchema
from app.services.audit_service import AuditService
from app.utils.auth import get_admin_user, get_current_admin_id

router = APIRouter()

@router.post("/log", response_model=AuditLogSchema)
async def create_audit_log(
    audit_data: AuditLogCreate,
    request: Request,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Manually create an audit log entry
    """
    audit_service = AuditService(db)
    try:
        return await audit_service.create_audit_log(
            action_type=audit_data.action_type,
            description=audit_data.description,
            admin_id=admin.id,
            user_id=audit_data.user_id,
            details=audit_data.details,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/logs", response_model=List[AuditLogSchema])
async def get_audit_logs(
    action_type: Optional[str] = None,
    admin_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    start_date: Optional[str] = None,  # ISO format
    end_date: Optional[str] = None,    # ISO format
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get audit logs with optional filters
    """
    audit_service = AuditService(db)
    return await audit_service.get_audit_logs(
        action_type=action_type,
        admin_id=admin_id,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset
    )

@router.get("/logs/{log_id}", response_model=AuditLogSchema)
async def get_audit_log(
    log_id: uuid.UUID,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific audit log by ID
    """
    audit_service = AuditService(db)
    try:
        return await audit_service.get_audit_log_by_id(log_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
