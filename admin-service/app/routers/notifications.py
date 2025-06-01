from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.admin import AdminUser, Notification
from app.schemas.admin import NotificationCreate, Notification as NotificationSchema
from app.services.notification_service import NotificationService
from app.utils.auth import get_admin_user, get_current_admin_id, get_current_user_id

router = APIRouter()

@router.post("/send", status_code=status.HTTP_202_ACCEPTED)
async def send_notification(
    notification_data: NotificationCreate,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Send notification to user or admin
    """
    notification_service = NotificationService(db)
    try:
        await notification_service.send_notification(notification_data, sender_id=admin.id)
        return {"message": "Notification queued for delivery"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/logs", response_model=List[NotificationSchema])
async def get_notification_logs(
    user_id: Optional[uuid.UUID] = None,
    admin_id: Optional[uuid.UUID] = None,
    type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get notification logs
    """
    notification_service = NotificationService(db)
    return await notification_service.get_notification_logs(
        user_id=user_id,
        admin_id=admin_id,
        type=type,
        status=status,
        limit=limit,
        offset=offset
    )

@router.get("/user", response_model=List[NotificationSchema])
async def get_user_notifications(
    user_id: uuid.UUID = Depends(get_current_user_id),
    is_read: Optional[bool] = None,
    limit: int = Query(10, ge=1, le=50),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    Get notifications for a user
    """
    notification_service = NotificationService(db)
    return await notification_service.get_user_notifications(
        user_id=user_id,
        is_read=is_read,
        limit=limit,
        offset=offset
    )

@router.post("/user/read/{notification_id}", status_code=status.HTTP_200_OK)
async def mark_notification_read(
    notification_id: uuid.UUID,
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Mark a notification as read
    """
    notification_service = NotificationService(db)
    try:
        await notification_service.mark_notification_read(notification_id, user_id)
        return {"message": "Notification marked as read"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
