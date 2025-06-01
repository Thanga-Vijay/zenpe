from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.admin import AdminUser
from app.schemas.admin import AdminUserCreate, AdminUser as AdminUserSchema, AdminLogin, Token, DashboardMetrics, BlockUserRequest
from app.services.admin_service import AdminService
from app.utils.auth import get_admin_user, get_current_admin_id

router = APIRouter()

@router.post("/login", response_model=Token)
async def admin_login(
    login_data: AdminLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Admin login endpoint
    """
    admin_service = AdminService(db)
    try:
        return await admin_service.authenticate_admin(login_data.email, login_data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.get("/dashboard", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get admin dashboard metrics
    """
    admin_service = AdminService(db)
    return await admin_service.get_dashboard_metrics()

@router.post("/users", response_model=AdminUserSchema)
async def create_admin_user(
    admin_data: AdminUserCreate,
    current_admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new admin user (super admin only)
    """
    if current_admin.role != "SuperAdmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can create admin users"
        )
    
    admin_service = AdminService(db)
    try:
        return await admin_service.create_admin_user(admin_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/users", response_model=List[AdminUserSchema])
async def list_admin_users(
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all admin users
    """
    admin_service = AdminService(db)
    return await admin_service.list_admin_users()

@router.post("/block-user", status_code=status.HTTP_200_OK)
async def block_user(
    block_data: BlockUserRequest,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Block a user
    """
    admin_service = AdminService(db)
    try:
        await admin_service.block_user(block_data.user_id, admin.id, block_data.reason)
        return {"message": "User blocked successfully"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
