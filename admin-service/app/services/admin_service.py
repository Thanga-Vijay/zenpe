from app.utils.caching import cache_result, invalidate_cache
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
from jose import jwt

from app.models.admin import AdminUser
from app.schemas.admin import AdminUserCreate, Token, DashboardMetrics
from app.utils.security import get_password_hash, verify_password
from app.services.audit_service import AuditService
from app.config import settings

class AdminService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_service = AuditService(db)
    
    async def authenticate_admin(self, email: str, password: str) -> Token:
        """
        Authenticate admin user and return JWT token
        """
        query = select(AdminUser).where(AdminUser.email == email)
        result = await self.db.execute(query)
        admin = result.scalars().first()
        
        if not admin or not verify_password(password, admin.password_hash):
            raise ValueError("Invalid credentials")
        
        if not admin.is_active:
            raise ValueError("Admin account is inactive")
        
        # Update last login
        admin.last_login = datetime.utcnow()
        await self.db.commit()
        
        # Create access token
        token_data = {
            "sub": str(admin.id),
            "email": admin.email,
            "role": admin.role,
            "permissions": admin.permissions,
            "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        }
        access_token = jwt.encode(token_data, settings.JWT_SECRET_KEY, algorithm="HS256")
        
        # Log login
        await self.audit_service.create_audit_log(
            action_type="Admin_Login",
            description=f"Admin login: {admin.email}",
            admin_id=admin.id,
            details={"email": admin.email}
        )
        
        return Token(access_token=access_token, token_type="bearer")
    
    async def create_admin_user(self, admin_data: AdminUserCreate) -> AdminUser:
        """
        Create a new admin user
        """
        # Check if email already exists
        query = select(AdminUser).where(AdminUser.email == admin_data.email)
        result = await self.db.execute(query)
        if result.scalars().first():
            raise ValueError(f"Admin with email {admin_data.email} already exists")
        
        # Create admin user
        hashed_password = get_password_hash(admin_data.password)
        admin = AdminUser(
            admin_name=admin_data.admin_name,
            email=admin_data.email,
            password_hash=hashed_password,
            role=admin_data.role,
            permissions=admin_data.permissions
        )
        
        self.db.add(admin)
        await self.db.commit()
        await self.db.refresh(admin)`n        # After creating admin, invalidate cache for admin list`n        invalidate_cache("app.services.admin_service.AdminService.list_admin_users")`n        # After creating admin, invalidate cache for admin list`n        invalidate_cache("app.services.admin_service.AdminService.list_admin_users")
        
        # Log creation
        await self.audit_service.create_audit_log(
            action_type="Admin_Created",
            description=f"Admin user created: {admin.email} with role {admin.role}",
            admin_id=admin.id,
            details={"email": admin.email, "role": admin.role}
        )
        
        return admin
    
    @cache_result(ttl_seconds=600)  # Cache for 10 minutes`n    @cache_result(ttl_seconds=600)  # Cache for 10 minutes`n    async def list_admin_users(self) -> List[AdminUser]:
        """
        List all admin users
        """
        query = select(AdminUser)
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_admin_by_id(self, admin_id: uuid.UUID) -> Optional[AdminUser]:
        """
        Get admin by ID
        """
        query = select(AdminUser).where(AdminUser.id == admin_id)
        result = await self.db.execute(query)
        return result.scalars().first()
    
    async def block_user(self, user_id: uuid.UUID, admin_id: uuid.UUID, reason: str) -> None:
        """
        Block a user (by setting is_active to False in User service)
        This is a placeholder implementation - in reality, this would call User service API
        """
        # In a real implementation, make an API call to User service to block the user
        # For this demo, we'll just log the action
        
        await self.audit_service.create_audit_log(
            action_type="User_Blocked",
            description=f"User {user_id} blocked",
            admin_id=admin_id,
            user_id=user_id,
            details={"reason": reason}
        )
        
        # Also send a notification to the user
        # This would be implemented in a real system
        
    @cache_result(ttl_seconds=300)  # Cache for 5 minutes`n    @cache_result(ttl_seconds=300)  # Cache for 5 minutes`n    async def get_dashboard_metrics(self) -> DashboardMetrics:
        """
        Get metrics for admin dashboard
        This is a placeholder implementation with mock data
        In a real application, this would query various services
        """
        # Mock data for demonstration
        return DashboardMetrics(
            total_users=1250,
            active_users=980,
            total_transactions=3456,
            transaction_volume=345670.50,
            recent_transactions=[
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(uuid.uuid4()),
                    "amount": 1500.00,
                    "status": "Success",
                    "created_at": datetime.utcnow().isoformat()
                },
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(uuid.uuid4()),
                    "amount": 2500.00,
                    "status": "Processing",
                    "created_at": datetime.utcnow().isoformat()
                }
            ],
            pending_kyc=45,
            success_rate=92.5
        )


