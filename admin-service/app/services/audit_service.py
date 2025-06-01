import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.admin import AuditLog

class AuditService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_audit_log(
        self,
        action_type: str,
        description: str,
        admin_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        details: Dict[str, Any] = {},
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """
        Create an audit log entry
        """
        audit_log = AuditLog(
            action_by=admin_id,
            user_id=user_id,
            action_type=action_type,
            description=description,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.db.add(audit_log)
        await self.db.commit()
        await self.db.refresh(audit_log)
        return audit_log
    
    async def get_audit_logs(
        self,
        action_type: Optional[str] = None,
        admin_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[AuditLog]:
        """
        Get audit logs with optional filters
        """
        query = select(AuditLog)
        
        # Apply filters
        filters = []
        if action_type:
            filters.append(AuditLog.action_type == action_type)
        if admin_id:
            filters.append(AuditLog.action_by == admin_id)
        if user_id:
            filters.append(AuditLog.user_id == user_id)
        
        # Date filters
        if start_date:
            start_datetime = datetime.fromisoformat(start_date)
            filters.append(AuditLog.created_at >= start_datetime)
        if end_date:
            end_datetime = datetime.fromisoformat(end_date)
            filters.append(AuditLog.created_at <= end_datetime)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(desc(AuditLog.created_at))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_audit_log_by_id(self, log_id: uuid.UUID) -> AuditLog:
        """
        Get a specific audit log by ID
        """
        query = select(AuditLog).where(AuditLog.id == log_id)
        result = await self.db.execute(query)
        audit_log = result.scalars().first()
        
        if not audit_log:
            raise ValueError(f"Audit log not found with ID: {log_id}")
        
        return audit_log
