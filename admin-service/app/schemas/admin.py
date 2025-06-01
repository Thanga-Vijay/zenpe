import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator

class AdminUserBase(BaseModel):
    admin_name: str
    email: EmailStr
    role: str
    permissions: Dict[str, Any] = {}

class AdminUserCreate(AdminUserBase):
    password: str

class AdminUserUpdate(BaseModel):
    admin_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    permissions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class AdminUser(AdminUserBase):
    id: uuid.UUID
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    admin_id: str
    role: str
    permissions: Dict[str, Any] = {}

class DashboardMetrics(BaseModel):
    total_users: int
    active_users: int
    total_transactions: int
    transaction_volume: float
    recent_transactions: List[Dict[str, Any]]
    pending_kyc: int
    success_rate: float

class BlockUserRequest(BaseModel):
    user_id: uuid.UUID
    reason: str
    
class AuditLogBase(BaseModel):
    action_type: str
    description: str
    details: Dict[str, Any] = {}
    user_id: Optional[uuid.UUID] = None

class AuditLogCreate(AuditLogBase):
    pass

class AuditLog(AuditLogBase):
    id: uuid.UUID
    action_by: Optional[uuid.UUID] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    
    class Config:
        orm_mode = True

class NotificationBase(BaseModel):
    type: str  # Email/SMS/In-App
    title: str
    message: str
    metadata: Dict[str, Any] = {}

class NotificationCreate(NotificationBase):
    user_id: Optional[uuid.UUID] = None
    admin_id: Optional[uuid.UUID] = None
    
    @validator('user_id', 'admin_id')
    def validate_recipient(cls, v, values):
        if 'user_id' not in values and 'admin_id' not in values:
            raise ValueError('Either user_id or admin_id must be provided')
        return v

class Notification(NotificationBase):
    id: uuid.UUID
    status: str
    sent_at: Optional[datetime] = None
    is_read: bool
    
    class Config:
        orm_mode = True

class EmailTemplateBase(BaseModel):
    template_name: str
    subject: str
    body: str
    variables: List[str] = []

class EmailTemplateCreate(EmailTemplateBase):
    pass

class EmailTemplateUpdate(BaseModel):
    subject: Optional[str] = None
    body: Optional[str] = None
    variables: Optional[List[str]] = None

class EmailTemplate(EmailTemplateBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True
