import uuid
from sqlalchemy import Column, String, DateTime, Boolean, JSON, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class AdminUser(Base):
    __tablename__ = "admin_roles_permissions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    admin_name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False)  # SuperAdmin/Verifier/Auditor
    permissions = Column(JSONB, default={})
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    audit_logs = relationship("AuditLog", back_populates="admin_user")
    
    def __repr__(self):
        return f"<AdminUser {self.admin_name} ({self.role})>"

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_by = Column(UUID(as_uuid=True), ForeignKey("admin_roles_permissions.id"), nullable=True)
    user_id = Column(UUID(as_uuid=True), nullable=True)  # If action relates to a user
    action_type = Column(String(50), nullable=False)  # KYC_Verification/User_Block/Manual_Settlement
    description = Column(Text, nullable=False)
    details = Column(JSONB, default={})
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    admin_user = relationship("AdminUser", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog {self.id} {self.action_type}>"

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=True)  # Null for admin notifications
    admin_id = Column(UUID(as_uuid=True), nullable=True)  # Null for user notifications
    type = Column(String(20), nullable=False)  # Email/SMS/In-App
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(20), default="Pending")  # Pending/Sent/Failed
    sent_at = Column(DateTime, nullable=True)
    metadata = Column(JSONB, default={})
    is_read = Column(Boolean, default=False)  # For in-app notifications
    
    def __repr__(self):
        return f"<Notification {self.id} {self.type}>"

class EmailTemplate(Base):
    __tablename__ = "email_templates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    template_name = Column(String(100), unique=True, nullable=False)
    subject = Column(String(200), nullable=False)
    body = Column(Text, nullable=False)
    variables = Column(JSONB, default=[])  # List of variables this template accepts
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<EmailTemplate {self.template_name}>"
