import uuid
from sqlalchemy import Column, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class KycRequest(Base):
    __tablename__ = "kyc_requests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    status = Column(String(20), default="Pending")  # Pending/Approved/Rejected
    submitted_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)
    admin_id = Column(UUID(as_uuid=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    primary_verification = Column(JSONB, nullable=True)
    secondary_verification = Column(JSONB, nullable=True)
    verification_complete = Column(Boolean, default=False)
    final_status = Column(String(20), default="Pending")  # Only set after both verifications
    
    # Relationships
    documents = relationship("KycDocument", back_populates="kyc_request")
    audit_logs = relationship("KycAuditLog", back_populates="kyc_request")
    
    def __repr__(self):
        return f"<KycRequest {self.id} {self.status}>"

class KycDocument(Base):
    __tablename__ = "kyc_documents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kyc_id = Column(UUID(as_uuid=True), ForeignKey("kyc_requests.id", ondelete="CASCADE"), index=True)
    doc_type = Column(String(50))  # Aadhaar/PAN/etc.
    doc_url = Column(Text, nullable=False)
    doc_metadata = Column(JSONB, default={})
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    kyc_request = relationship("KycRequest", back_populates="documents")
    
    def __repr__(self):
        return f"<KycDocument {self.id} {self.doc_type}>"

class KycAuditLog(Base):
    __tablename__ = "kyc_audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kyc_id = Column(UUID(as_uuid=True), ForeignKey("kyc_requests.id", ondelete="CASCADE"), index=True)
    action = Column(String(50))  # Submitted/Approved/Rejected
    actor_type = Column(String(20))  # User/Admin
    actor_id = Column(UUID(as_uuid=True), nullable=False)
    remarks = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    access_type = Column(String(50))  # View/Modify/Verify
    document_id = Column(UUID(as_uuid=True), nullable=True)
    session_id = Column(String(100), nullable=True)
    
    # Relationships
    kyc_request = relationship("KycRequest", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<KycAuditLog {self.id} {self.action}>"
