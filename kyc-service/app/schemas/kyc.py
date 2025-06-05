import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator, HttpUrl

class DocumentBase(BaseModel):
    doc_type: str
    doc_metadata: Optional[Dict[str, Any]] = {}

class DocumentCreate(DocumentBase):
    pass

class DocumentResponse(DocumentBase):
    id: uuid.UUID
    kyc_id: uuid.UUID
    doc_url: str
    uploaded_at: datetime
    
    class Config:
        from_attributes = True

class KycRequestBase(BaseModel):
    user_id: uuid.UUID

class KycRequestCreate(KycRequestBase):
    pass

class KycRequestUpdate(BaseModel):
    status: Optional[str] = None
    admin_id: Optional[uuid.UUID] = None
    rejection_reason: Optional[str] = None

class KycRequestResponse(KycRequestBase):
    id: uuid.UUID
    status: str
    submitted_at: datetime
    reviewed_at: Optional[datetime] = None
    documents: List[DocumentResponse] = []
    
    class Config:
        from_attributes = True

class KycStatusResponse(BaseModel):
    status: str
    submitted_at: datetime
    reviewed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    
    class Config:
        from_attributes = True

class KycAuditLogBase(BaseModel):
    kyc_id: uuid.UUID
    action: str
    actor_type: str
    actor_id: uuid.UUID
    remarks: Optional[str] = None

class KycAuditLogCreate(KycAuditLogBase):
    pass

class KycAuditLogResponse(KycAuditLogBase):
    id: uuid.UUID
    timestamp: datetime
    
    class Config:
        from_attributes = True

class AdminVerifyRequest(BaseModel):
    status: str  # Approved/Rejected
    remarks: Optional[str] = None

class DocumentVerificationChecklist(BaseModel):
    document_quality: bool = False  # Image is clear and readable
    data_matching: bool = False     # Data matches with application
    tampering_check: bool = False   # No signs of manipulation
    expiry_check: bool = False      # Document is not expired
    verification_notes: str = ""

class VerificationDetail(BaseModel):
    verified_by: uuid.UUID
    verification_timestamp: datetime
    verification_ip: str
    checklist: DocumentVerificationChecklist
    access_location: str

