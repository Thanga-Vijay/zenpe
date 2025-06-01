import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.kyc import KycRequest, KycDocument, KycAuditLog
from app.schemas.kyc import KycRequestCreate, DocumentCreate, KycAuditLogCreate, KycStatusResponse, KycAuditLogResponse

class KycService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def get_or_create_kyc_request(self, user_id: uuid.UUID) -> KycRequest:
        """
        Get existing KYC request or create a new one
        """
        # Check for existing pending request
        query = select(KycRequest).where(
            KycRequest.user_id == user_id,
            KycRequest.status.in_(["Pending", "Approved"])
        )
        result = await self.db.execute(query)
        kyc_request = result.scalars().first()
        
        if kyc_request:
            if kyc_request.status == "Approved":
                raise ValueError("KYC already approved")
            return kyc_request
        
        # Create new KYC request
        kyc_request = KycRequest(user_id=user_id)
        self.db.add(kyc_request)
        await self.db.commit()
        await self.db.refresh(kyc_request)
        
        # Log the creation
        await self.log_audit(
            kyc_id=kyc_request.id,
            action="Submitted",
            actor_type="User",
            actor_id=user_id,
            remarks="KYC request created"
        )
        
        return kyc_request
    
    async def add_document(self, kyc_id: uuid.UUID, document_data: DocumentCreate, doc_url: str) -> KycDocument:
        """
        Add document to KYC request
        """
        # First check if document type already exists for this KYC request
        query = select(KycDocument).where(
            KycDocument.kyc_id == kyc_id,
            KycDocument.doc_type == document_data.doc_type
        )
        result = await self.db.execute(query)
        existing_doc = result.scalars().first()
        
        if existing_doc:
            # Update existing document
            existing_doc.doc_url = doc_url
            existing_doc.doc_metadata = document_data.doc_metadata
            existing_doc.uploaded_at = datetime.utcnow()
            await self.db.commit()
            return existing_doc
        
        # Create new document
        document = KycDocument(
            kyc_id=kyc_id,
            doc_type=document_data.doc_type,
            doc_url=doc_url,
            doc_metadata=document_data.doc_metadata
        )
        self.db.add(document)
        await self.db.commit()
        await self.db.refresh(document)
        return document
    
    async def get_kyc_request(self, kyc_id: uuid.UUID) -> KycRequest:
        """
        Get KYC request by ID with documents
        """
        query = select(KycRequest).where(KycRequest.id == kyc_id).options(
            selectinload(KycRequest.documents)
        )
        result = await self.db.execute(query)
        kyc_request = result.scalars().first()
        
        if not kyc_request:
            raise ValueError(f"KYC request not found with ID: {kyc_id}")
        
        return kyc_request
    
    async def get_kyc_status(self, user_id: uuid.UUID) -> KycStatusResponse:
        """
        Get current KYC status for user
        """
        query = select(KycRequest).where(KycRequest.user_id == user_id).order_by(
            KycRequest.submitted_at.desc()
        )
        result = await self.db.execute(query)
        kyc_request = result.scalars().first()
        
        if not kyc_request:
            raise ValueError(f"No KYC request found for user: {user_id}")
        
        return KycStatusResponse(
            status=kyc_request.status,
            submitted_at=kyc_request.submitted_at,
            reviewed_at=kyc_request.reviewed_at,
            rejection_reason=kyc_request.rejection_reason
        )
    
    async def update_kyc_status(
        self,
        kyc_id: uuid.UUID,
        status: str,
        admin_id: uuid.UUID,
        rejection_reason: Optional[str] = None
    ) -> KycRequest:
        """
        Update KYC request status by admin
        """
        kyc_request = await self.get_kyc_request(kyc_id)
        
        if kyc_request.status != "Pending":
            raise ValueError(f"Cannot update KYC with status: {kyc_request.status}")
        
        kyc_request.status = status
        kyc_request.reviewed_at = datetime.utcnow()
        kyc_request.admin_id = admin_id
        
        if status == "Rejected" and rejection_reason:
            kyc_request.rejection_reason = rejection_reason
        
        await self.db.commit()
        await self.db.refresh(kyc_request)
        return kyc_request
    
    async def log_audit(
        self,
        kyc_id: uuid.UUID,
        action: str,
        actor_type: str,
        actor_id: uuid.UUID,
        remarks: Optional[str] = None
    ) -> KycAuditLog:
        """
        Create audit log entry for KYC actions
        """
        audit_log = KycAuditLog(
            kyc_id=kyc_id,
            action=action,
            actor_type=actor_type,
            actor_id=actor_id,
            remarks=remarks
        )
        self.db.add(audit_log)
        await self.db.commit()
        await self.db.refresh(audit_log)
        return audit_log
    
    async def get_kyc_history(self, user_id: uuid.UUID) -> List[KycAuditLogResponse]:
        """
        Get KYC history/audit logs for a user
        """
        # First get all KYC requests for this user
        kyc_query = select(KycRequest).where(KycRequest.user_id == user_id)
        kyc_result = await self.db.execute(kyc_query)
        kyc_requests = kyc_result.scalars().all()
        
        if not kyc_requests:
            raise ValueError(f"No KYC requests found for user: {user_id}")
        
        kyc_ids = [kyc.id for kyc in kyc_requests]
        
        # Get all audit logs for these KYC requests
        audit_query = select(KycAuditLog).where(
            KycAuditLog.kyc_id.in_(kyc_ids)
        ).order_by(KycAuditLog.timestamp.desc())
        
        audit_result = await self.db.execute(audit_query)
        audit_logs = audit_result.scalars().all()
        
        return [KycAuditLogResponse.from_orm(log) for log in audit_logs]
    
    async def get_kyc_audit_logs(self, kyc_id: uuid.UUID) -> List[KycAuditLogResponse]:
        """
        Get all audit logs for a specific KYC request
        """
        audit_query = select(KycAuditLog).where(
            KycAuditLog.kyc_id == kyc_id
        ).order_by(KycAuditLog.timestamp.desc())
        
        audit_result = await self.db.execute(audit_query)
        audit_logs = audit_result.scalars().all()
        
        if not audit_logs:
            raise ValueError(f"No audit logs found for KYC request: {kyc_id}")
        
        return [KycAuditLogResponse.from_orm(log) for log in audit_logs]
    
    async def list_kyc_requests_by_status(self, status: str) -> List[KycRequest]:
        """
        List KYC requests by status for admin review
        """
        query = select(KycRequest).where(
            KycRequest.status == status
        ).options(
            selectinload(KycRequest.documents)
        ).order_by(KycRequest.submitted_at.asc())
        
        result = await self.db.execute(query)
        return result.scalars().all()
