from fastapi import APIRouter, Depends, HTTPException, status, Request
from app.dependencies import get_kyc_service, get_notification_service, get_document_service
from app.schemas.kyc import DocumentVerificationChecklist, VerificationDetail

router = APIRouter()

@router.post("/verify/{kyc_id}/primary")
async def primary_verification(
    kyc_id: uuid.UUID,
    checklist: DocumentVerificationChecklist,
    request: Request,
    kyc_service = Depends(get_kyc_service),
    doc_service = Depends(get_document_service)
):
    verification_detail = VerificationDetail(
        verified_by=request.state.user_id,
        verification_timestamp=datetime.now(),
        verification_ip=request.client.host,
        checklist=checklist,
        access_location=request.headers.get("x-forwarded-for", request.client.host)
    )
    return await kyc_service.add_primary_verification(kyc_id, verification_detail)

@router.post("/verify/{kyc_id}/secondary")
async def secondary_verification(
    kyc_id: uuid.UUID,
    checklist: DocumentVerificationChecklist,
    request: Request,
    kyc_service = Depends(get_kyc_service),
    notification_service = Depends(get_notification_service)
):
    verification_detail = VerificationDetail(
        verified_by=request.state.user_id,
        verification_timestamp=datetime.now(),
        verification_ip=request.client.host,
        checklist=checklist,
        access_location=request.headers.get("x-forwarded-for", request.client.host)
    )
    result = await kyc_service.add_secondary_verification(kyc_id, verification_detail)
    if result.verification_complete:
        await notification_service.notify_verification_complete(kyc_id)
    return result
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import uuid

from app.database import get_db
from app.schemas.kyc import KycRequestResponse, AdminVerifyRequest, KycAuditLogResponse
from app.services.kyc_service import KycService
from app.utils.auth import get_admin_user_id

router = APIRouter()

@router.post("/verify/{kyc_id}", response_model=KycRequestResponse)
async def verify_kyc(
    kyc_id: uuid.UUID,
    verify_data: AdminVerifyRequest,
    admin_id: uuid.UUID = Depends(get_admin_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Admin verifies or rejects KYC request
    """
    kyc_service = KycService(db)
    
    try:
        if verify_data.status not in ["Approved", "Rejected"]:
            raise ValueError("Status must be 'Approved' or 'Rejected'")
        
        if verify_data.status == "Rejected" and not verify_data.remarks:
            raise ValueError("Rejection reason is required")
            
        result = await kyc_service.update_kyc_status(
            kyc_id=kyc_id,
            status=verify_data.status,
            admin_id=admin_id,
            rejection_reason=verify_data.remarks
        )
        
        # Log audit
        await kyc_service.log_audit(
            kyc_id=kyc_id,
            action=f"KYC {verify_data.status}",
            actor_type="Admin",
            actor_id=admin_id,
            remarks=verify_data.remarks
        )
        
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/list", response_model=List[KycRequestResponse])
async def list_pending_kyc_requests(
    status: str = "Pending",
    admin_id: uuid.UUID = Depends(get_admin_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    List KYC requests by status for admin review
    """
    kyc_service = KycService(db)
    return await kyc_service.list_kyc_requests_by_status(status)

@router.get("/audit-logs/{kyc_id}", response_model=List[KycAuditLogResponse])
async def get_kyc_audit_logs(
    kyc_id: uuid.UUID,
    admin_id: uuid.UUID = Depends(get_admin_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all audit logs for a specific KYC request
    """
    kyc_service = KycService(db)
    try:
        return await kyc_service.get_kyc_audit_logs(kyc_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
