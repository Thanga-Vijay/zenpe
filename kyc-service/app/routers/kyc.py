from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.kyc import KycRequest, KycDocument, KycAuditLog
from app.schemas.kyc import KycRequestCreate, KycRequestResponse, KycStatusResponse, DocumentCreate
from app.services.kyc_service import KycService
from app.services.storage_service import StorageService
from app.utils.auth import get_current_user_id

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/upload", response_model=KycRequestResponse)
async def upload_kyc_documents(
    doc_type: str = Form(...),
    document: UploadFile = File(...),
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload KYC documents
    """
    kyc_service = KycService(db)
    storage_service = StorageService()
    
    try:
        # Create or get existing KYC request
        kyc_request = await kyc_service.get_or_create_kyc_request(user_id)
        
        # Upload document to storage
        doc_url = await storage_service.upload_document(
            document, 
            f"{user_id}/{kyc_request.id}/{doc_type}"
        )
        
        # Create document record
        doc_metadata = {"filename": document.filename, "content_type": document.content_type}
        await kyc_service.add_document(
            kyc_request.id,
            DocumentCreate(
                doc_type=doc_type,
                doc_metadata=doc_metadata
            ),
            doc_url
        )
        
        # Log audit
        await kyc_service.log_audit(
            kyc_id=kyc_request.id,
            action="Document Uploaded",
            actor_type="User",
            actor_id=user_id,
            remarks=f"Uploaded {doc_type} document"
        )
        
        return await kyc_service.get_kyc_request(kyc_request.id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/status", response_model=KycStatusResponse)
async def get_kyc_status(
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Check current KYC status for the user
    """
    kyc_service = KycService(db)
    try:
        return await kyc_service.get_kyc_status(user_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

@router.get("/history", response_model=List[KycAuditLogResponse])
async def get_kyc_history(
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get KYC history for the user
    """
    kyc_service = KycService(db)
    try:
        return await kyc_service.get_kyc_history(user_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
