from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.services.notification_service import NotificationService
from app.services.document_service import DocumentService
from app.services.retention_service import RetentionService
from app.services.kyc_service import KycService

async def get_notification_service():
    return NotificationService()

async def get_document_service(db: AsyncSession = Depends(get_db)):
    return DocumentService(db)

async def get_retention_service(db: AsyncSession = Depends(get_db)):
    return RetentionService(db)

async def get_kyc_service(db: AsyncSession = Depends(get_db)):
    return KycService(db)