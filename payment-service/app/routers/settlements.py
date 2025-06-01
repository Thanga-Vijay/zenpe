from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.schemas.payment import SettlementResponse
from app.services.settlement_service import SettlementService
from app.utils.auth import get_current_user_id, get_admin_user_id

router = APIRouter()

@router.post("/trigger", response_model=SettlementResponse)
async def trigger_settlement(
    transaction_id: uuid.UUID,
    admin_id: uuid.UUID = Depends(get_admin_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Manually trigger settlement for a transaction (admin only)
    """
    settlement_service = SettlementService(db)
    try:
        return await settlement_service.trigger_settlement(transaction_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/status", response_model=List[SettlementResponse])
async def get_settlement_status(
    transaction_id: Optional[uuid.UUID] = None,
    status: Optional[str] = None,
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get settlement status for user's transactions
    """
    settlement_service = SettlementService(db)
    try:
        return await settlement_service.get_settlements_by_user(
            user_id=user_id,
            transaction_id=transaction_id,
            status=status,
            limit=limit,
            offset=offset
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

@router.get("/admin/pending", response_model=List[SettlementResponse])
async def get_pending_settlements(
    limit: int = Query(50, ge=1, le=500),
    admin_id: uuid.UUID = Depends(get_admin_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all pending settlements (admin only)
    """
    settlement_service = SettlementService(db)
    return await settlement_service.get_settlements_by_status("Pending", limit=limit)

@router.post("/admin/retry/{settlement_id}", response_model=SettlementResponse)
async def retry_failed_settlement(
    settlement_id: uuid.UUID,
    admin_id: uuid.UUID = Depends(get_admin_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Retry a failed settlement (admin only)
    """
    settlement_service = SettlementService(db)
    try:
        return await settlement_service.retry_settlement(settlement_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
