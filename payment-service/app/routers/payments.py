from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.payment import Transaction
from app.schemas.payment import PaymentCreate, PaymentResponse, PaymentStatusResponse, PaymentHistoryItem, FailedTransactionResponse
from app.services.payment_service import PaymentService
from app.utils.auth import get_current_user_id

router = APIRouter()

@router.post("/initiate", response_model=PaymentResponse)
async def initiate_payment(
    payment: PaymentCreate,
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Initiate a new payment from credit card to UPI
    """
    payment_service = PaymentService(db)
    try:
        return await payment_service.initiate_payment(user_id, payment)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/status/{txn_id}", response_model=PaymentStatusResponse)
async def get_payment_status(
    txn_id: uuid.UUID,
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get status of a payment by transaction ID
    """
    payment_service = PaymentService(db)
    try:
        return await payment_service.get_payment_status(txn_id, user_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

@router.get("/history", response_model=List[PaymentHistoryItem])
async def get_payment_history(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get payment transaction history for the user
    """
    payment_service = PaymentService(db)
    return await payment_service.get_payment_history(user_id, limit, offset, status)

@router.get("/failed/{txn_id}", response_model=FailedTransactionResponse)
async def get_failed_transaction_details(
    txn_id: uuid.UUID,
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a failed transaction
    """
    payment_service = PaymentService(db)
    try:
        return await payment_service.get_failed_transaction(txn_id, user_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

@router.post("/webhook", status_code=status.HTTP_200_OK)
async def payment_gateway_webhook(
    event: dict,
    db: AsyncSession = Depends(get_db)
):
    """
    Webhook endpoint for payment gateway events
    """
    payment_service = PaymentService(db)
    try:
        await payment_service.process_webhook_event(event)
        return {"status": "success"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
