from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import uuid

from app.database import get_db
from app.schemas.otp import OtpRequest, OtpVerify, OtpResponse, OtpVerifyResponse
from app.services.otp_service import OtpService

router = APIRouter()

@router.post("/send", response_model=OtpResponse)
async def send_otp(
    otp_request: OtpRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Send OTP to user's phone number and optionally email
    """
    client_ip = request.client.host if request.client else "0.0.0.0"
    
    otp_service = OtpService(db)
    try:
        result = await otp_service.generate_and_send_otp(
            phone_number=otp_request.phone_number,
            email=otp_request.email,
            otp_type=otp_request.otp_type,
            user_id=otp_request.user_id,
            ip_address=client_ip
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/verify", response_model=OtpVerifyResponse)
async def verify_otp(
    verify_data: OtpVerify,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify OTP entered by user
    """
    client_ip = request.client.host if request.client else "0.0.0.0"
    
    otp_service = OtpService(db)
    try:
        result = await otp_service.verify_otp(
            phone_number=verify_data.phone_number,
            otp_code=verify_data.otp_code,
            otp_type=verify_data.otp_type,
            ip_address=client_ip
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/resend", response_model=OtpResponse)
async def resend_otp(
    phone_number: str,
    otp_type: str = "login",
    db: AsyncSession = Depends(get_db)
):
    """
    Resend OTP to user's phone number
    """
    otp_service = OtpService(db)
    try:
        result = await otp_service.resend_otp(
            phone_number=phone_number,
            otp_type=otp_type
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
