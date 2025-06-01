import random
import uuid
import jwt
import aiohttp
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.otp import OtpLog
from app.schemas.otp import OtpResponse, OtpVerifyResponse
from app.config import settings
from app.utils.auth import get_password_hash, verify_password

class OtpService:
    def __init__(self, db: AsyncSession):
        self.db = db
        
    def _generate_otp(self, length: int = 6) -> str:
        """Generate a random OTP code"""
        digits = "0123456789"
        return ''.join(random.choice(digits) for _ in range(length))
    
    async def _log_otp_to_db(
        self,
        phone_number: str,
        otp_code: str,  # This will now be a hashed OTP
        otp_type: str,
        email: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        expires_at: Optional[datetime] = None
    ) -> OtpLog:
        """Store OTP in database for verification and audit"""
        if not expires_at:
            expires_at = datetime.utcnow() + timedelta(minutes=10)
            
        otp_log = OtpLog(
            user_id=user_id or uuid.uuid4(),  # Generate UUID if not provided
            otp_code=otp_code,  # Store hashed OTP
            otp_type=otp_type,
            phone_number=phone_number,
            email=email,
            expires_at=expires_at,
            verified=False,
            verification_attempts=0
        )
        
        self.db.add(otp_log)
        await self.db.commit()
        await self.db.refresh(otp_log)
        return otp_log
    
    async def _send_via_msg91(self, phone_number: str, otp_code: str) -> bool:
        """Send OTP using MSG91 API"""
        try:
            # MSG91 API integration
            url = "https://api.msg91.com/api/v5/otp"
            headers = {
                "authkey": settings.MSG91_AUTH_KEY,
                "Content-Type": "application/json"
            }
            payload = {
                "template_id": settings.MSG91_TEMPLATE_ID,
                "mobile": phone_number,
                "otp": otp_code
            }
            
            # Make HTTP request to MSG91
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers) as response:
                    result = await response.json()
                    return result.get("type") == "success"
                    
        except Exception as e:
            print(f"Error sending OTP via MSG91: {str(e)}")
            return False
    
    async def generate_and_send_otp(
        self,
        phone_number: str,
        otp_type: str,
        email: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        ip_address: str = "0.0.0.0"
    ) -> OtpResponse:
        """Generate OTP, store in database, and send via MSG91"""
        # Generate plain OTP
        otp_code = self._generate_otp()
        
        # Hash OTP for storage
        hashed_otp = get_password_hash(otp_code)
        
        # Set expiration time (10 minutes)
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        
        # Store in database
        otp_log = await self._log_otp_to_db(
            phone_number=phone_number,
            otp_code=hashed_otp,  # Store hashed version
            otp_type=otp_type,
            email=email,
            user_id=user_id,
            expires_at=expires_at
        )
        
        # Send via MSG91
        success = await self._send_via_msg91(phone_number, otp_code)
        
        if not success:
            # Update database record if sending failed
            otp_log.status = "Failed"
            await self.db.commit()
            raise ValueError("Failed to send OTP. Please try again later.")
        
        return OtpResponse(
            success=True,
            message="OTP sent successfully",
            expires_in=600,  # 10 minutes in seconds
            reference_id=str(otp_log.id)
        )
    
    async def verify_otp(
        self,
        phone_number: str,
        otp_code: str,
        otp_type: str,
        ip_address: str = "0.0.0.0"
    ) -> OtpVerifyResponse:
        """Verify OTP entered by user"""
        # Find the latest unverified OTP for this phone number and type
        query = select(OtpLog).where(
            OtpLog.phone_number == phone_number,
            OtpLog.otp_type == otp_type,
            OtpLog.verified == False,
            OtpLog.expires_at > datetime.utcnow()
        ).order_by(OtpLog.created_at.desc())
        
        result = await self.db.execute(query)
        otp_log = result.scalars().first()
        
        if not otp_log:
            raise ValueError("No valid OTP found. Please request a new OTP.")
        
        # Check if maximum attempts reached
        if otp_log.verification_attempts >= 3:
            raise ValueError("Maximum verification attempts reached. Please request a new OTP.")
        
        # Update verification attempts
        otp_log.verification_attempts += 1
        await self.db.commit()
        
        # Verify OTP (check if provided OTP matches stored hashed OTP)
        if not verify_password(otp_code, otp_log.otp_code):
            if otp_log.verification_attempts >= 3:
                # If max attempts reached after this attempt, invalidate OTP
                otp_log.expires_at = datetime.utcnow()
                await self.db.commit()
                raise ValueError("Invalid OTP. Maximum attempts reached.")
            else:
                # Still has attempts left
                await self.db.commit()
                raise ValueError(f"Invalid OTP. {3 - otp_log.verification_attempts} attempts remaining.")
        
        # OTP is valid - update record
        otp_log.verified = True
        otp_log.verified_at = datetime.utcnow()
        await self.db.commit()
        
        # Create JWT token if needed
        token = None
        if otp_log.user_id:
            # Create access token for authenticated user
            token_data = {
                "sub": str(otp_log.user_id),
                "phone": phone_number,
                "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            }
            token = jwt.encode(token_data, settings.JWT_SECRET_KEY, algorithm="HS256")
        
        return OtpVerifyResponse(
            success=True,
            message="OTP verified successfully",
            token=token,
            user_id=otp_log.user_id
        )
