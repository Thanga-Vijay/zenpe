import uuid
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator, constr

class OtpRequest(BaseModel):
    phone_number: constr(min_length=10, max_length=15)  # type: ignore
    email: Optional[EmailStr] = None
    otp_type: str = "login"  # login/kyc/payment
    user_id: Optional[uuid.UUID] = None

class OtpVerify(BaseModel):
    phone_number: constr(min_length=10, max_length=15)  # type: ignore
    otp_code: constr(min_length=4, max_length=8)  # type: ignore
    otp_type: str = "login"

class OtpResponse(BaseModel):
    success: bool
    message: str
    expires_in: Optional[int] = None
    reference_id: Optional[str] = None

class OtpVerifyResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user_id: Optional[uuid.UUID] = None
