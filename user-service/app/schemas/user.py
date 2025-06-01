import uuid
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator, constr

class UserBase(BaseModel):
    full_name: str
    email: EmailStr
    phone_number: constr(min_length=10, max_length=15)  # type: ignore

class UserCreate(UserBase):
    password: constr(min_length=8)  # type: ignore

class UserLogin(BaseModel):
    phone_number: str
    password: str

class UserProfile(BaseModel):
    dob: Optional[datetime] = None
    address: Optional[str] = None
    referral_code: Optional[str] = None
    
    class Config:
        orm_mode = True

class User(UserBase):
    id: uuid.UUID
    is_active: bool
    created_at: datetime
    profile: Optional[UserProfile] = None
    
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: str
    
class LoginAttemptCreate(BaseModel):
    ip_address: str
    status: str  # Success/Failure

class ReferralInfo(BaseModel):
    referral_code: str
    referred_users_count: int = 0
