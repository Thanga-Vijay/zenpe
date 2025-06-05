# PowerShell script to populate remaining code in microservice files
$baseDir = "C:\Users\ADMIN\Documents\APP\Continue\Backend"

# Function to create or overwrite a file with content
function Set-FileContent {
    param (
        [string]$Path,
        [string]$Content
    )
    
    if (Test-Path $Path) {
        Clear-Content $Path
    }
    
    $Content | Out-File -FilePath $Path -Encoding utf8
    Write-Host "Created file: $Path"
}

#############################################
# 1. COMPLETE USER SERVICE FILES
#############################################
$userServiceDir = Join-Path $baseDir "user-service"

# User Schema
$userSchemaContent = @'
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
'@

Set-FileContent -Path (Join-Path $userServiceDir "app\schemas\user.py") -Content $userSchemaContent

# User Router
$userRouterContent = @'
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.user import User, UserProfile
from app.schemas.user import UserCreate, User as UserSchema, UserProfile as UserProfileSchema, Token, ReferralInfo
from app.services.user_service import UserService
from app.utils.security import create_access_token, get_current_user

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

@router.post("/register", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user with email, phone, and password
    """
    user_service = UserService(db)
    try:
        return await user_service.create_user(user_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return JWT token
    """
    user_service = UserService(db)
    user = await user_service.authenticate_user(form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/profile", response_model=UserSchema)
async def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user's profile information
    """
    return current_user

@router.put("/profile", response_model=UserProfileSchema)
async def update_profile(
    profile_data: UserProfileSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update user profile information
    """
    user_service = UserService(db)
    return await user_service.update_profile(current_user.id, profile_data)

@router.get("/referral", response_model=ReferralInfo)
async def get_referral_info(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get user's referral code and stats
    """
    user_service = UserService(db)
    return await user_service.get_referral_info(current_user.id)
'@

Set-FileContent -Path (Join-Path $userServiceDir "app\routers\users.py") -Content $userRouterContent

# User Service
$userServiceContent = @'
import uuid
from typing import Optional, List, Dict, Any
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from datetime import datetime

from app.models.user import User, UserProfile, LoginAttempt
from app.schemas.user import UserCreate, UserProfile as UserProfileSchema, ReferralInfo
from app.utils.security import get_password_hash, verify_password

class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_user(self, user_data: UserCreate) -> User:
        """
        Create a new user with profile
        """
        # Check if email already exists
        email_query = select(User).where(User.email == user_data.email)
        email_result = await self.db.execute(email_query)
        if email_result.scalars().first() is not None:
            raise ValueError("Email already registered")
        
        # Check if phone number already exists
        phone_query = select(User).where(User.phone_number == user_data.phone_number)
        phone_result = await self.db.execute(phone_query)
        if phone_result.scalars().first() is not None:
            raise ValueError("Phone number already registered")
        
        # Create user
        hashed_password = get_password_hash(user_data.password)
        user = User(
            full_name=user_data.full_name,
            email=user_data.email,
            phone_number=user_data.phone_number,
            password_hash=hashed_password
        )
        self.db.add(user)
        
        # Generate referral code (simple implementation)
        referral_code = f"REF{uuid.uuid4().hex[:8].upper()}"
        
        # Create user profile
        profile = UserProfile(
            user=user,
            referral_code=referral_code
        )
        self.db.add(profile)
        
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def authenticate_user(self, phone_number: str, password: str) -> Optional[User]:
        """
        Authenticate user by phone number and password
        """
        query = select(User).where(User.phone_number == phone_number)
        result = await self.db.execute(query)
        user = result.scalars().first()
        
        if not user or not verify_password(password, user.password_hash):
            return None
            
        # Log login attempt
        login_attempt = LoginAttempt(
            user_id=user.id,
            ip_address="0.0.0.0",  # In real implementation, get from request
            status="Success"
        )
        self.db.add(login_attempt)
        await self.db.commit()
        
        return user
    
    async def get_user_by_id(self, user_id: uuid.UUID) -> Optional[User]:
        """
        Get user by ID with profile
        """
        query = select(User).where(User.id == user_id).options(selectinload(User.profile))
        result = await self.db.execute(query)
        return result.scalars().first()
    
    async def update_profile(self, user_id: uuid.UUID, profile_data: UserProfileSchema) -> UserProfile:
        """
        Update user profile
        """
        query = select(UserProfile).where(UserProfile.user_id == user_id)
        result = await self.db.execute(query)
        profile = result.scalars().first()
        
        if not profile:
            raise ValueError("Profile not found")
        
        # Update profile fields
        if profile_data.dob:
            profile.dob = profile_data.dob
        if profile_data.address:
            profile.address = profile_data.address
        
        await self.db.commit()
        await self.db.refresh(profile)
        return profile
    
    async def get_referral_info(self, user_id: uuid.UUID) -> ReferralInfo:
        """
        Get user referral code and count of referred users
        """
        # Get referral code
        profile_query = select(UserProfile).where(UserProfile.user_id == user_id)
        profile_result = await self.db.execute(profile_query)
        profile = profile_result.scalars().first()
        
        if not profile:
            raise ValueError("Profile not found")
        
        # Count referred users
        count_query = select(func.count()).select_from(UserProfile).where(UserProfile.referred_by == user_id)
        count_result = await self.db.execute(count_query)
        referred_count = count_result.scalar() or 0
        
        return ReferralInfo(
            referral_code=profile.referral_code,
            referred_users_count=referred_count
        )
'@

Set-FileContent -Path (Join-Path $userServiceDir "app\services\user_service.py") -Content $userServiceContent

# Security Utils
$securityUtilsContent = @'
import uuid
from datetime import datetime, timedelta
from typing import Optional, Union, Any
from jose import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.config import settings
from app.database import get_db
from app.services.user_service import UserService

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password against hashed version
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash a password
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Get current authenticated user from JWT token
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    
    user_service = UserService(db)
    user = await user_service.get_user_by_id(uuid.UUID(user_id))
    
    if user is None:
        raise credentials_exception
    
    return user
'@

Set-FileContent -Path (Join-Path $userServiceDir "app\utils\security.py") -Content $securityUtilsContent

# User Test File
$userTestContent = @'
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_health_check():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

# Add more tests for user registration, login, etc.
'@

Set-FileContent -Path (Join-Path $userServiceDir "tests\test_users.py") -Content $userTestContent

#############################################
# 2. OTP SERVICE FILES
#############################################
$otpServiceDir = Join-Path $baseDir "otp-service"

# OTP Service main.py
$otpMainContent = @'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import otp
from app.database import create_tables

app = FastAPI(
    title="OTP Service API",
    description="API for OTP generation, sending, and verification",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(otp.router, prefix="/otp", tags=["otp"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8001, reload=True)
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\main.py") -Content $otpMainContent

# OTP Service config.py
$otpConfigContent = @'
import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "OTP Service"
    API_V1_STR: str = "/api/v1"
    
    # OTP settings
    OTP_EXPIRY_SECONDS: int = 300  # 5 minutes
    OTP_LENGTH: int = 6
    
    # Database settings - For OTP logs
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/otp_service")
    
    # Redis settings - For OTP storage
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_PREFIX: str = "otp:"
    
    # SMS Provider settings
    SMS_API_KEY: str = os.getenv("SMS_API_KEY", "your-sms-api-key")
    SMS_SENDER_ID: str = os.getenv("SMS_SENDER_ID", "RUPAYPAY")
    
    # Email Provider settings
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "your-email@gmail.com")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "your-password")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "noreply@yourdomain.com")
    
    # AWS Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_SECRET_MANAGER_NAME: str = os.getenv("AWS_SECRET_MANAGER_NAME", "otp-service-secrets")
    AWS_SNS_ARN: str = os.getenv("AWS_SNS_ARN", "your-sns-arn")
    
    class Config:
        case_sensitive = True

settings = Settings()
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\config.py") -Content $otpConfigContent

# OTP Service database.py
$otpDatabaseContent = @'
import sqlalchemy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

DATABASE_URL = settings.DATABASE_URL
# Convert PostgreSQL URL to async version
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db() -> AsyncSession:
    """
    Dependency for getting async database session
    """
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

async def create_tables():
    """
    Create all tables defined in the models
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\database.py") -Content $otpDatabaseContent

# OTP Service models/otp.py
$otpModelContent = @'
import uuid
from sqlalchemy import Column, String, DateTime, Text, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from app.database import Base

class OtpLog(Base):
    __tablename__ = "otp_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False)
    otp_code = Column(String(10))  # Store hashed OTP for security
    otp_type = Column(String(20))  # login/kyc/payment
    phone_number = Column(String(20), nullable=False)
    email = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    verified = Column(Boolean, default=False)
    verification_attempts = Column(Integer, default=0)
    verified_at = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<OtpLog {self.id} {self.otp_type}>"
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\models\otp.py") -Content $otpModelContent

# OTP Service schemas/otp.py
$otpSchemaContent = @'
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
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\schemas\otp.py") -Content $otpSchemaContent

# OTP Service routers/otp.py
$otpRouterContent = @'
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
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\routers\otp.py") -Content $otpRouterContent

# OTP Service utils/redis_client.py
$redisClientContent = @'
import redis
import json
from typing import Any, Optional, Dict
from app.config import settings

class RedisClient:
    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        self.prefix = settings.REDIS_PREFIX
    
    async def set(self, key: str, value: Any, expire_seconds: int = None) -> None:
        """
        Set key-value pair in Redis with optional expiration
        """
        full_key = f"{self.prefix}{key}"
        
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        
        self.redis.set(full_key, value)
        
        if expire_seconds:
            self.redis.expire(full_key, expire_seconds)
    
    async def get(self, key: str) -> Optional[str]:
        """
        Get value by key from Redis
        """
        full_key = f"{self.prefix}{key}"
        return self.redis.get(full_key)
    
    async def delete(self, key: str) -> None:
        """
        Delete key from Redis
        """
        full_key = f"{self.prefix}{key}"
        self.redis.delete(full_key)
    
    async def exists(self, key: str) -> bool:
        """
        Check if key exists in Redis
        """
        full_key = f"{self.prefix}{key}"
        return self.redis.exists(full_key) > 0
    
    async def get_ttl(self, key: str) -> int:
        """
        Get remaining TTL for key
        """
        full_key = f"{self.prefix}{key}"
        return self.redis.ttl(full_key)
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\utils\redis_client.py") -Content $redisClientContent

# OTP Service services/otp_service.py (continued)
$otpServiceContent = @'
import uuid
import random
import string
import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.otp import OtpLog
from app.schemas.otp import OtpResponse, OtpVerifyResponse
from app.utils.redis_client import RedisClient
from app.config import settings

class OtpService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.redis = RedisClient()
        
    def _generate_otp(self, length: int = 6) -> str:
        """
        Generate a numeric OTP of specified length
        """
        return ''.join(random.choices(string.digits, k=length))
    
    async def _store_otp_in_redis(
        self, 
        phone_number: str, 
        otp_code: str, 
        otp_type: str,
        user_id: Optional[uuid.UUID] = None
    ) -> None:
        """
        Store OTP in Redis with expiration
        """
        key = f"{phone_number}:{otp_type}"
        value = {
            "otp_code": otp_code,
            "created_at": datetime.utcnow().isoformat(),
            "user_id": str(user_id) if user_id else None
        }
        
        await self.redis.set(key, value, settings.OTP_EXPIRY_SECONDS)
    
    async def _log_otp_to_db(
        self,
        phone_number: str,
        otp_code: str,
        otp_type: str,
        email: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None
    ) -> OtpLog:
        """
        Log OTP generation to database for audit
        """
        expires_at = datetime.utcnow() + timedelta(seconds=settings.OTP_EXPIRY_SECONDS)
        
        otp_log = OtpLog(
            user_id=user_id or uuid.uuid4(),
            otp_code=otp_code,  # In production, store hashed value
            otp_type=otp_type,
            phone_number=phone_number,
            email=email,
            expires_at=expires_at
        )
        
        self.db.add(otp_log)
        await self.db.commit()
        await self.db.refresh(otp_log)
        return otp_log
    
    async def _send_sms(self, phone_number: str, otp_code: str) -> bool:
        """
        Send OTP via SMS
        """
        # In a real implementation, integrate with SMS provider
        # For now, just simulate sending
        print(f"SMS sent to {phone_number}: Your OTP is {otp_code}")
        return True
    
    async def _send_email(self, email: str, otp_code: str) -> bool:
        """
        Send OTP via email
        """
        # In a real implementation, integrate with email provider
        # For now, just simulate sending
        print(f"Email sent to {email}: Your OTP is {otp_code}")
        return True
    
    async def generate_and_send_otp(
        self,
        phone_number: str,
        otp_type: str,
        email: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        ip_address: str = "0.0.0.0"
    ) -> OtpResponse:
        """
        Generate OTP, store it, and send to user
        """
        # Check if OTP was recently sent
        key = f"{phone_number}:{otp_type}"
        existing_otp = await self.redis.exists(key)
        
        if existing_otp:
            ttl = await self.redis.get_ttl(key)
            if ttl > settings.OTP_EXPIRY_SECONDS - 60:  # Less than 1 minute ago
                return OtpResponse(
                    success=False,
                    message=f"OTP already sent. Please wait before requesting again.",
                    expires_in=ttl
                )
        
        # Generate new OTP
        otp_code = self._generate_otp(settings.OTP_LENGTH)
        
        # Store in Redis
        await self._store_otp_in_redis(phone_number, otp_code, otp_type, user_id)
        
        # Log to DB
        otp_log = await self._log_otp_to_db(phone_number, otp_code, otp_type, email, user_id)
        
        # Send OTP via SMS
        sms_sent = await self._send_sms(phone_number, otp_code)
        
        # Send OTP via email if provided
        email_sent = False
        if email:
            email_sent = await self._send_email(email, otp_code)
        
        return OtpResponse(
            success=sms_sent or email_sent,
            message="OTP sent successfully",
            expires_in=settings.OTP_EXPIRY_SECONDS,
            reference_id=str(otp_log.id)
        )
    
    async def verify_otp(
        self,
        phone_number: str,
        otp_code: str,
        otp_type: str,
        ip_address: str = "0.0.0.0"
    ) -> OtpVerifyResponse:
        """
        Verify OTP entered by user
        """
        key = f"{phone_number}:{otp_type}"
        stored_data_json = await self.redis.get(key)
        
        if not stored_data_json:
            return OtpVerifyResponse(
                success=False,
                message="OTP expired or not found"
            )
        
        stored_data = json.loads(stored_data_json)
        stored_otp = stored_data.get("otp_code")
        user_id = stored_data.get("user_id")
        
        if stored_otp != otp_code:
            # Update attempt count in DB
            otp_query = select(OtpLog).where(
                OtpLog.phone_number == phone_number,
                OtpLog.otp_type == otp_type,
                OtpLog.verified == False,
                OtpLog.expires_at > datetime.utcnow()
            ).order_by(OtpLog.created_at.desc())
            
            result = await self.db.execute(otp_query)
            otp_log = result.scalars().first()
            
            if otp_log:
                otp_log.verification_attempts += 1
                await self.db.commit()
            
            return OtpVerifyResponse(
                success=False,
                message="Invalid OTP"
            )
        
        # OTP is valid, mark as verified in DB
        otp_query = select(OtpLog).where(
            OtpLog.phone_number == phone_number,
            OtpLog.otp_code == otp_code,  # In production, compare hashed values
            OtpLog.otp_type == otp_type,
            OtpLog.verified == False,
            OtpLog.expires_at > datetime.utcnow()
        ).order_by(OtpLog.created_at.desc())
        
        result = await self.db.execute(otp_query)
        otp_log = result.scalars().first()
        
        if otp_log:
            otp_log.verified = True
            otp_log.verified_at = datetime.utcnow()
            await self.db.commit()
        
        # Delete OTP from Redis after successful verification
        await self.redis.delete(key)
        
        return OtpVerifyResponse(
            success=True,
            message="OTP verified successfully",
            user_id=uuid.UUID(user_id) if user_id else None
        )
    
    async def resend_otp(
        self,
        phone_number: str,
        otp_type: str
    ) -> OtpResponse:
        """
        Resend OTP to user's phone number
        """
        # Find the most recent OTP log for this user and type
        otp_query = select(OtpLog).where(
            OtpLog.phone_number == phone_number,
            OtpLog.otp_type == otp_type,
            OtpLog.verified == False
        ).order_by(OtpLog.created_at.desc())
        
        result = await self.db.execute(otp_query)
        otp_log = result.scalars().first()
        
        if not otp_log:
            raise ValueError("No OTP found to resend")
        
        # Check if last OTP was sent less than 1 minute ago
        if (datetime.utcnow() - otp_log.created_at).total_seconds() < 60:
            return OtpResponse(
                success=False,
                message="Please wait before requesting another OTP",
                expires_in=int(60 - (datetime.utcnow() - otp_log.created_at).total_seconds())
            )
        
        # Generate new OTP and send
        return await self.generate_and_send_otp(
            phone_number=phone_number,
            otp_type=otp_type,
            email=otp_log.email,
            user_id=otp_log.user_id
        )
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\services\otp_service.py") -Content $otpServiceContent

# OTP Service Test
$otpTestContent = @'
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_health_check():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

# Add more tests for OTP sending, verification, etc.
'@

Set-FileContent -Path (Join-Path $otpServiceDir "tests\test_otp.py") -Content $otpTestContent

# OTP Service Dockerfile
$otpDockerfileContent = @'
FROM python:3.11-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
'@

Set-FileContent -Path (Join-Path $otpServiceDir "Dockerfile") -Content $otpDockerfileContent

# OTP Service docker-compose.yml
$otpDockerComposeContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8001:8001"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/otp_service
      - REDIS_HOST=redis
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
    networks:
      - app-network

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=otp_service
    ports:
      - "5433:5432"
    networks:
      - app-network

  redis:
    image: redis:7
    ports:
      - "6379:6379"
    networks:
      - app-network

networks:
  app-network:

volumes:
  postgres_data:
'@

Set-FileContent -Path (Join-Path $otpServiceDir "docker-compose.yml") -Content $otpDockerComposeContent

# OTP Service requirements.txt
$otpRequirementsContent = @'
fastapi==0.103.1
uvicorn==0.23.2
sqlalchemy==2.0.20
asyncpg==0.28.0
alembic==1.12.0
pydantic==2.3.0
pydantic-settings==2.0.3
redis==4.6.0
python-jose==3.3.0
python-multipart==0.0.6
email-validator==2.0.0.post2
pytest==7.4.2
pytest-asyncio==0.21.1
httpx==0.25.0
'@

Set-FileContent -Path (Join-Path $otpServiceDir "requirements.txt") -Content $otpRequirementsContent

#############################################
# 3. KYC SERVICE FILES
#############################################
$kycServiceDir = Join-Path $baseDir "kyc-service"

# KYC Service main.py
$kycMainContent = @'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import kyc, admin
from app.database import create_tables

app = FastAPI(
    title="KYC Service API",
    description="API for KYC document upload, verification, and status checking",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(kyc.router, prefix="/kyc", tags=["kyc"])
app.include_router(admin.router, prefix="/kyc/admin", tags=["admin"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8002, reload=True)
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\main.py") -Content $kycMainContent

# KYC Service config.py
$kycConfigContent = @'
import os
from typing import Optional, Dict, Any, List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "KYC Service"
    API_V1_STR: str = "/api/v1"
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/kyc_service")
    
    # AWS Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_S3_BUCKET: str = os.getenv("AWS_S3_BUCKET", "kyc-documents-bucket")
    AWS_SECRET_MANAGER_NAME: str = os.getenv("AWS_SECRET_MANAGER_NAME", "kyc-service-secrets")
    
    # KYC Provider settings (if using a third-party service like Signzy)
    KYC_PROVIDER_API_KEY: str = os.getenv("KYC_PROVIDER_API_KEY", "your-kyc-provider-api-key")
    KYC_PROVIDER_BASE_URL: str = os.getenv("KYC_PROVIDER_BASE_URL", "https://api.kycprovider.com")
    
    # Security settings
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key")
    
    # Document settings
    ALLOWED_DOCUMENT_TYPES: List[str] = ["aadhaar_card", "pan_card", "passport", "driving_license", "voter_id"]
    MAX_DOCUMENT_SIZE_MB: int = 5
    
    class Config:
        case_sensitive = True

settings = Settings()
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\config.py") -Content $kycConfigContent

# KYC Service database.py
$kycDatabaseContent = @'
import sqlalchemy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

DATABASE_URL = settings.DATABASE_URL
# Convert PostgreSQL URL to async version
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db() -> AsyncSession:
    """
    Dependency for getting async database session
    """
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

async def create_tables():
    """
    Create all tables defined in the models
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\database.py") -Content $kycDatabaseContent

# KYC Service models/kyc.py
$kycModelContent = @'
import uuid
from sqlalchemy import Column, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class KycRequest(Base):
    __tablename__ = "kyc_requests"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    status = Column(String(20), default="Pending")  # Pending/Approved/Rejected
    submitted_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)
    admin_id = Column(UUID(as_uuid=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    
    # Relationships
    documents = relationship("KycDocument", back_populates="kyc_request")
    audit_logs = relationship("KycAuditLog", back_populates="kyc_request")
    
    def __repr__(self):
        return f"<KycRequest {self.id} {self.status}>"

class KycDocument(Base):
    __tablename__ = "kyc_documents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kyc_id = Column(UUID(as_uuid=True), ForeignKey("kyc_requests.id", ondelete="CASCADE"), index=True)
    doc_type = Column(String(50))  # Aadhaar/PAN/etc.
    doc_url = Column(Text, nullable=False)
    doc_metadata = Column(JSONB, default={})
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    kyc_request = relationship("KycRequest", back_populates="documents")
    
    def __repr__(self):
        return f"<KycDocument {self.id} {self.doc_type}>"

class KycAuditLog(Base):
    __tablename__ = "kyc_audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kyc_id = Column(UUID(as_uuid=True), ForeignKey("kyc_requests.id", ondelete="CASCADE"), index=True)
    action = Column(String(50))  # Submitted/Approved/Rejected
    actor_type = Column(String(20))  # User/Admin
    actor_id = Column(UUID(as_uuid=True), nullable=False)
    remarks = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    kyc_request = relationship("KycRequest", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<KycAuditLog {self.id} {self.action}>"
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\models\kyc.py") -Content $kycModelContent

# KYC Service schemas/kyc.py
$kycSchemaContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator, HttpUrl

class DocumentBase(BaseModel):
    doc_type: str
    doc_metadata: Optional[Dict[str, Any]] = {}

class DocumentCreate(DocumentBase):
    pass

class DocumentResponse(DocumentBase):
    id: uuid.UUID
    kyc_id: uuid.UUID
    doc_url: str
    uploaded_at: datetime
    
    class Config:
        orm_mode = True

class KycRequestBase(BaseModel):
    user_id: uuid.UUID

class KycRequestCreate(KycRequestBase):
    pass

class KycRequestUpdate(BaseModel):
    status: Optional[str] = None
    admin_id: Optional[uuid.UUID] = None
    rejection_reason: Optional[str] = None

class KycRequestResponse(KycRequestBase):
    id: uuid.UUID
    status: str
    submitted_at: datetime
    reviewed_at: Optional[datetime] = None
    documents: List[DocumentResponse] = []
    
    class Config:
        orm_mode = True

class KycStatusResponse(BaseModel):
    status: str
    submitted_at: datetime
    reviewed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    
    class Config:
        orm_mode = True

class KycAuditLogBase(BaseModel):
    kyc_id: uuid.UUID
    action: str
    actor_type: str
    actor_id: uuid.UUID
    remarks: Optional[str] = None

class KycAuditLogCreate(KycAuditLogBase):
    pass

class KycAuditLogResponse(KycAuditLogBase):
    id: uuid.UUID
    timestamp: datetime
    
    class Config:
        orm_mode = True

class AdminVerifyRequest(BaseModel):
    status: str  # Approved/Rejected
    remarks: Optional[str] = None
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\schemas\kyc.py") -Content $kycSchemaContent

# KYC Service routers/kyc.py
$kycRouterContent = @'
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
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\routers\kyc.py") -Content $kycRouterContent

# KYC Service routers/admin.py
$kycAdminRouterContent = @'
from fastapi import APIRouter, Depends, HTTPException, status
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
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\routers\admin.py") -Content $kycAdminRouterContent

# KYC Service services/kyc_service.py (continued)
$kycServiceContent = @'
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
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\services\kyc_service.py") -Content $kycServiceContent

# KYC Service services/storage_service.py
$storageServiceContent = @'
import uuid
import os
import boto3
from fastapi import UploadFile
from typing import Optional
from app.config import settings

class StorageService:
    def __init__(self):
        # Initialize AWS S3 client
        self.s3 = boto3.client(
            's3',
            region_name=settings.AWS_REGION
        )
        self.bucket = settings.AWS_S3_BUCKET
    
    async def upload_document(self, file: UploadFile, path: str) -> str:
        """
        Upload document to S3
        """
        file_content = await file.read()
        file_ext = os.path.splitext(file.filename)[1]
        file_key = f"{path}/{uuid.uuid4()}{file_ext}"
        
        # For local development, you might want to save to disk instead
        # Uncomment this if needed:
        """
        os.makedirs(os.path.dirname(f"./uploads/{file_key}"), exist_ok=True)
        with open(f"./uploads/{file_key}", "wb") as f:
            f.write(file_content)
        return f"./uploads/{file_key}"
        """
        
        # Upload to S3
        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=file_key,
                Body=file_content,
                ContentType=file.content_type
            )
            
            # Generate S3 URL
            url = f"https://{self.bucket}.s3.{settings.AWS_REGION}.amazonaws.com/{file_key}"
            return url
        except Exception as e:
            # In production, handle S3 errors properly
            print(f"Error uploading to S3: {str(e)}")
            # For development, save locally as fallback
            os.makedirs("./uploads", exist_ok=True)
            with open(f"./uploads/{uuid.uuid4()}{file_ext}", "wb") as f:
                await file.seek(0)
                f.write(await file.read())
            return f"local://uploads/{uuid.uuid4()}{file_ext}"
    
    def get_document_url(self, file_key: str) -> str:
        """
        Get document URL from S3
        """
        return f"https://{self.bucket}.s3.{settings.AWS_REGION}.amazonaws.com/{file_key}"
    
    async def delete_document(self, file_key: str) -> bool:
        """
        Delete document from S3
        """
        try:
            self.s3.delete_object(
                Bucket=self.bucket,
                Key=file_key
            )
            return True
        except Exception as e:
            print(f"Error deleting from S3: {str(e)}")
            return False
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\services\storage_service.py") -Content $storageServiceContent

# KYC Service utils/auth.py
$kycAuthContent = @'
import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import Optional
from app.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> uuid.UUID:
    """
    Get current user ID from JWT token
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    return uuid.UUID(user_id)

async def get_admin_user_id(token: str = Depends(oauth2_scheme)) -> uuid.UUID:
    """
    Get admin user ID from JWT token (with admin role verification)
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    permission_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Not enough permissions",
    )
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        # Check if user has admin role
        roles = payload.get("roles", [])
        if "admin" not in roles:
            raise permission_exception
    except JWTError:
        raise credentials_exception
    
    return uuid.UUID(user_id)
'@

Set-FileContent -Path (Join-Path $kycServiceDir "app\utils\auth.py") -Content $kycAuthContent

# KYC Service Dockerfile
$kycDockerfileContent = @'
FROM python:3.11-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create uploads directory
RUN mkdir -p ./uploads

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
'@

Set-FileContent -Path (Join-Path $kycServiceDir "Dockerfile") -Content $kycDockerfileContent

# KYC Service docker-compose.yml
$kycDockerComposeContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8002:8002"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/kyc_service
      - AWS_REGION=us-east-1
      - AWS_S3_BUCKET=kyc-documents-bucket
      - JWT_SECRET_KEY=your_development_jwt_secret
    depends_on:
      - db
    volumes:
      - .:/app
      - ./uploads:/app/uploads
    networks:
      - app-network

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=kyc_service
    ports:
      - "5434:5432"
    networks:
      - app-network

networks:
  app-network:

volumes:
  postgres_data:
'@

Set-FileContent -Path (Join-Path $kycServiceDir "docker-compose.yml") -Content $kycDockerComposeContent

# KYC Service requirements.txt
$kycRequirementsContent = @'
fastapi==0.103.1
uvicorn==0.23.2
sqlalchemy==2.0.20
asyncpg==0.28.0
alembic==1.12.0
pydantic==2.3.0
pydantic-settings==2.0.3
python-jose==3.3.0
python-multipart==0.0.6
boto3==1.28.38
pytest==7.4.2
pytest-asyncio==0.21.1
httpx==0.25.0
'@

Set-FileContent -Path (Join-Path $kycServiceDir "requirements.txt") -Content $kycRequirementsContent

#############################################
# 4. PAYMENT SERVICE FILES
#############################################
$paymentServiceDir = Join-Path $baseDir "payment-service"

# Payment Service main.py
$paymentMainContent = @'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import payments, settlements
from app.database import create_tables

app = FastAPI(
    title="Payment and Settlement Service API",
    description="API for handling credit card to UPI payments and settlements",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(payments.router, prefix="/payments", tags=["payments"])
app.include_router(settlements.router, prefix="/settlements", tags=["settlements"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8003, reload=True)
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\main.py") -Content $paymentMainContent

# Payment Service config.py
$paymentConfigContent = @'
import os
from typing import Optional, Dict, Any, List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Payment and Settlement Service"
    API_V1_STR: str = "/api/v1"
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/payment_service")
    
    # AWS Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_SECRET_MANAGER_NAME: str = os.getenv("AWS_SECRET_MANAGER_NAME", "payment-service-secrets")
    AWS_SQS_QUEUE_URL: str = os.getenv("AWS_SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/settlement-queue")
    AWS_EVENTBRIDGE_BUS: str = os.getenv("AWS_EVENTBRIDGE_BUS", "payment-events")
    
    # Payment Gateway settings (Razorpay)
    RAZORPAY_KEY_ID: str = os.getenv("RAZORPAY_KEY_ID", "your-razorpay-key-id")
    RAZORPAY_KEY_SECRET: str = os.getenv("RAZORPAY_KEY_SECRET", "your-razorpay-key-secret")
    
    # Security settings
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key")
    
    # Transaction settings
    TRANSACTION_TIMEOUT_SECONDS: int = 300  # 5 minutes
    MAX_RETRY_ATTEMPTS: int = 3
    
    # UPI settings
    UPI_PROVIDERS: List[str] = ["BHIM", "GooglePay", "PhonePe", "Paytm", "AmazonPay"]
    
    class Config:
        case_sensitive = True

settings = Settings()
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\config.py") -Content $paymentConfigContent

# Payment Service database.py
$paymentDatabaseContent = @'
import sqlalchemy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

DATABASE_URL = settings.DATABASE_URL
# Convert PostgreSQL URL to async version
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db() -> AsyncSession:
    """
    Dependency for getting async database session
    """
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

async def create_tables():
    """
    Create all tables defined in the models
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\database.py") -Content $paymentDatabaseContent

# Payment Service models/payment.py
$paymentModelContent = @'
import uuid
from sqlalchemy import Column, String, DateTime, Numeric, Integer, Boolean, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    amount = Column(Numeric(10, 2), nullable=False)
    status = Column(String(20), default="Initiated")  # Initiated/Processing/Success/Failed
    upi_id = Column(String(100), nullable=False)
    credit_card_last4 = Column(String(4), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    payment_gateway_txn_id = Column(String(100), nullable=True)
    payment_method = Column(String(50), nullable=True)  # VISA/MasterCard/RuPay
    payment_gateway_response = Column(JSONB, default={})
    
    # Relationships
    settlement = relationship("Settlement", back_populates="transaction", uselist=False)
    retry_logs = relationship("PaymentRetryLog", back_populates="transaction")
    failed_transaction = relationship("FailedTransaction", back_populates="transaction", uselist=False)
    
    # Indices
    __table_args__ = (
        Index('idx_txn_user_created', "user_id", "created_at"),
        Index('idx_txn_status', "status"),
    )
    
    def __repr__(self):
        return f"<Transaction {self.id} {self.status}>"

class Settlement(Base):
    __tablename__ = "settlements"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    transaction_id = Column(UUID(as_uuid=True), ForeignKey("transactions.id", ondelete="CASCADE"), unique=True)
    settled_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="Pending")  # Pending/Settled/Failed
    retry_count = Column(Integer, default=0)
    settlement_reference = Column(String(100), nullable=True)
    settlement_response = Column(JSONB, default={})
    
    # Relationships
    transaction = relationship("Transaction", back_populates="settlement")
    
    def __repr__(self):
        return f"<Settlement {self.id} {self.status}>"

class PaymentRetryLog(Base):
    __tablename__ = "payment_retry_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    transaction_id = Column(UUID(as_uuid=True), ForeignKey("transactions.id", ondelete="CASCADE"))
    retry_reason = Column(Text, nullable=False)
    retried_at = Column(DateTime, default=datetime.utcnow)
    attempt_number = Column(Integer, default=1)
    success = Column(Boolean, default=False)
    response = Column(JSONB, default={})
    
    # Relationships
    transaction = relationship("Transaction", back_populates="retry_logs")
    
    def __repr__(self):
        return f"<PaymentRetryLog {self.id} {self.success}>"

class FailedTransaction(Base):
    __tablename__ = "failed_transactions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    transaction_id = Column(UUID(as_uuid=True), ForeignKey("transactions.id", ondelete="CASCADE"), unique=True)
    failure_reason = Column(Text, nullable=False)
    failed_at = Column(DateTime, default=datetime.utcnow)
    error_code = Column(String(50), nullable=True)
    error_details = Column(JSONB, default={})
    refund_initiated = Column(Boolean, default=False)
    refund_status = Column(String(20), nullable=True)  # Initiated/Completed/Failed
    refund_reference = Column(String(100), nullable=True)
    
    # Relationships
    transaction = relationship("Transaction", back_populates="failed_transaction")
    
    def __repr__(self):
        return f"<FailedTransaction {self.id} {self.refund_status}>"
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\models\payment.py") -Content $paymentModelContent

# Payment Service schemas/payment.py
$paymentSchemaContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator, condecimal

class PaymentBase(BaseModel):
    amount: condecimal(max_digits=10, decimal_places=2)  # type: ignore
    upi_id: str
    
class PaymentCreate(PaymentBase):
    credit_card_token: str
    credit_card_last4: str
    payment_method: Optional[str] = None
    
class PaymentResponse(PaymentBase):
    id: uuid.UUID
    status: str
    created_at: datetime
    updated_at: datetime
    credit_card_last4: str
    payment_method: Optional[str] = None
    
    class Config:
        orm_mode = True

class PaymentStatusResponse(BaseModel):
    id: uuid.UUID
    status: str
    amount: condecimal(max_digits=10, decimal_places=2)  # type: ignore
    upi_id: str
    created_at: datetime
    updated_at: datetime
    payment_gateway_txn_id: Optional[str] = None
    
    class Config:
        orm_mode = True

class PaymentHistoryItem(PaymentStatusResponse):
    payment_method: Optional[str] = None
    credit_card_last4: str
    
    class Config:
        orm_mode = True

class SettlementBase(BaseModel):
    transaction_id: uuid.UUID
    
class SettlementCreate(SettlementBase):
    pass
    
class SettlementResponse(SettlementBase):
    id: uuid.UUID
    status: str
    settled_at: Optional[datetime] = None
    retry_count: int
    settlement_reference: Optional[str] = None
    
    class Config:
        orm_mode = True

class FailedTransactionResponse(BaseModel):
    id: uuid.UUID
    transaction_id: uuid.UUID
    failure_reason: str
    failed_at: datetime
    error_code: Optional[str] = None
    refund_initiated: bool
    refund_status: Optional[str] = None
    
    class Config:
        orm_mode = True

class PaymentWebhookEvent(BaseModel):
    event_type: str
    transaction_id: uuid.UUID
    payment_gateway_txn_id: str
    status: str
    amount: condecimal(max_digits=10, decimal_places=2)  # type: ignore
    gateway_response: Dict[str, Any]
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\schemas\payment.py") -Content $paymentSchemaContent

# Payment Service routers/payments.py (continued)
$paymentRouterContent = @'
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
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\routers\payments.py") -Content $paymentRouterContent

# Payment Service routers/settlements.py
$settlementRouterContent = @'
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
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\routers\settlements.py") -Content $settlementRouterContent

# Payment Service services/payment_service.py
$paymentServiceContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from decimal import Decimal
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.payment import Transaction, PaymentRetryLog, FailedTransaction, Settlement
from app.schemas.payment import PaymentCreate, PaymentResponse, PaymentStatusResponse, PaymentHistoryItem
from app.services.payment_gateway import PaymentGateway
from app.services.event_service import EventService
from app.config import settings

class PaymentService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.payment_gateway = PaymentGateway()
        self.event_service = EventService()
    
    async def initiate_payment(self, user_id: uuid.UUID, payment_data: PaymentCreate) -> Transaction:
        """
        Initiate a payment from credit card to UPI
        """
        # Create transaction record
        transaction = Transaction(
            user_id=user_id,
            amount=payment_data.amount,
            upi_id=payment_data.upi_id,
            credit_card_last4=payment_data.credit_card_last4,
            payment_method=payment_data.payment_method,
            status="Initiated"
        )
        self.db.add(transaction)
        await self.db.commit()
        await self.db.refresh(transaction)
        
        try:
            # Call payment gateway to process the payment
            payment_result = await self.payment_gateway.process_payment(
                amount=payment_data.amount,
                card_token=payment_data.credit_card_token,
                upi_id=payment_data.upi_id,
                transaction_id=str(transaction.id)
            )
            
            # Update transaction with gateway response
            transaction.payment_gateway_txn_id = payment_result.get("gateway_txn_id")
            transaction.status = "Processing"
            transaction.payment_gateway_response = payment_result
            
            # Publish event to EventBridge
            await self.event_service.publish_payment_event(
                transaction_id=transaction.id,
                status="Processing",
                amount=payment_data.amount,
                payment_gateway_txn_id=payment_result.get("gateway_txn_id"),
                user_id=user_id
            )
            
        except Exception as e:
            # Handle payment gateway errors
            transaction.status = "Failed"
            
            # Create failed transaction record
            failed_transaction = FailedTransaction(
                transaction_id=transaction.id,
                failure_reason=str(e),
                error_code="PAYMENT_GATEWAY_ERROR",
                error_details={"error": str(e)}
            )
            self.db.add(failed_transaction)
            
            # Publish failure event
            await self.event_service.publish_payment_event(
                transaction_id=transaction.id,
                status="Failed",
                amount=payment_data.amount,
                user_id=user_id,
                error=str(e)
            )
        
        await self.db.commit()
        await self.db.refresh(transaction)
        
        # Create settlement record for successful initiations
        if transaction.status == "Processing":
            settlement = Settlement(
                transaction_id=transaction.id,
                status="Pending"
            )
            self.db.add(settlement)
            await self.db.commit()
        
        return transaction
    
    async def get_payment_status(self, txn_id: uuid.UUID, user_id: uuid.UUID) -> Transaction:
        """
        Get status of a payment transaction
        """
        query = select(Transaction).where(
            Transaction.id == txn_id,
            Transaction.user_id == user_id
        )
        result = await self.db.execute(query)
        transaction = result.scalars().first()
        
        if not transaction:
            raise ValueError(f"Transaction not found with ID: {txn_id}")
        
        # If transaction is in Processing state for too long, check with gateway
        if (transaction.status == "Processing" and 
            (datetime.utcnow() - transaction.updated_at).total_seconds() > settings.TRANSACTION_TIMEOUT_SECONDS):
            try:
                # Call payment gateway to check status
                gateway_status = await self.payment_gateway.check_payment_status(
                    transaction.payment_gateway_txn_id
                )
                
                # Update transaction status based on gateway response
                if gateway_status.get("status") == "SUCCESS":
                    transaction.status = "Success"
                elif gateway_status.get("status") == "FAILED":
                    transaction.status = "Failed"
                    
                    # Create failed transaction record
                    failed_transaction = FailedTransaction(
                        transaction_id=transaction.id,
                        failure_reason="Payment failed at gateway",
                        error_code=gateway_status.get("error_code"),
                        error_details=gateway_status
                    )
                    self.db.add(failed_transaction)
                
                transaction.payment_gateway_response.update(gateway_status)
                await self.db.commit()
                await self.db.refresh(transaction)
                
                # Publish status update event
                await self.event_service.publish_payment_event(
                    transaction_id=transaction.id,
                    status=transaction.status,
                    amount=transaction.amount,
                    payment_gateway_txn_id=transaction.payment_gateway_txn_id,
                    user_id=transaction.user_id
                )
            except Exception as e:
                # Log error but don't change transaction status
                print(f"Error checking gateway status: {str(e)}")
        
        return transaction
    
    async def get_payment_history(
        self, 
        user_id: uuid.UUID, 
        limit: int = 10, 
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[Transaction]:
        """
        Get payment transaction history for a user
        """
        query = select(Transaction).where(Transaction.user_id == user_id)
        
        if status:
            query = query.where(Transaction.status == status)
        
        query = query.order_by(desc(Transaction.created_at)).offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_failed_transaction(self, txn_id: uuid.UUID, user_id: uuid.UUID) -> FailedTransaction:
        """
        Get details of a failed transaction
        """
        query = select(FailedTransaction).join(Transaction).where(
            Transaction.id == txn_id,
            Transaction.user_id == user_id,
            Transaction.status == "Failed"
        )
        
        result = await self.db.execute(query)
        failed_transaction = result.scalars().first()
        
        if not failed_transaction:
            raise ValueError(f"Failed transaction not found for ID: {txn_id}")
        
        return failed_transaction
    
    async def process_webhook_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process webhook events from payment gateway
        """
        # Validate event data
        if "transaction_id" not in event_data or "status" not in event_data:
            raise ValueError("Invalid webhook event data")
        
        # Find transaction by gateway transaction ID
        gateway_txn_id = event_data.get("transaction_id")
        query = select(Transaction).where(
            Transaction.payment_gateway_txn_id == gateway_txn_id
        )
        
        result = await self.db.execute(query)
        transaction = result.scalars().first()
        
        if not transaction:
            raise ValueError(f"Transaction not found for gateway ID: {gateway_txn_id}")
        
        # Update transaction based on webhook event
        status = event_data.get("status")
        if status == "SUCCESS" and transaction.status != "Success":
            transaction.status = "Success"
        elif status == "FAILED" and transaction.status != "Failed":
            transaction.status = "Failed"
            
            # Create failed transaction record if not exists
            failed_query = select(FailedTransaction).where(
                FailedTransaction.transaction_id == transaction.id
            )
            failed_result = await self.db.execute(failed_query)
            if not failed_result.scalars().first():
                failed_transaction = FailedTransaction(
                    transaction_id=transaction.id,
                    failure_reason="Payment failed (webhook notification)",
                    error_code=event_data.get("error_code"),
                    error_details=event_data
                )
                self.db.add(failed_transaction)
        
        # Update transaction data
        transaction.payment_gateway_response.update(event_data)
        transaction.updated_at = datetime.utcnow()
        
        await self.db.commit()
        
        # Publish event to EventBridge
        await self.event_service.publish_payment_event(
            transaction_id=transaction.id,
            status=transaction.status,
            amount=transaction.amount,
            payment_gateway_txn_id=transaction.payment_gateway_txn_id,
            user_id=transaction.user_id,
            webhook_data=event_data
        )
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\services\payment_service.py") -Content $paymentServiceContent

# Payment Service services/settlement_service.py
$settlementServiceContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.payment import Transaction, Settlement
from app.services.upi_service import UpiService
from app.services.event_service import EventService
from app.config import settings

class SettlementService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.upi_service = UpiService()
        self.event_service = EventService()
    
    async def trigger_settlement(self, transaction_id: uuid.UUID) -> Settlement:
        """
        Trigger settlement for a transaction
        """
        # Get transaction with settlement
        query = select(Transaction).where(
            Transaction.id == transaction_id,
            Transaction.status == "Success"
        ).options(
            selectinload(Transaction.settlement)
        )
        
        result = await self.db.execute(query)
        transaction = result.scalars().first()
        
        if not transaction:
            raise ValueError(f"Successful transaction not found with ID: {transaction_id}")
        
        # Check if settlement already exists
        if transaction.settlement:
            if transaction.settlement.status == "Settled":
                raise ValueError(f"Transaction already settled at: {transaction.settlement.settled_at}")
            
            settlement = transaction.settlement
        else:
            # Create new settlement
            settlement = Settlement(
                transaction_id=transaction_id,
                status="Pending"
            )
            self.db.add(settlement)
            await self.db.commit()
            await self.db.refresh(settlement)
        
        # Process settlement if it's pending or failed
        if settlement.status in ["Pending", "Failed"]:
            try:
                # Call UPI service to process settlement
                settlement_result = await self.upi_service.process_settlement(
                    amount=transaction.amount,
                    upi_id=transaction.upi_id,
                    transaction_id=str(transaction.id),
                    settlement_id=str(settlement.id)
                )
                
                # Update settlement based on result
                settlement.status = "Settled"
                settlement.settled_at = datetime.utcnow()
                settlement.settlement_reference = settlement_result.get("reference_id")
                settlement.settlement_response = settlement_result
                
                # Publish event
                await self.event_service.publish_settlement_event(
                    transaction_id=transaction.id,
                    settlement_id=settlement.id,
                    status="Settled",
                    amount=transaction.amount,
                    user_id=transaction.user_id
                )
                
            except Exception as e:
                # Handle settlement failure
                settlement.status = "Failed"
                settlement.retry_count += 1
                settlement.settlement_response = {"error": str(e)}
                
                # Publish failure event
                await self.event_service.publish_settlement_event(
                    transaction_id=transaction.id,
                    settlement_id=settlement.id,
                    status="Failed",
                    amount=transaction.amount,
                    user_id=transaction.user_id,
                    error=str(e)
                )
            
            await self.db.commit()
            await self.db.refresh(settlement)
        
        return settlement
    
    async def get_settlements_by_user(
        self,
        user_id: uuid.UUID,
        transaction_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        limit: int = 10,
        offset: int = 0
    ) -> List[Settlement]:
        """
        Get settlements for a user's transactions
        """
        query = select(Settlement).join(Transaction).where(Transaction.user_id == user_id)
        
        if transaction_id:
            query = query.where(Settlement.transaction_id == transaction_id)
        
        if status:
            query = query.where(Settlement.status == status)
        
        query = query.order_by(desc(Settlement.settled_at if Settlement.settled_at else Settlement.id))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_settlements_by_status(self, status: str, limit: int = 50) -> List[Settlement]:
        """
        Get settlements by status (for admin use)
        """
        query = select(Settlement).where(
            Settlement.status == status
        ).order_by(
            Settlement.id
        ).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def retry_settlement(self, settlement_id: uuid.UUID) -> Settlement:
        """
        Retry a failed settlement
        """
        # Get settlement with transaction
        query = select(Settlement).where(
            Settlement.id == settlement_id,
            Settlement.status == "Failed"
        ).options(
            selectinload(Settlement.transaction)
        )
        
        result = await self.db.execute(query)
        settlement = result.scalars().first()
        
        if not settlement:
            raise ValueError(f"Failed settlement not found with ID: {settlement_id}")
        
        if settlement.retry_count >= settings.MAX_RETRY_ATTEMPTS:
            raise ValueError(f"Maximum retry attempts reached: {settlement.retry_count}")
        
        # Increment retry count
        settlement.retry_count += 1
        await self.db.commit()
        
        # Process the settlement
        try:
            # Call UPI service to process settlement
            settlement_result = await self.upi_service.process_settlement(
                amount=settlement.transaction.amount,
                upi_id=settlement.transaction.upi_id,
                transaction_id=str(settlement.transaction.id),
                settlement_id=str(settlement.id)
            )
            
            # Update settlement based on result
            settlement.status = "Settled"
            settlement.settled_at = datetime.utcnow()
            settlement.settlement_reference = settlement_result.get("reference_id")
            settlement.settlement_response = settlement_result
            
            # Publish event
            await self.event_service.publish_settlement_event(
                transaction_id=settlement.transaction.id,
                settlement_id=settlement.id,
                status="Settled",
                amount=settlement.transaction.amount,
                user_id=settlement.transaction.user_id
            )
            
        except Exception as e:
            # Handle settlement failure
            settlement.status = "Failed"
            settlement.settlement_response = {"error": str(e)}
            
            # Publish failure event
            await self.event_service.publish_settlement_event(
                transaction_id=settlement.transaction.id,
                settlement_id=settlement.id,
                status="Failed",
                amount=settlement.transaction.amount,
                user_id=settlement.transaction.user_id,
                error=str(e)
            )
        
        await self.db.commit()
        await self.db.refresh(settlement)
        return settlement
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\services\settlement_service.py") -Content $settlementServiceContent

# Payment Service services/payment_gateway.py
$paymentGatewayContent = @'
from typing import Dict, Any
from decimal import Decimal
import json
import razorpay
from app.config import settings

class PaymentGateway:
    def __init__(self):
        # Initialize Razorpay client
        self.client = razorpay.Client(
            auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
        )
    
    async def process_payment(
        self,
        amount: Decimal,
        card_token: str,
        upi_id: str,
        transaction_id: str
    ) -> Dict[str, Any]:
        """
        Process payment through Razorpay
        For development, simulate payment gateway response
        """
        # In a real implementation, call Razorpay API
        # For development, simulate gateway response
        
        # Convert Decimal to paise (Razorpay uses smallest currency unit)
        amount_in_paise = int(amount * 100)
        
        # Simulate Razorpay payment
        try:
            # In production, this would be a real API call:
            # payment = self.client.payment.create({
            #     'amount': amount_in_paise,
            #     'currency': 'INR',
            #     'payment_capture': '1',
            #     'notes': {
            #         'transaction_id': transaction_id,
            #         'upi_id': upi_id
            #     }
            # })
            
            # Simulated response
            gateway_txn_id = f"pay_{transaction_id.replace('-', '')[:16]}"
            
            return {
                "gateway_txn_id": gateway_txn_id,
                "status": "created",
                "amount": str(amount),
                "currency": "INR",
                "created_at": "2023-09-15T10:30:00Z",
                "card_id": card_token,
                "upi_id": upi_id
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"Payment gateway error: {str(e)}")
            raise ValueError(f"Payment processing failed: {str(e)}")
    
    async def check_payment_status(self, gateway_txn_id: str) -> Dict[str, Any]:
        """
        Check payment status with Razorpay
        For development, simulate payment gateway response
        """
        # In a real implementation, call Razorpay API
        # For development, simulate gateway response
        
        try:
            # In production, this would be a real API call:
            # payment = self.client.payment.fetch(gateway_txn_id)
            
            # Simulated response - assume payment succeeded
            return {
                "gateway_txn_id": gateway_txn_id,
                "status": "SUCCESS",
                "amount": "1000.00",
                "currency": "INR",
                "created_at": "2023-09-15T10:30:00Z",
                "updated_at": "2023-09-15T10:31:00Z"
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"Payment gateway status check error: {str(e)}")
            raise ValueError(f"Payment status check failed: {str(e)}")
    
    async def process_refund(
        self,
        gateway_txn_id: str,
        amount: Decimal = None
    ) -> Dict[str, Any]:
        """
        Process refund through Razorpay
        For development, simulate refund response
        """
        # In a real implementation, call Razorpay API
        # For development, simulate gateway response
        
        try:
            # In production, this would be a real API call:
            # refund = self.client.payment.refund(gateway_txn_id, {
            #     'amount': int(amount * 100) if amount else None
            # })
            
            # Simulated response
            refund_id = f"rfnd_{gateway_txn_id[4:]}"
            
            return {
                "refund_id": refund_id,
                "payment_id": gateway_txn_id,
                "status": "processed",
                "amount": str(amount) if amount else "1000.00",
                "currency": "INR",
                "created_at": "2023-09-15T11:00:00Z"
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"Payment gateway refund error: {str(e)}")
            raise ValueError(f"Refund processing failed: {str(e)}")
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\services\payment_gateway.py") -Content $paymentGatewayContent

# Payment Service services/upi_service.py
$upiServiceContent = @'
from typing import Dict, Any
from decimal import Decimal
import uuid
from app.config import settings

class UpiService:
    def __init__(self):
        # In a real implementation, you might initialize UPI provider client
        pass
    
    async def process_settlement(
        self,
        amount: Decimal,
        upi_id: str,
        transaction_id: str,
        settlement_id: str
    ) -> Dict[str, Any]:
        """
        Process UPI settlement
        For development, simulate UPI settlement response
        """
        # In a real implementation, call UPI provider API
        # For development, simulate response
        
        try:
            # Simulated response
            reference_id = f"upi_{uuid.uuid4().hex[:16]}"
            
            return {
                "reference_id": reference_id,
                "status": "SUCCESS",
                "amount": str(amount),
                "upi_id": upi_id,
                "transaction_id": transaction_id,
                "settlement_id": settlement_id,
                "timestamp": "2023-09-15T12:00:00Z"
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"UPI settlement error: {str(e)}")
            raise ValueError(f"UPI settlement failed: {str(e)}")
    
    async def check_settlement_status(self, reference_id: str) -> Dict[str, Any]:
        """
        Check UPI settlement status
        For development, simulate UPI status response
        """
        # In a real implementation, call UPI provider API
        # For development, simulate response
        
        try:
            # Simulated response
            return {
                "reference_id": reference_id,
                "status": "SUCCESS",
                "amount": "1000.00",
                "upi_id": "user@okicici",
                "timestamp": "2023-09-15T12:01:00Z"
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"UPI status check error: {str(e)}")
            raise ValueError(f"UPI status check failed: {str(e)}")
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\services\upi_service.py") -Content $upiServiceContent

# Payment Service services/event_service.py (continued)
$eventServiceContent = @'
import uuid
import json
import boto3
from decimal import Decimal
from typing import Dict, Any, Optional
from app.config import settings

class DecimalEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for Decimal values
    """
    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        if isinstance(o, uuid.UUID):
            return str(o)
        return super(DecimalEncoder, self).default(o)

class EventService:
    def __init__(self):
        # Initialize AWS EventBridge client
        self.eventbridge = boto3.client(
            'events',
            region_name=settings.AWS_REGION
        )
        
        # Initialize AWS SQS client
        self.sqs = boto3.client(
            'sqs',
            region_name=settings.AWS_REGION
        )
    
    async def publish_payment_event(
        self,
        transaction_id: uuid.UUID,
        status: str,
        amount: Decimal,
        user_id: uuid.UUID,
        payment_gateway_txn_id: Optional[str] = None,
        error: Optional[str] = None,
        webhook_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Publish payment event to EventBridge
        For development, just log the event
        """
        event_detail = {
            "event_type": f"payment.{status.lower()}",
            "transaction_id": str(transaction_id),
            "status": status,
            "amount": str(amount),
            "user_id": str(user_id),
            "timestamp": f"{datetime.utcnow().isoformat()}Z"
        }
        
        if payment_gateway_txn_id:
            event_detail["payment_gateway_txn_id"] = payment_gateway_txn_id
        
        if error:
            event_detail["error"] = error
            
        if webhook_data:
            event_detail["webhook_data"] = webhook_data
        
        # In production, publish to EventBridge
        # try:
        #     response = self.eventbridge.put_events(
        #         Entries=[
        #             {
        #                 'Source': 'payment.service',
        #                 'DetailType': f'payment.{status.lower()}',
        #                 'Detail': json.dumps(event_detail, cls=DecimalEncoder),
        #                 'EventBusName': settings.AWS_EVENTBRIDGE_BUS
        #             }
        #         ]
        #     )
        #     print(f"Published event: {response}")
        # except Exception as e:
        #     print(f"Error publishing event: {str(e)}")
        
        # For development, just log the event
        print(f"PAYMENT EVENT: {json.dumps(event_detail, cls=DecimalEncoder)}")
    
    async def publish_settlement_event(
        self,
        transaction_id: uuid.UUID,
        settlement_id: uuid.UUID,
        status: str,
        amount: Decimal,
        user_id: uuid.UUID,
        error: Optional[str] = None
    ) -> None:
        """
        Publish settlement event to EventBridge and SQS
        For development, just log the event
        """
        event_detail = {
            "event_type": f"settlement.{status.lower()}",
            "transaction_id": str(transaction_id),
            "settlement_id": str(settlement_id),
            "status": status,
            "amount": str(amount),
            "user_id": str(user_id),
            "timestamp": f"{datetime.utcnow().isoformat()}Z"
        }
        
        if error:
            event_detail["error"] = error
        
        # In production, publish to EventBridge
        # try:
        #     response = self.eventbridge.put_events(
        #         Entries=[
        #             {
        #                 'Source': 'settlement.service',
        #                 'DetailType': f'settlement.{status.lower()}',
        #                 'Detail': json.dumps(event_detail, cls=DecimalEncoder),
        #                 'EventBusName': settings.AWS_EVENTBRIDGE_BUS
        #             }
        #         ]
        #     )
        #     print(f"Published event: {response}")
        # except Exception as e:
        #     print(f"Error publishing event: {str(e)}")
        
        # For successful settlements, also send to SQS for notification
        if status == "Settled":
            # In production, send to SQS
            # try:
            #     response = self.sqs.send_message(
            #         QueueUrl=settings.AWS_SQS_QUEUE_URL,
            #         MessageBody=json.dumps(event_detail, cls=DecimalEncoder)
            #     )
            #     print(f"Sent to SQS: {response}")
            # except Exception as e:
            #     print(f"Error sending to SQS: {str(e)}")
            
            # For development, just log the event
            print(f"SQS MESSAGE: {json.dumps(event_detail, cls=DecimalEncoder)}")
        
        # For development, log all events
        print(f"SETTLEMENT EVENT: {json.dumps(event_detail, cls=DecimalEncoder)}")
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\services\event_service.py") -Content $eventServiceContent

# Payment Service utils/auth.py
$paymentAuthContent = @'
import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import Optional
from app.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> uuid.UUID:
    """
    Get current user ID from JWT token
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    return uuid.UUID(user_id)

async def get_admin_user_id(token: str = Depends(oauth2_scheme)) -> uuid.UUID:
    """
    Get admin user ID from JWT token (with admin role verification)
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    permission_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Not enough permissions",
    )
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        # Check if user has admin role
        roles = payload.get("roles", [])
        if "admin" not in roles:
            raise permission_exception
    except JWTError:
        raise credentials_exception
    
    return uuid.UUID(user_id)
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "app\utils\auth.py") -Content $paymentAuthContent

# Payment Service Dockerfile
$paymentDockerfileContent = @'
FROM python:3.11-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "Dockerfile") -Content $paymentDockerfileContent

# Payment Service docker-compose.yml
$paymentDockerComposeContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8003:8003"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/payment_service
      - AWS_REGION=us-east-1
      - RAZORPAY_KEY_ID=your_razorpay_key_id
      - RAZORPAY_KEY_SECRET=your_razorpay_key_secret
      - JWT_SECRET_KEY=your_development_jwt_secret
    depends_on:
      - db
    volumes:
      - .:/app
    networks:
      - app-network

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=payment_service
    ports:
      - "5435:5432"
    networks:
      - app-network

networks:
  app-network:

volumes:
  postgres_data:
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "docker-compose.yml") -Content $paymentDockerComposeContent

# Payment Service requirements.txt
$paymentRequirementsContent = @'
fastapi==0.103.1
uvicorn==0.23.2
sqlalchemy==2.0.20
asyncpg==0.28.0
alembic==1.12.0
pydantic==2.3.0
pydantic-settings==2.0.3
python-jose==3.3.0
python-multipart==0.0.6
razorpay==1.3.0
boto3==1.28.38
pytest==7.4.2
pytest-asyncio==0.21.1
httpx==0.25.0
'@

Set-FileContent -Path (Join-Path $paymentServiceDir "requirements.txt") -Content $paymentRequirementsContent

#############################################
# 5. ADMIN SERVICE FILES
#############################################
$adminServiceDir = Join-Path $baseDir "admin-service"

# Admin Service main.py
$adminMainContent = @'
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import admin, notifications, audit
from app.database import create_tables

app = FastAPI(
    title="Admin and Notification Service API",
    description="API for admin operations, user notifications, and audit logging",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(admin.router, prefix="/admin", tags=["admin"])
app.include_router(notifications.router, prefix="/notifications", tags=["notifications"])
app.include_router(audit.router, prefix="/admin/audit", tags=["audit"])

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8004, reload=True)
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\main.py") -Content $adminMainContent

# Admin Service config.py
$adminConfigContent = @'
import os
from typing import Optional, Dict, Any, List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Admin and Notification Service"
    API_V1_STR: str = "/api/v1"
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/admin_service")
    
    # AWS Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_SECRET_MANAGER_NAME: str = os.getenv("AWS_SECRET_MANAGER_NAME", "admin-service-secrets")
    AWS_SNS_TOPIC_ARN: str = os.getenv("AWS_SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:notifications")
    AWS_SQS_QUEUE_URL: str = os.getenv("AWS_SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/admin-notifications")
    
    # Security settings
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key")
    
    # Email settings
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "your-email@gmail.com")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "your-password")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "noreply@yourdomain.com")
    
    # SMS settings
    SMS_PROVIDER_API_KEY: str = os.getenv("SMS_PROVIDER_API_KEY", "your-sms-api-key")
    SMS_SENDER_ID: str = os.getenv("SMS_SENDER_ID", "RUPAYAPP")
    
    class Config:
        case_sensitive = True

settings = Settings()
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\config.py") -Content $adminConfigContent

# Admin Service database.py
$adminDatabaseContent = @'
import sqlalchemy
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

DATABASE_URL = settings.DATABASE_URL
# Convert PostgreSQL URL to async version
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db() -> AsyncSession:
    """
    Dependency for getting async database session
    """
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

async def create_tables():
    """
    Create all tables defined in the models
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\database.py") -Content $adminDatabaseContent

# Admin Service models/admin.py
$adminModelContent = @'
import uuid
from sqlalchemy import Column, String, DateTime, Boolean, JSON, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class AdminUser(Base):
    __tablename__ = "admin_roles_permissions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    admin_name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False)  # SuperAdmin/Verifier/Auditor
    permissions = Column(JSONB, default={})
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    audit_logs = relationship("AuditLog", back_populates="admin_user")
    
    def __repr__(self):
        return f"<AdminUser {self.admin_name} ({self.role})>"

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_by = Column(UUID(as_uuid=True), ForeignKey("admin_roles_permissions.id"), nullable=True)
    user_id = Column(UUID(as_uuid=True), nullable=True)  # If action relates to a user
    action_type = Column(String(50), nullable=False)  # KYC_Verification/User_Block/Manual_Settlement
    description = Column(Text, nullable=False)
    details = Column(JSONB, default={})
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    admin_user = relationship("AdminUser", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog {self.id} {self.action_type}>"

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=True)  # Null for admin notifications
    admin_id = Column(UUID(as_uuid=True), nullable=True)  # Null for user notifications
    type = Column(String(20), nullable=False)  # Email/SMS/In-App
    title = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(20), default="Pending")  # Pending/Sent/Failed
    sent_at = Column(DateTime, nullable=True)
    metadata = Column(JSONB, default={})
    is_read = Column(Boolean, default=False)  # For in-app notifications
    
    def __repr__(self):
        return f"<Notification {self.id} {self.type}>"

class EmailTemplate(Base):
    __tablename__ = "email_templates"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    template_name = Column(String(100), unique=True, nullable=False)
    subject = Column(String(200), nullable=False)
    body = Column(Text, nullable=False)
    variables = Column(JSONB, default=[])  # List of variables this template accepts
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<EmailTemplate {self.template_name}>"
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\models\admin.py") -Content $adminModelContent

# Admin Service schemas/admin.py
$adminSchemaContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, validator

class AdminUserBase(BaseModel):
    admin_name: str
    email: EmailStr
    role: str
    permissions: Dict[str, Any] = {}

class AdminUserCreate(AdminUserBase):
    password: str

class AdminUserUpdate(BaseModel):
    admin_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    permissions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class AdminUser(AdminUserBase):
    id: uuid.UUID
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    admin_id: str
    role: str
    permissions: Dict[str, Any] = {}

class DashboardMetrics(BaseModel):
    total_users: int
    active_users: int
    total_transactions: int
    transaction_volume: float
    recent_transactions: List[Dict[str, Any]]
    pending_kyc: int
    success_rate: float

class BlockUserRequest(BaseModel):
    user_id: uuid.UUID
    reason: str
    
class AuditLogBase(BaseModel):
    action_type: str
    description: str
    details: Dict[str, Any] = {}
    user_id: Optional[uuid.UUID] = None

class AuditLogCreate(AuditLogBase):
    pass

class AuditLog(AuditLogBase):
    id: uuid.UUID
    action_by: Optional[uuid.UUID] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime
    
    class Config:
        orm_mode = True

class NotificationBase(BaseModel):
    type: str  # Email/SMS/In-App
    title: str
    message: str
    metadata: Dict[str, Any] = {}

class NotificationCreate(NotificationBase):
    user_id: Optional[uuid.UUID] = None
    admin_id: Optional[uuid.UUID] = None
    
    @validator('user_id', 'admin_id')
    def validate_recipient(cls, v, values):
        if 'user_id' not in values and 'admin_id' not in values:
            raise ValueError('Either user_id or admin_id must be provided')
        return v

class Notification(NotificationBase):
    id: uuid.UUID
    status: str
    sent_at: Optional[datetime] = None
    is_read: bool
    
    class Config:
        orm_mode = True

class EmailTemplateBase(BaseModel):
    template_name: str
    subject: str
    body: str
    variables: List[str] = []

class EmailTemplateCreate(EmailTemplateBase):
    pass

class EmailTemplateUpdate(BaseModel):
    subject: Optional[str] = None
    body: Optional[str] = None
    variables: Optional[List[str]] = None

class EmailTemplate(EmailTemplateBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\schemas\admin.py") -Content $adminSchemaContent

# Admin Service routers/admin.py
$adminRouterContent = @'
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.admin import AdminUser
from app.schemas.admin import AdminUserCreate, AdminUser as AdminUserSchema, AdminLogin, Token, DashboardMetrics, BlockUserRequest
from app.services.admin_service import AdminService
from app.utils.auth import get_admin_user, get_current_admin_id

router = APIRouter()

@router.post("/login", response_model=Token)
async def admin_login(
    login_data: AdminLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Admin login endpoint
    """
    admin_service = AdminService(db)
    try:
        return await admin_service.authenticate_admin(login_data.email, login_data.password)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.get("/dashboard", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get admin dashboard metrics
    """
    admin_service = AdminService(db)
    return await admin_service.get_dashboard_metrics()

@router.post("/users", response_model=AdminUserSchema)
async def create_admin_user(
    admin_data: AdminUserCreate,
    current_admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new admin user (super admin only)
    """
    if current_admin.role != "SuperAdmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can create admin users"
        )
    
    admin_service = AdminService(db)
    try:
        return await admin_service.create_admin_user(admin_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/users", response_model=List[AdminUserSchema])
async def list_admin_users(
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all admin users
    """
    admin_service = AdminService(db)
    return await admin_service.list_admin_users()

@router.post("/block-user", status_code=status.HTTP_200_OK)
async def block_user(
    block_data: BlockUserRequest,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Block a user
    """
    admin_service = AdminService(db)
    try:
        await admin_service.block_user(block_data.user_id, admin.id, block_data.reason)
        return {"message": "User blocked successfully"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\routers\admin.py") -Content $adminRouterContent

# Admin Service routers/notifications.py
$notificationsRouterContent = @'
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.admin import AdminUser, Notification
from app.schemas.admin import NotificationCreate, Notification as NotificationSchema
from app.services.notification_service import NotificationService
from app.utils.auth import get_admin_user, get_current_admin_id, get_current_user_id

router = APIRouter()

@router.post("/send", status_code=status.HTTP_202_ACCEPTED)
async def send_notification(
    notification_data: NotificationCreate,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Send notification to user or admin
    """
    notification_service = NotificationService(db)
    try:
        await notification_service.send_notification(notification_data, sender_id=admin.id)
        return {"message": "Notification queued for delivery"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/logs", response_model=List[NotificationSchema])
async def get_notification_logs(
    user_id: Optional[uuid.UUID] = None,
    admin_id: Optional[uuid.UUID] = None,
    type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get notification logs
    """
    notification_service = NotificationService(db)
    return await notification_service.get_notification_logs(
        user_id=user_id,
        admin_id=admin_id,
        type=type,
        status=status,
        limit=limit,
        offset=offset
    )

@router.get("/user", response_model=List[NotificationSchema])
async def get_user_notifications(
    user_id: uuid.UUID = Depends(get_current_user_id),
    is_read: Optional[bool] = None,
    limit: int = Query(10, ge=1, le=50),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    """
    Get notifications for a user
    """
    notification_service = NotificationService(db)
    return await notification_service.get_user_notifications(
        user_id=user_id,
        is_read=is_read,
        limit=limit,
        offset=offset
    )

@router.post("/user/read/{notification_id}", status_code=status.HTTP_200_OK)
async def mark_notification_read(
    notification_id: uuid.UUID,
    user_id: uuid.UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Mark a notification as read
    """
    notification_service = NotificationService(db)
    try:
        await notification_service.mark_notification_read(notification_id, user_id)
        return {"message": "Notification marked as read"}
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\routers\notifications.py") -Content $notificationsRouterContent

# Admin Service routers/audit.py (continued)
$auditRouterContent = @'
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import uuid

from app.database import get_db
from app.models.admin import AdminUser
from app.schemas.admin import AuditLogCreate, AuditLog as AuditLogSchema
from app.services.audit_service import AuditService
from app.utils.auth import get_admin_user, get_current_admin_id

router = APIRouter()

@router.post("/log", response_model=AuditLogSchema)
async def create_audit_log(
    audit_data: AuditLogCreate,
    request: Request,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Manually create an audit log entry
    """
    audit_service = AuditService(db)
    try:
        return await audit_service.create_audit_log(
            action_type=audit_data.action_type,
            description=audit_data.description,
            admin_id=admin.id,
            user_id=audit_data.user_id,
            details=audit_data.details,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/logs", response_model=List[AuditLogSchema])
async def get_audit_logs(
    action_type: Optional[str] = None,
    admin_id: Optional[uuid.UUID] = None,
    user_id: Optional[uuid.UUID] = None,
    start_date: Optional[str] = None,  # ISO format
    end_date: Optional[str] = None,    # ISO format
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get audit logs with optional filters
    """
    audit_service = AuditService(db)
    return await audit_service.get_audit_logs(
        action_type=action_type,
        admin_id=admin_id,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset
    )

@router.get("/logs/{log_id}", response_model=AuditLogSchema)
async def get_audit_log(
    log_id: uuid.UUID,
    admin: AdminUser = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific audit log by ID
    """
    audit_service = AuditService(db)
    try:
        return await audit_service.get_audit_log_by_id(log_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\routers\audit.py") -Content $auditRouterContent

# Admin Service services/admin_service.py
$adminServiceContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status
from jose import jwt

from app.models.admin import AdminUser
from app.schemas.admin import AdminUserCreate, Token, DashboardMetrics
from app.utils.security import get_password_hash, verify_password
from app.services.audit_service import AuditService
from app.config import settings

class AdminService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit_service = AuditService(db)
    
    async def authenticate_admin(self, email: str, password: str) -> Token:
        """
        Authenticate admin user and return JWT token
        """
        query = select(AdminUser).where(AdminUser.email == email)
        result = await self.db.execute(query)
        admin = result.scalars().first()
        
        if not admin or not verify_password(password, admin.password_hash):
            raise ValueError("Invalid credentials")
        
        if not admin.is_active:
            raise ValueError("Admin account is inactive")
        
        # Update last login
        admin.last_login = datetime.utcnow()
        await self.db.commit()
        
        # Create access token
        token_data = {
            "sub": str(admin.id),
            "email": admin.email,
            "role": admin.role,
            "permissions": admin.permissions,
            "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        }
        access_token = jwt.encode(token_data, settings.JWT_SECRET_KEY, algorithm="HS256")
        
        # Log login
        await self.audit_service.create_audit_log(
            action_type="Admin_Login",
            description=f"Admin login: {admin.email}",
            admin_id=admin.id,
            details={"email": admin.email}
        )
        
        return Token(access_token=access_token, token_type="bearer")
    
    async def create_admin_user(self, admin_data: AdminUserCreate) -> AdminUser:
        """
        Create a new admin user
        """
        # Check if email already exists
        query = select(AdminUser).where(AdminUser.email == admin_data.email)
        result = await self.db.execute(query)
        if result.scalars().first():
            raise ValueError(f"Admin with email {admin_data.email} already exists")
        
        # Create admin user
        hashed_password = get_password_hash(admin_data.password)
        admin = AdminUser(
            admin_name=admin_data.admin_name,
            email=admin_data.email,
            password_hash=hashed_password,
            role=admin_data.role,
            permissions=admin_data.permissions
        )
        
        self.db.add(admin)
        await self.db.commit()
        await self.db.refresh(admin)
        
        # Log creation
        await self.audit_service.create_audit_log(
            action_type="Admin_Created",
            description=f"Admin user created: {admin.email} with role {admin.role}",
            admin_id=admin.id,
            details={"email": admin.email, "role": admin.role}
        )
        
        return admin
    
    async def list_admin_users(self) -> List[AdminUser]:
        """
        List all admin users
        """
        query = select(AdminUser)
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_admin_by_id(self, admin_id: uuid.UUID) -> Optional[AdminUser]:
        """
        Get admin by ID
        """
        query = select(AdminUser).where(AdminUser.id == admin_id)
        result = await self.db.execute(query)
        return result.scalars().first()
    
    async def block_user(self, user_id: uuid.UUID, admin_id: uuid.UUID, reason: str) -> None:
        """
        Block a user (by setting is_active to False in User service)
        This is a placeholder implementation - in reality, this would call User service API
        """
        # In a real implementation, make an API call to User service to block the user
        # For this demo, we'll just log the action
        
        await self.audit_service.create_audit_log(
            action_type="User_Blocked",
            description=f"User {user_id} blocked",
            admin_id=admin_id,
            user_id=user_id,
            details={"reason": reason}
        )
        
        # Also send a notification to the user
        # This would be implemented in a real system
        
    async def get_dashboard_metrics(self) -> DashboardMetrics:
        """
        Get metrics for admin dashboard
        This is a placeholder implementation with mock data
        In a real application, this would query various services
        """
        # Mock data for demonstration
        return DashboardMetrics(
            total_users=1250,
            active_users=980,
            total_transactions=3456,
            transaction_volume=345670.50,
            recent_transactions=[
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(uuid.uuid4()),
                    "amount": 1500.00,
                    "status": "Success",
                    "created_at": datetime.utcnow().isoformat()
                },
                {
                    "id": str(uuid.uuid4()),
                    "user_id": str(uuid.uuid4()),
                    "amount": 2500.00,
                    "status": "Processing",
                    "created_at": datetime.utcnow().isoformat()
                }
            ],
            pending_kyc=45,
            success_rate=92.5
        )
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\services\admin_service.py") -Content $adminServiceContent

# Admin Service services/notification_service.py
$notificationServiceContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, update, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
import boto3
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.models.admin import Notification, EmailTemplate
from app.schemas.admin import NotificationCreate
from app.config import settings

class NotificationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        
        # Initialize AWS SNS client
        self.sns = boto3.client(
            'sns',
            region_name=settings.AWS_REGION
        )
    
    async def send_notification(self, notification_data: NotificationCreate, sender_id: uuid.UUID) -> Notification:
        """
        Send notification to user or admin
        """
        # Create notification record
        notification = Notification(
            user_id=notification_data.user_id,
            admin_id=notification_data.admin_id,
            type=notification_data.type,
            title=notification_data.title,
            message=notification_data.message,
            metadata=notification_data.metadata,
            status="Pending"
        )
        
        self.db.add(notification)
        await self.db.commit()
        await self.db.refresh(notification)
        
        # Process notification based on type
        try:
            if notification.type == "Email":
                await self._send_email_notification(notification)
            elif notification.type == "SMS":
                await self._send_sms_notification(notification)
            elif notification.type == "In-App":
                # In-app notifications don't need to be sent externally
                notification.status = "Sent"
            else:
                raise ValueError(f"Unsupported notification type: {notification.type}")
            
            # Update notification status
            if notification.status == "Pending":
                notification.status = "Sent"
                notification.sent_at = datetime.utcnow()
            
        except Exception as e:
            notification.status = "Failed"
            notification.metadata["error"] = str(e)
        
        await self.db.commit()
        await self.db.refresh(notification)
        return notification
    
    async def _send_email_notification(self, notification: Notification) -> None:
        """
        Send email notification
        """
        if not notification.user_id and not notification.admin_id:
            raise ValueError("No recipient specified for email notification")
        
        # In a real implementation, you'd get user/admin email from respective services
        # For this demo, we'll assume the email is stored in metadata
        recipient_email = notification.metadata.get("email", "recipient@example.com")
        
        # Check if we need to use a template
        template_name = notification.metadata.get("template_name")
        if template_name:
            # Get template
            template_query = select(EmailTemplate).where(EmailTemplate.template_name == template_name)
            template_result = await self.db.execute(template_query)
            template = template_result.scalars().first()
            
            if not template:
                raise ValueError(f"Email template not found: {template_name}")
            
            # Replace variables in template
            subject = template.subject
            body = template.body
            
            # Replace variables
            template_vars = notification.metadata.get("template_vars", {})
            for var_name, var_value in template_vars.items():
                placeholder = f"{{{{{var_name}}}}}"
                body = body.replace(placeholder, str(var_value))
                subject = subject.replace(placeholder, str(var_value))
        else:
            # Use direct message
            subject = notification.title
            body = notification.message
        
        # In a real implementation, send via SMTP or SES
        # For this demo, just log
        print(f"Email to {recipient_email}: {subject} - {body}")
        
        # In production, this would be uncommented:
        """
        try:
            msg = MIMEMultipart()
            msg['From'] = settings.SMTP_FROM_EMAIL
            msg['To'] = recipient_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            server = smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT)
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            raise
        """
    
    async def _send_sms_notification(self, notification: Notification) -> None:
        """
        Send SMS notification
        """
        if not notification.user_id and not notification.admin_id:
            raise ValueError("No recipient specified for SMS notification")
        
        # In a real implementation, you'd get user/admin phone from respective services
        # For this demo, we'll assume the phone is stored in metadata
        recipient_phone = notification.metadata.get("phone", "+1234567890")
        
        # In a real implementation, send via SNS or third-party SMS provider
        # For this demo, just log
        print(f"SMS to {recipient_phone}: {notification.message}")
        
        # In production, this would be uncommented:
        """
        try:
            response = self.sns.publish(
                PhoneNumber=recipient_phone,
                Message=notification.message,
                MessageAttributes={
                    'AWS.SNS.SMS.SenderID': {
                        'DataType': 'String',
                        'StringValue': settings.SMS_SENDER_ID
                    }
                }
            )
            print(f"SMS sent: {response}")
        except Exception as e:
            print(f"Error sending SMS: {str(e)}")
            raise
        """
    
    async def get_notification_logs(
        self,
        user_id: Optional[uuid.UUID] = None,
        admin_id: Optional[uuid.UUID] = None,
        type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> List[Notification]:
        """
        Get notification logs with optional filters
        """
        query = select(Notification)
        
        # Apply filters
        filters = []
        if user_id:
            filters.append(Notification.user_id == user_id)
        if admin_id:
            filters.append(Notification.admin_id == admin_id)
        if type:
            filters.append(Notification.type == type)
        if status:
            filters.append(Notification.status == status)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(desc(Notification.sent_at if Notification.sent_at else Notification.id))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_user_notifications(
        self,
        user_id: uuid.UUID,
        is_read: Optional[bool] = None,
        limit: int = 10,
        offset: int = 0
    ) -> List[Notification]:
        """
        Get notifications for a user
        """
        query = select(Notification).where(
            Notification.user_id == user_id,
            Notification.type == "In-App"
        )
        
        if is_read is not None:
            query = query.where(Notification.is_read == is_read)
        
        query = query.order_by(desc(Notification.sent_at if Notification.sent_at else Notification.id))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def mark_notification_read(self, notification_id: uuid.UUID, user_id: uuid.UUID) -> None:
        """
        Mark a notification as read
        """
        query = select(Notification).where(
            Notification.id == notification_id,
            Notification.user_id == user_id
        )
        
        result = await self.db.execute(query)
        notification = result.scalars().first()
        
        if not notification:
            raise ValueError("Notification not found or does not belong to user")
        
        notification.is_read = True
        await self.db.commit()
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\services\notification_service.py") -Content $notificationServiceContent

# Admin Service services/audit_service.py
$auditServiceContent = @'
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.admin import AuditLog

class AuditService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_audit_log(
        self,
        action_type: str,
        description: str,
        admin_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        details: Dict[str, Any] = {},
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditLog:
        """
        Create an audit log entry
        """
        audit_log = AuditLog(
            action_by=admin_id,
            user_id=user_id,
            action_type=action_type,
            description=description,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.db.add(audit_log)
        await self.db.commit()
        await self.db.refresh(audit_log)
        return audit_log
    
    async def get_audit_logs(
        self,
        action_type: Optional[str] = None,
        admin_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[AuditLog]:
        """
        Get audit logs with optional filters
        """
        query = select(AuditLog)
        
        # Apply filters
        filters = []
        if action_type:
            filters.append(AuditLog.action_type == action_type)
        if admin_id:
            filters.append(AuditLog.action_by == admin_id)
        if user_id:
            filters.append(AuditLog.user_id == user_id)
        
        # Date filters
        if start_date:
            start_datetime = datetime.fromisoformat(start_date)
            filters.append(AuditLog.created_at >= start_datetime)
        if end_date:
            end_datetime = datetime.fromisoformat(end_date)
            filters.append(AuditLog.created_at <= end_datetime)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(desc(AuditLog.created_at))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_audit_log_by_id(self, log_id: uuid.UUID) -> AuditLog:
        """
        Get a specific audit log by ID
        """
        query = select(AuditLog).where(AuditLog.id == log_id)
        result = await self.db.execute(query)
        audit_log = result.scalars().first()
        
        if not audit_log:
            raise ValueError(f"Audit log not found with ID: {log_id}")
        
        return audit_log
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\services\audit_service.py") -Content $auditServiceContent

# Admin Service utils/auth.py
$adminAuthContent = @'
import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.services.admin_service import AdminService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="admin/login")

async def get_current_admin_id(
    token: str = Depends(oauth2_scheme)
) -> uuid.UUID:
    """
    Get current admin ID from JWT token
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        admin_id: str = payload.get("sub")
        if admin_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    return uuid.UUID(admin_id)

async def get_admin_user(
    admin_id: uuid.UUID = Depends(get_current_admin_id),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current admin user from database
    """
    admin_service = AdminService(db)
    admin = await admin_service.get_admin_by_id(admin_id)
    
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return admin

async def get_current_user_id(
    token: str = Depends(oauth2_scheme)
) -> uuid.UUID:
    """
    Get current user ID from JWT token
    This is for user authentication - in a real system, this would verify with User Service
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    return uuid.UUID(user_id)
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\utils\auth.py") -Content $adminAuthContent

# Admin Service utils/security.py
$adminSecurityContent = @'
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from typing import Dict, Any, Optional
from app.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hashed version"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate password hash"""
    return pwd_context.hash(password)

def create_jwt_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm="HS256")
    
    return encoded_jwt
'@

Set-FileContent -Path (Join-Path $adminServiceDir "app\utils\security.py") -Content $adminSecurityContent

# Admin Service Dockerfile
$adminDockerfileContent = @'
FROM python:3.11-slim

WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8004"]
'@

Set-FileContent -Path (Join-Path $adminServiceDir "Dockerfile") -Content $adminDockerfileContent

# Admin Service docker-compose.yml
$adminDockerComposeContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8004:8004"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/admin_service
      - AWS_REGION=us-east-1
      - JWT_SECRET_KEY=your_development_jwt_secret
      - SMTP_USERNAME=your-email@gmail.com
      - SMTP_PASSWORD=your-email-password
    depends_on:
      - db
    volumes:
      - .:/app
    networks:
      - app-network

  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=admin_service
    ports:
      - "5436:5432"
    networks:
      - app-network

networks:
  app-network:

volumes:
  postgres_data:
'@

Set-FileContent -Path (Join-Path $adminServiceDir "docker-compose.yml") -Content $adminDockerComposeContent

# Admin Service requirements.txt
$adminRequirementsContent = @'
fastapi==0.103.1
uvicorn==0.23.2
sqlalchemy==2.0.20
asyncpg==0.28.0
alembic==1.12.0
pydantic==2.3.0
pydantic-settings==2.0.3
passlib==1.7.4
bcrypt==4.0.1
python-jose==3.3.0
python-multipart==0.0.6
email-validator==2.0.0.post2
boto3==1.28.38
pytest==7.4.2
pytest-asyncio==0.21.1
httpx==0.25.0
'@

Set-FileContent -Path (Join-Path $adminServiceDir "requirements.txt") -Content $adminRequirementsContent


#############################################
# CREATE INFRASTRUCTURE AS CODE REPOSITORY
#############################################
$infraDir = Join-Path $baseDir "infrastructure"

# Create infrastructure directory if it doesn't exist
if (!(Test-Path $infraDir)) {
    New-Item -ItemType Directory -Path $infraDir
}

# Create Terraform files
$mainTfContent = @'
# AWS Provider Configuration
provider "aws" {
  region = var.aws_region
}

# VPC and Networking
module "vpc" {
  source = "./modules/vpc"
  
  app_name        = var.app_name
  environment     = var.environment
  vpc_cidr        = var.vpc_cidr
  azs             = var.azs
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets
}

# RDS Aurora PostgreSQL
module "database" {
  source = "./modules/database"
  
  app_name          = var.app_name
  environment       = var.environment
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.database_subnet_ids
  instance_class    = var.db_instance_class
  master_username   = var.db_master_username
  master_password   = var.db_master_password
  database_name     = var.db_name
  engine_version    = var.db_engine_version
}

# Redis for OTP and caching
module "redis" {
  source = "./modules/redis"
  
  app_name      = var.app_name
  environment   = var.environment
  vpc_id        = module.vpc.vpc_id
  subnet_ids    = module.vpc.private_subnet_ids
  node_type     = var.redis_node_type
  engine_version = var.redis_engine_version
}

# ECS Cluster
module "ecs" {
  source = "./modules/ecs"
  
  app_name     = var.app_name
  environment  = var.environment
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnet_ids
}

# ECS Services - User Service
module "user_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-user"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8000
  container_image   = "${var.ecr_repository_url}/user-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/user_service" },
    { name = "REDIS_HOST", value = module.redis.endpoint },
    { name = "AWS_REGION", value = var.aws_region }
  ]
}

# ECS Services - OTP Service
module "otp_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-otp"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8001
  container_image   = "${var.ecr_repository_url}/otp-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/otp_service" },
    { name = "REDIS_HOST", value = module.redis.endpoint },
    { name = "AWS_REGION", value = var.aws_region }
  ]
}

# ECS Services - KYC Service
module "kyc_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-kyc"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8002
  container_image   = "${var.ecr_repository_url}/kyc-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/kyc_service" },
    { name = "AWS_S3_BUCKET", value = aws_s3_bucket.kyc_documents.bucket },
    { name = "AWS_REGION", value = var.aws_region }
  ]
}

# ECS Services - Payment Service
module "payment_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-payment"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8003
  container_image   = "${var.ecr_repository_url}/payment-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/payment_service" },
    { name = "AWS_SQS_QUEUE_URL", value = aws_sqs_queue.settlement_queue.url },
    { name = "AWS_EVENTBRIDGE_BUS", value = aws_cloudwatch_event_bus.payment_events.name },
    { name = "AWS_REGION", value = var.aws_region }
  ]
}

# ECS Services - Admin Service
module "admin_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-admin"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8004
  container_image   = "${var.ecr_repository_url}/admin-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/admin_service" },
    { name = "AWS_SNS_TOPIC_ARN", value = aws_sns_topic.notifications.arn },
    { name = "AWS_SQS_QUEUE_URL", value = aws_sqs_queue.admin_notifications.url },
    { name = "AWS_REGION", value = var.aws_region }
  ]
}

# API Gateway
module "api_gateway" {
  source = "./modules/api-gateway"
  
  app_name      = var.app_name
  environment   = var.environment
  vpc_id        = module.vpc.vpc_id
  
  # Service integrations
  integrations = [
    {
      name       = "user-service"
      target_url = module.user_service.service_url
      base_path  = "users"
    },
    {
      name       = "otp-service"
      target_url = module.otp_service.service_url
      base_path  = "otp"
    },
    {
      name       = "kyc-service"
      target_url = module.kyc_service.service_url
      base_path  = "kyc"
    },
    {
      name       = "payment-service"
      target_url = module.payment_service.service_url
      base_path  = "payments"
    },
    {
      name       = "settlement-service"
      target_url = module.payment_service.service_url
      base_path  = "settlements"
    },
    {
      name       = "admin-service"
      target_url = module.admin_service.service_url
      base_path  = "admin"
    },
    {
      name       = "notifications-service"
      target_url = module.admin_service.service_url
      base_path  = "notifications"
    }
  ]
}

# S3 Bucket for KYC Documents
resource "aws_s3_bucket" "kyc_documents" {
  bucket = "${var.app_name}-kyc-documents-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-kyc-documents"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "kyc_encryption" {
  bucket = aws_s3_bucket.kyc_documents.bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# SQS Queues
resource "aws_sqs_queue" "settlement_queue" {
  name                      = "${var.app_name}-settlement-queue-${var.environment}"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10
  
  tags = {
    Name        = "${var.app_name}-settlement-queue"
    Environment = var.environment
  }
}

resource "aws_sqs_queue" "admin_notifications" {
  name                      = "${var.app_name}-admin-notifications-${var.environment}"
  delay_seconds             = 0
  max_message_size          = 262144
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10
  
  tags = {
    Name        = "${var.app_name}-admin-notifications"
    Environment = var.environment
  }
}

# SNS Topic for Notifications
resource "aws_sns_topic" "notifications" {
  name = "${var.app_name}-notifications-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-notifications"
    Environment = var.environment
  }
}

# EventBridge Event Bus
resource "aws_cloudwatch_event_bus" "payment_events" {
  name = "${var.app_name}-payment-events-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-payment-events"
    Environment = var.environment
  }
}

# Secret Manager for Service Credentials
resource "aws_secretsmanager_secret" "service_credentials" {
  name = "${var.app_name}-service-credentials-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-service-credentials"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "service_credentials" {
  secret_id = aws_secretsmanager_secret.service_credentials.id
  secret_string = jsonencode({
    database = {
      username = var.db_master_username
      password = var.db_master_password
      host     = module.database.endpoint
    }
    razorpay = {
      key_id     = var.razorpay_key_id
      key_secret = var.razorpay_key_secret
    }
    jwt = {
      secret_key = var.jwt_secret_key
    }
    smtp = {
      username = var.smtp_username
      password = var.smtp_password
    }
  })
}
'@

Set-FileContent -Path (Join-Path $infraDir "main.tf") -Content $mainTfContent

$variablesTfContent = @'
variable "app_name" {
  description = "Name of the application"
  default     = "rupay-upi"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  default     = "ap-south-1"
}

# VPC Variables
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "Availability zones to use"
  type        = list(string)
  default     = ["ap-south-1a", "ap-south-1b", "ap-south-1c"]
}

variable "private_subnets" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnets" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

# Database Variables
variable "db_instance_class" {
  description = "Instance class for RDS Aurora"
  default     = "db.t3.small"
}

variable "db_master_username" {
  description = "Master username for RDS"
  default     = "postgres"
}

variable "db_master_password" {
  description = "Master password for RDS"
  sensitive   = true
}

variable "db_name" {
  description = "Name of the database"
  default     = "rupayupi"
}

variable "db_engine_version" {
  description = "Aurora PostgreSQL engine version"
  default     = "13.7"
}

# Redis Variables
variable "redis_node_type" {
  description = "Node type for Redis"
  default     = "cache.t3.small"
}

variable "redis_engine_version" {
  description = "Redis engine version"
  default     = "6.x"
}

# ECS Service Variables
variable "service_desired_count" {
  description = "Desired count of containers for each service"
  default     = 2
}

variable "service_cpu" {
  description = "CPU units for each container"
  default     = 256
}

variable "service_memory" {
  description = "Memory for each container in MB"
  default     = 512
}

variable "ecr_repository_url" {
  description = "URL of the ECR repository without the image name and tag"
}

# Third-party Service Credentials
variable "razorpay_key_id" {
  description = "Razorpay Key ID"
  sensitive   = true
}

variable "razorpay_key_secret" {
  description = "Razorpay Key Secret"
  sensitive   = true
}

variable "jwt_secret_key" {
  description = "Secret key for JWT token generation"
  sensitive   = true
}

variable "smtp_username" {
  description = "SMTP username for sending emails"
  sensitive   = true
}

variable "smtp_password" {
  description = "SMTP password for sending emails"
  sensitive   = true
}
'@

Set-FileContent -Path (Join-Path $infraDir "variables.tf") -Content $variablesTfContent

$outputsTfContent = @'
output "api_gateway_url" {
  description = "URL of the API Gateway"
  value       = module.api_gateway.api_url
}

output "database_endpoint" {
  description = "Endpoint of the RDS Aurora cluster"
  value       = module.database.endpoint
}

output "redis_endpoint" {
  description = "Endpoint of the Redis cluster"
  value       = module.redis.endpoint
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.ecs.cluster_name
}

output "service_urls" {
  description = "URLs of the microservices"
  value = {
    user_service      = module.user_service.service_url
    otp_service       = module.otp_service.service_url
    kyc_service       = module.kyc_service.service_url
    payment_service   = module.payment_service.service_url
    admin_service     = module.admin_service.service_url
  }
}

output "kyc_bucket_name" {
  description = "Name of the S3 bucket for KYC documents"
  value       = aws_s3_bucket.kyc_documents.bucket
}

output "sqs_queues" {
  description = "SQS queue URLs"
  value = {
    settlement_queue     = aws_sqs_queue.settlement_queue.url
    admin_notifications  = aws_sqs_queue.admin_notifications.url
  }
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = aws_sns_topic.notifications.arn
}

output "event_bus_name" {
  description = "Name of the EventBridge event bus"
  value       = aws_cloudwatch_event_bus.payment_events.name
}

output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret"
  value       = aws_secretsmanager_secret.service_credentials.arn
}
'@

Set-FileContent -Path (Join-Path $infraDir "outputs.tf") -Content $outputsTfContent

# Create infrastructure README
$infraReadmeContent = @'
# Infrastructure as Code for RuPay UPI Application

## Overview
This directory contains Terraform configuration for deploying the RuPay UPI application infrastructure on AWS.

## Architecture
- VPC with public and private subnets across multiple AZs
- Aurora PostgreSQL for database
- ElastiCache Redis for caching and OTP storage
- ECS Fargate for containerized microservices
- API Gateway for frontend API access
- S3 for document storage
- SQS for asynchronous messaging
- SNS for notifications
- EventBridge for event-driven architecture
- Secrets Manager for secure credential storage

## Services Deployed
- User Service
- OTP Service
- KYC Service
- Payment & Settlement Service
- Admin & Notification Service

## Deployment Instructions
1. Initialize Terraform:
2. Create a terraform.tfvars file with your configuration:
3. Plan the deployment:
4. Apply the changes:


## Structure
- `main.tf`: Main configuration file
- `variables.tf`: Input variables
- `outputs.tf`: Output values
- `modules/`: Reusable infrastructure modules
  - `vpc/`: VPC and networking
  - `database/`: Aurora PostgreSQL
  - `redis/`: ElastiCache Redis
  - `ecs/`: ECS Cluster
  - `ecs-service/`: ECS Service
  - `api-gateway/`: API Gateway

## Notes
- The infrastructure is designed for a multi-AZ deployment for high availability
- Secrets are stored securely in AWS Secrets Manager
- All resources are tagged for easy identification and cost allocation
'@

Set-FileContent -Path (Join-Path $infraDir "README.md") -Content $infraReadmeContent

# Create a root README file
$rootReadmeContent = @'
# RuPay to UPI Payment Application

## Project Overview
This application allows users to make UPI payments using RuPay credit cards with security compliance, full transaction auditing, and a mobile-first experience.

## Microservices Architecture
The application is built using a microservices architecture with the following components:

### 1. User Service
Manages user accounts, authentication, and profile data.

### 2. OTP Service
Handles OTP generation, verification for secure authentication.

### 3. KYC Service
Manages KYC document uploads, verification workflow.

### 4. Payment + Settlement Service
Processes credit card to UPI payments and settlements.

### 5. Admin + Notification Service
Provides admin dashboard, notification management, and audit logging.

## Key Workflows

### User Onboarding
1. User registers via Web or Mobile app
2. User gets OTP (via OTP Service & Redis)
3. User completes KYC (via KYC Service)

### Transaction Flow
1. User initiates payment to a UPI ID via frontend
2. API Gateway routes request to Payment Service
3. Payment Service interacts with Razorpay and logs event to EventBridge
4. Settlement Service handles UPI payout
5. Notifications sent via Notification Service

### Admin Operations
1. Admin logs in through Admin Panel
2. Views dashboards, manages users, handles disputes
3. Operates via secure Admin Service APIs

## Deployment Architecture
- All microservices deployed in AWS ECS Fargate
- API Gateway exposing public endpoints
- Internal services using VPC Link + Internal ALB
- Aurora PostgreSQL for data storage
- Redis for OTP, SQS for async jobs, EventBridge for events
- S3 for document storage
- Secrets Manager for credentials

## Development Setup
Each microservice has its own Docker configuration for local development:


## API Documentation
Each service has its own API documentation available at `/docs` when running locally.

## Infrastructure
Infrastructure is managed using Terraform in the `infrastructure/` directory.
'@

Set-FileContent -Path (Join-Path $baseDir "README.md") -Content $rootReadmeContent

Write-Host "All files have been created successfully!"
Write-Host "The microservices structure is now complete with all necessary files."
Write-Host "You can find the code in: $baseDir"