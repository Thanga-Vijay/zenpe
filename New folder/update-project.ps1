# update-project.ps1 - FIXED VERSION
# PowerShell script to update the project files to remove Redis and implement PostgreSQL and in-memory caching

Write-Host "Starting project updates to remove Redis dependencies..." -ForegroundColor Green

# Function to ensure directory exists
function EnsureDirectoryExists {
    param (
        [string]$Path
    )
    
    if (-not [string]::IsNullOrEmpty($Path) -and -not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "Created directory: $Path" -ForegroundColor Yellow
    }
}

# Function to write file content
function WriteFile {
    param (
        [string]$Path,
        [string]$Content
    )
    
    if ([string]::IsNullOrEmpty($Path)) {
        Write-Host "Error: Empty file path provided to WriteFile function" -ForegroundColor Red
        return
    }
    
    # Ensure the directory exists
    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrEmpty($directory)) {
        EnsureDirectoryExists -Path $directory
    }
    
    # Write the file
    $Content | Out-File -FilePath $Path -Encoding utf8 -Force
    Write-Host "Updated file: $Path" -ForegroundColor Cyan
}

# 1. Update OTP Service files
Write-Host "Updating OTP Service files..." -ForegroundColor Yellow

# OTP Service - Update OTP Service class
$otpServicePath = "otp-service/app/services/otp_service.py"
$otpServiceContent = @'
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
'@

WriteFile -Path $otpServicePath -Content $otpServiceContent

# OTP Service - Update Config
$otpConfigPath = "otp-service/app/config.py"
$otpConfigContent = @'
import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "OTP Service"
    API_V1_STR: str = "/api/v1"
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/otp_service")
    
    # JWT settings
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # MSG91 settings (add these)
    MSG91_AUTH_KEY: str = os.getenv("MSG91_AUTH_KEY", "")
    MSG91_TEMPLATE_ID: str = os.getenv("MSG91_TEMPLATE_ID", "")
    
    # AWS Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    
    class Config:
        case_sensitive = True

settings = Settings()
'@

WriteFile -Path $otpConfigPath -Content $otpConfigContent

# OTP Service - Update Auth Utils
$otpAuthPath = "otp-service/app/utils/auth.py"
$otpAuthContent = @'
from passlib.context import CryptContext

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """Create password hash using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash using bcrypt"""
    return pwd_context.verify(plain_password, hashed_password)
'@

WriteFile -Path $otpAuthPath -Content $otpAuthContent

# OTP Service - Update Docker Compose
$otpDockerPath = "otp-service/docker-compose.yml"
$otpDockerContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8001:8001"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/otp_service
      - MSG91_AUTH_KEY=your_msg91_auth_key
      - MSG91_TEMPLATE_ID=your_msg91_template_id
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
      - POSTGRES_DB=otp_service
    ports:
      - "5433:5432"
    networks:
      - app-network

networks:
  app-network:

volumes:
  postgres_data:
'@

WriteFile -Path $otpDockerPath -Content $otpDockerContent

# 2. Update User Service files
Write-Host "Updating User Service files..." -ForegroundColor Yellow

# User Service - Update User Model to include BlacklistedToken
$userModelPath = "user-service/app/models/user.py"
$userModelContent = @'
import uuid
import hashlib
from sqlalchemy import Column, String, DateTime, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from datetime import datetime
from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    phone_number = Column(String(20), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=True)
    password_hash = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Add relationship
    blacklisted_tokens = relationship("BlacklistedToken", back_populates="user")
    
    def __repr__(self):
        return f"<User {self.name}>"

class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash = Column(String(64), nullable=False, index=True)  # Store token hash, not actual token
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    
    # Relationship
    user = relationship("User", back_populates="blacklisted_tokens")
    
    def __repr__(self):
        return f"<BlacklistedToken {self.id}>"
'@

WriteFile -Path $userModelPath -Content $userModelContent

# User Service - Create Auth Service
$authServicePath = "user-service/app/services/auth_service.py"
$authServiceContent = @'
import uuid
import hashlib
import jwt
from datetime import datetime, timedelta
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import BlacklistedToken
from app.config import settings

class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_access_token(self, user_id: uuid.UUID, data: dict = None) -> str:
        """Create JWT access token for user"""
        payload = {
            "sub": str(user_id),
            "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        }
        
        if data:
            payload.update(data)
            
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")
    
    async def blacklist_token(self, token: str, user_id: uuid.UUID) -> None:
        """Add token to blacklist when user logs out"""
        # Get token expiration time from payload
        try:
            payload = jwt.decode(
                token, 
                settings.JWT_SECRET_KEY, 
                algorithms=["HS256"],
                options={"verify_signature": False}  # Don't validate signature here
            )
            
            exp_timestamp = payload.get("exp", 0)
            exp_datetime = datetime.fromtimestamp(exp_timestamp)
            
            # Hash the token for security
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            # Store in database
            blacklisted_token = BlacklistedToken(
                token_hash=token_hash,
                user_id=user_id,
                expires_at=exp_datetime
            )
            
            self.db.add(blacklisted_token)
            await self.db.commit()
        except Exception as e:
            print(f"Error blacklisting token: {str(e)}")
            raise
    
    async def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        # Hash the token
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Check database
        query = select(BlacklistedToken).where(
            BlacklistedToken.token_hash == token_hash,
            BlacklistedToken.expires_at > datetime.utcnow()
        )
        
        result = await self.db.execute(query)
        return result.scalars().first() is not None
    
    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from blacklist"""
        query = delete(BlacklistedToken).where(
            BlacklistedToken.expires_at < datetime.utcnow()
        )
        
        result = await self.db.execute(query)
        await self.db.commit()
        return result.rowcount
'@

WriteFile -Path $authServicePath -Content $authServiceContent

# User Service - Update Auth Utils
$userAuthPath = "user-service/app/utils/auth.py"
$userAuthContent = @'
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError
import uuid
from app.models.user import User
from app.services.user_service import UserService
from app.services.auth_service import AuthService
from app.database import get_db
from app.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Verify token is not blacklisted
        auth_service = AuthService(db)
        if await auth_service.is_token_blacklisted(token):
            raise credentials_exception
        
        # Decode token
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
            
        # Get user from database
        user_service = UserService(db)
        user = await user_service.get_user_by_id(uuid.UUID(user_id))
        if user is None:
            raise credentials_exception
            
        return user
    except JWTError:
        raise credentials_exception

async def get_current_user_id(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> uuid.UUID:
    """Get current user ID from JWT token"""
    user = await get_current_user(token, db)
    return user.id
'@

WriteFile -Path $userAuthPath -Content $userAuthContent

# User Service - Add Logout Route
$userRouterPath = "user-service/app/routers/users.py"
$logoutRouteContent = @'
@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    user: User = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """
    Logout user by blacklisting current token
    """
    auth_service = AuthService(db)
    await auth_service.blacklist_token(token, user.id)
    return {"detail": "Successfully logged out"}
'@

# Check if users.py exists and append logout route
if (Test-Path -Path $userRouterPath) {
    $content = Get-Content -Path $userRouterPath -Raw
    if (-not $content.Contains("logout")) {
        $content += "`n" + $logoutRouteContent
        Set-Content -Path $userRouterPath -Value $content
        Write-Host "Added logout route to $userRouterPath" -ForegroundColor Cyan
    }
}

# User Service - Update Main.py for Token Cleanup
$userMainPath = "user-service/app/main.py"
$tokenCleanupContent = @'
import asyncio
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.routers import users
from app.database import create_tables, engine
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.auth_service import AuthService

app = FastAPI(
    title="User Service API",
    description="API for user management and authentication",
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
app.include_router(users.router, prefix="/users", tags=["users"])

# Add a background task to clean up expired tokens
@app.on_event("startup")
async def startup():
    await create_tables()
    
    # Schedule token cleanup task
    async def cleanup_tokens_task():
        while True:
            db = AsyncSession(engine)
            try:
                auth_service = AuthService(db)
                count = await auth_service.cleanup_expired_tokens()
                print(f"Cleaned up {count} expired tokens")
            except Exception as e:
                print(f"Error in token cleanup: {str(e)}")
            finally:
                await db.close()
            
            # Run once a day
            await asyncio.sleep(24 * 60 * 60)
    
    # Start background task
    asyncio.create_task(cleanup_tokens_task())

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
'@

# Update main.py completely instead of trying to replace parts
WriteFile -Path $userMainPath -Content $tokenCleanupContent
Write-Host "Updated main.py in $userMainPath" -ForegroundColor Cyan

# User Service - Update Docker Compose
$userDockerPath = "user-service/docker-compose.yml"
$userDockerContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/user_service
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
      - POSTGRES_DB=user_service
    ports:
      - "5432:5432"
    networks:
      - app-network

networks:
  app-network:

volumes:
  postgres_data:
'@

WriteFile -Path $userDockerPath -Content $userDockerContent

# 3. Create Application-Level Caching for Admin Service
Write-Host "Creating application-level caching for Admin Service..." -ForegroundColor Yellow

# Admin Service - Create Caching Utility
$cachingUtilPath = "admin-service/app/utils/caching.py"
$cachingUtilContent = @'
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Callable, TypeVar, Awaitable
import functools
import hashlib
import json

T = TypeVar('T')

class CacheItem:
    def __init__(self, value: Any, expires_at: datetime):
        self.value = value
        self.expires_at = expires_at
        
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

# In-memory cache store
_cache: Dict[str, CacheItem] = {}

def generate_cache_key(prefix: str, *args, **kwargs) -> str:
    """Generate a unique cache key based on function arguments"""
    # Convert args and kwargs to a string representation
    key_parts = [prefix]
    
    if args:
        for arg in args:
            key_parts.append(str(arg))
    
    if kwargs:
        # Sort kwargs for consistent keys
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}:{v}")
    
    # Join and hash to create fixed-length key
    key_str = ":".join(key_parts)
    return hashlib.md5(key_str.encode()).hexdigest()

def cache_result(ttl_seconds: int = 300):
    """Decorator for caching function results in memory"""
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            prefix = f"{func.__module__}.{func.__name__}"
            cache_key = generate_cache_key(prefix, *args, **kwargs)
            
            # Check cache
            cache_item = _cache.get(cache_key)
            if cache_item and not cache_item.is_expired():
                return cache_item.value
            
            # Call function
            result = await func(*args, **kwargs)
            
            # Store in cache
            expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)
            _cache[cache_key] = CacheItem(result, expires_at)
            
            return result
        return wrapper
    return decorator

def invalidate_cache(prefix: str, *args, **kwargs) -> None:
    """Invalidate specific cache entries"""
    if not args and not kwargs:
        # Invalidate all entries with prefix
        for key in list(_cache.keys()):
            if key.startswith(prefix):
                del _cache[key]
    else:
        # Invalidate specific entry
        cache_key = generate_cache_key(prefix, *args, **kwargs)
        if cache_key in _cache:
            del _cache[cache_key]

def clear_cache() -> None:
    """Clear the entire cache"""
    _cache.clear()
'@

WriteFile -Path $cachingUtilPath -Content $cachingUtilContent

# Admin Service - Update Admin Service with Caching
$adminServicePath = "admin-service/app/services/admin_service.py"

# Check if admin_service.py exists and update with caching
if (Test-Path -Path $adminServicePath) {
    $content = Get-Content -Path $adminServicePath -Raw
    
    # Add import
    if (-not $content.Contains("from app.utils.caching import")) {
        $content = "from app.utils.caching import cache_result, invalidate_cache`n" + $content
    }
    
    # Add caching decorator to get_dashboard_metrics
    $content = $content -replace 'async def get_dashboard_metrics\(', '@cache_result(ttl_seconds=300)  # Cache for 5 minutes`n    async def get_dashboard_metrics('
    
    # Add caching decorator to list_admin_users
    $content = $content -replace 'async def list_admin_users\(', '@cache_result(ttl_seconds=600)  # Cache for 10 minutes`n    async def list_admin_users('
    
    # Add cache invalidation to create_admin_user
    $content = $content -replace '(?s)(async def create_admin_user.*?await self\.db\.refresh\(admin\))', '$1`n        # After creating admin, invalidate cache for admin list`n        invalidate_cache("app.services.admin_service.AdminService.list_admin_users")'
    
    # Add cache invalidation to block_user
    $content = $content -replace '(?s)(async def block_user.*?details={"reason": reason}\))', '$1`n        # After blocking user, invalidate dashboard metrics cache`n        invalidate_cache("app.services.admin_service.AdminService.get_dashboard_metrics")'
    
    Set-Content -Path $adminServicePath -Value $content
    Write-Host "Updated Admin Service with caching at $adminServicePath" -ForegroundColor Cyan
}

# Admin Service - Update Docker Compose
$adminDockerPath = "admin-service/docker-compose.yml"
$adminDockerContent = @'
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

WriteFile -Path $adminDockerPath -Content $adminDockerContent

# 4. Update Payment Service Docker Compose
$paymentDockerPath = "payment-service/docker-compose.yml"
$paymentDockerContent = @'
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

WriteFile -Path $paymentDockerPath -Content $paymentDockerContent

# 5. Update KYC Service Docker Compose
$kycDockerPath = "kyc-service/docker-compose.yml"
$kycDockerContent = @'
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

WriteFile -Path $kycDockerPath -Content $kycDockerContent

# 6. Update Infrastructure - Remove Redis References
Write-Host "Updating infrastructure Terraform files..." -ForegroundColor Yellow

# Update main.tf to remove Redis
$infraMainPath = "infrastructure/main.tf"

if (Test-Path -Path $infraMainPath) {
    $content = Get-Content -Path $infraMainPath -Raw
    
    # Remove Redis module
    $redisPattern = '(?s)# Redis for OTP and caching.*?engine_version = var\.redis_engine_version\n\}\n\n'
    $content = $content -replace $redisPattern, ''
    
    # Update environment variables to remove Redis references and add MSG91
    $content = $content -replace 'REDIS_HOST", value = module\.redis\.endpoint', 'MSG91_AUTH_KEY", value = var.msg91_auth_key'
    
    Set-Content -Path $infraMainPath -Value $content
    Write-Host "Updated infrastructure main.tf to remove Redis references" -ForegroundColor Cyan
}

# Update variables.tf to remove Redis variables
$infraVarsPath = "infrastructure/variables.tf"

if (Test-Path -Path $infraVarsPath) {
    $content = Get-Content -Path $infraVarsPath -Raw
    
    # Remove Redis variables
    $redisVarsPattern = '(?s)# Redis Variables.*?default\s+= "6\.x"\n\}\n\n'
    $content = $content -replace $redisVarsPattern, ''
    
    # Add MSG91 variables
    $msg91VarsContent = @'
# MSG91 Variables
variable "msg91_auth_key" {
  description = "MSG91 Auth Key"
  sensitive   = true
}

variable "msg91_template_id" {
  description = "MSG91 Template ID"
  sensitive   = true
}

'@
    
    # Replace placeholder to add MSG91 variables
    if ($content -match "# ECS Service Variables") {
        $content = $content -replace "# ECS Service Variables", ($msg91VarsContent + "# ECS Service Variables")
    } else {
        # Add to the end if pattern not found
        $content += "`n" + $msg91VarsContent
    }
    
    Set-Content -Path $infraVarsPath -Value $content
    Write-Host "Updated infrastructure variables.tf to remove Redis variables and add MSG91 variables" -ForegroundColor Cyan
}

# Update outputs.tf to remove Redis reference
$infraOutputsPath = "infrastructure/outputs.tf"

if (Test-Path -Path $infraOutputsPath) {
    $content = Get-Content -Path $infraOutputsPath -Raw
    
    # Remove Redis endpoint output
    $redisOutputPattern = '(?s)output "redis_endpoint".*?value\s+= module\.redis\.endpoint\n\}\n\n'
    $content = $content -replace $redisOutputPattern, ''
    
    Set-Content -Path $infraOutputsPath -Value $content
    Write-Host "Updated infrastructure outputs.tf to remove Redis endpoint output" -ForegroundColor Cyan
}

# 7. Update package requirements.txt files to add dependencies
Write-Host "Updating requirements.txt files to add needed dependencies..." -ForegroundColor Yellow

# OTP Service - Update requirements.txt
$otpReqsPath = "otp-service/requirements.txt"
if (Test-Path -Path $otpReqsPath) {
    $content = Get-Content -Path $otpReqsPath -Raw
    
    # Add aiohttp and remove redis if present
    if ($content -match 'redis==') {
        $content = $content -replace 'redis==.*\n', ''
    }
    
    if (-not $content.Contains("aiohttp")) {
        $content += "`naiohttp==3.8.5"
    }
    
    if (-not $content.Contains("passlib")) {
        $content += "`npasslib[bcrypt]==1.7.4"
    }
    
    Set-Content -Path $otpReqsPath -Value $content
    Write-Host "Updated OTP Service requirements.txt" -ForegroundColor Cyan
}

# User Service - Update requirements.txt
$userReqsPath = "user-service/requirements.txt"
if (Test-Path -Path $userReqsPath) {
    $content = Get-Content -Path $userReqsPath -Raw
    
    # Remove redis if present
    if ($content -match 'redis==') {
        $content = $content -replace 'redis==.*\n', ''
    }
    
    Set-Content -Path $userReqsPath -Value $content
    Write-Host "Updated User Service requirements.txt" -ForegroundColor Cyan
}

# 8. Create a test script to verify database connections
$testScriptPath = "test-db-connections.py"
$testScriptContent = @'
import asyncio
import sys
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.future import select
from sqlalchemy.sql import text

async def test_db_connection(db_url: str, service_name: str):
    """Test connection to a PostgreSQL database"""
    try:
        print(f"Testing connection to {service_name} database...")
        
        # Create engine
        engine = create_async_engine(db_url, echo=False)
        
        # Test connection with a simple query
        async with AsyncSession(engine) as session:
            result = await session.execute(text("SELECT 1"))
            value = result.scalar()
            
            if value == 1:
                print(f"✅ Successfully connected to {service_name} database")
                return True
            else:
                print(f"❌ Failed to execute query on {service_name} database")
                return False
    except Exception as e:
        print(f"❌ Error connecting to {service_name} database: {str(e)}")
        return False

async def main():
    # List of services and their database URLs
    services = [
        ("User Service", "postgresql+asyncpg://postgres:password@localhost:5432/user_service"),
        ("OTP Service", "postgresql+asyncpg://postgres:password@localhost:5433/otp_service"),
        ("KYC Service", "postgresql+asyncpg://postgres:password@localhost:5434/kyc_service"),
        ("Payment Service", "postgresql+asyncpg://postgres:password@localhost:5435/payment_service"),
        ("Admin Service", "postgresql+asyncpg://postgres:password@localhost:5436/admin_service")
    ]
    
    # Test each connection
    results = []
    for service_name, db_url in services:
        result = await test_db_connection(db_url, service_name)
        results.append((service_name, result))
    
    # Print summary
    print("\n=== Connection Test Summary ===")
    all_success = True
    for service_name, success in results:
        status = "✅ Success" if success else "❌ Failed"
        print(f"{service_name}: {status}")
        if not success:
            all_success = False
    
    if not all_success:
        print("\n⚠️ Some database connections failed. Please check your PostgreSQL setup.")
        sys.exit(1)
    else:
        print("\n✅ All database connections successful!")

if __name__ == "__main__":
    asyncio.run(main())
'@

WriteFile -Path $testScriptPath -Content $testScriptContent
Write-Host "Created database connection test script at $testScriptPath" -ForegroundColor Cyan

# 9. Create a utility script to clean PostgreSQL data
$cleanDbScriptPath = "clean-postgres-data.ps1"
$cleanDbScriptContent = @'
# PowerShell script to clean and reset PostgreSQL data
param(
    [switch]$Force
)

# Services and their database details
$services = @(
    @{
        Name = "User Service"
        Port = 5432
        Database = "user_service"
    },
    @{
        Name = "OTP Service"
        Port = 5433
        Database = "otp_service"
    },
    @{
        Name = "KYC Service"
        Port = 5434
        Database = "kyc_service"
    },
    @{
        Name = "Payment Service"
        Port = 5435
        Database = "payment_service"
    },
    @{
        Name = "Admin Service"
        Port = 5436
        Database = "admin_service"
    }
)

# PostgreSQL credentials
$pgUser = "postgres"
$pgPassword = "password"
$pgHost = "localhost"

# Check if psql is available
$psqlExists = $null
try {
    $psqlExists = Get-Command "psql" -ErrorAction SilentlyContinue
} catch {
    $psqlExists = $null
}

if (-not $psqlExists) {
    Write-Host "❌ PostgreSQL client (psql) not found. Please install PostgreSQL client tools." -ForegroundColor Red
    exit 1
}

# Confirmation
if (-not $Force) {
    Write-Host "⚠️ WARNING: This will delete all data in the following databases:" -ForegroundColor Yellow
    foreach ($service in $services) {
        Write-Host "  - $($service.Name) (Port: $($service.Port), Database: $($service.Database))" -ForegroundColor Yellow
    }
    
    $confirmation = Read-Host "Are you sure you want to proceed? (y/n)"
    if ($confirmation -ne "y") {
        Write-Host "Operation cancelled." -ForegroundColor Cyan
        exit 0
    }
}

# Set environment variable for PostgreSQL password
$env:PGPASSWORD = $pgPassword

# Process each service
foreach ($service in $services) {
    Write-Host "Processing $($service.Name)..." -ForegroundColor Cyan
    
    # Try to connect to the database
    try {
        $connected = $false
        $output = psql -h $pgHost -p $service.Port -U $pgUser -d "postgres" -c "SELECT 1" 2>&1
        $connected = $?
        
        if ($connected) {
            # Drop and recreate database
            Write-Host "  Dropping database $($service.Database)..." -ForegroundColor Gray
            psql -h $pgHost -p $service.Port -U $pgUser -d "postgres" -c "DROP DATABASE IF EXISTS $($service.Database);" | Out-Null
            
            Write-Host "  Creating database $($service.Database)..." -ForegroundColor Gray
            psql -h $pgHost -p $service.Port -U $pgUser -d "postgres" -c "CREATE DATABASE $($service.Database);" | Out-Null
            
            Write-Host "✅ Reset database for $($service.Name)" -ForegroundColor Green
        } else {
            Write-Host "❌ Could not connect to PostgreSQL for $($service.Name) (Port: $($service.Port))" -ForegroundColor Red
        }
    } catch {
        Write-Host "❌ Error processing $($service.Name): $_" -ForegroundColor Red
    }
}

# Clean up
$env:PGPASSWORD = ""

Write-Host "Database cleanup complete." -ForegroundColor Green
Write-Host "You can now restart your services to recreate the schema." -ForegroundColor Cyan
'@

WriteFile -Path $cleanDbScriptPath -Content $cleanDbScriptContent
Write-Host "Created PostgreSQL cleanup script at $cleanDbScriptPath" -ForegroundColor Cyan

# 10. Create a startup script for all services
$startupScriptPath = "start-services.ps1"
$startupScriptContent = @'
# PowerShell script to start all services
param(
    [string]$Service = "all"
)

$services = @(
    @{
        Name = "user-service"
        Path = "user-service"
        Port = 8000
    },
    @{
        Name = "otp-service"
        Path = "otp-service"
        Port = 8001
    },
    @{
        Name = "kyc-service"
        Path = "kyc-service"
        Port = 8002
    },
    @{
        Name = "payment-service"
        Path = "payment-service"
        Port = 8003
    },
    @{
        Name = "admin-service"
        Path = "admin-service"
        Port = 8004
    }
)

function Start-Service {
    param (
        [string]$ServicePath,
        [string]$ServiceName,
        [int]$Port
    )
    
    Write-Host "Starting $ServiceName on port $Port..." -ForegroundColor Cyan
    
    # Check if the directory exists
    if (-not (Test-Path $ServicePath)) {
        Write-Host "❌ Directory not found: $ServicePath" -ForegroundColor Red
        return
    }
    
    # Navigate to service directory
    Push-Location $ServicePath
    
    try {
        # Check if docker-compose is available
        $dockerComposeExists = $null
        try {
            $dockerComposeExists = Get-Command "docker-compose" -ErrorAction SilentlyContinue
        } catch {
            $dockerComposeExists = $null
        }
        
        if (-not $dockerComposeExists) {
            Write-Host "❌ Docker Compose not found. Please install Docker Compose." -ForegroundColor Red
            return
        }
        
        # Start the service
        docker-compose up -d
        
        if ($?) {
            Write-Host "✅ $ServiceName started successfully" -ForegroundColor Green
        } else {
            Write-Host "❌ Failed to start $ServiceName" -ForegroundColor Red
        }
    } finally {
        # Return to original directory
        Pop-Location
    }
}

if ($Service -eq "all") {
    foreach ($svc in $services) {
        Start-Service -ServicePath $svc.Path -ServiceName $svc.Name -Port $svc.Port
    }
} else {
    $selectedService = $services | Where-Object { $_.Name -eq $Service }
    
    if ($selectedService) {
        Start-Service -ServicePath $selectedService.Path -ServiceName $selectedService.Name -Port $selectedService.Port
    } else {
        Write-Host "❌ Service not found: $Service" -ForegroundColor Red
        Write-Host "Available services:" -ForegroundColor Yellow
        foreach ($svc in $services) {
            Write-Host "  - $($svc.Name)" -ForegroundColor Yellow
        }
    }
}

Write-Host "Done." -ForegroundColor Green
'@

WriteFile -Path $startupScriptPath -Content $startupScriptContent
Write-Host "Created service startup script at $startupScriptPath" -ForegroundColor Cyan

# 11. Create a README file with instructions
$readmePath = "POSTGRES_MIGRATION.md"
$readmeContent = @'
# Redis to PostgreSQL Migration Guide

This document explains the changes made to remove Redis dependencies and implement PostgreSQL-based alternatives.

## Changes Made

### 1. OTP Service Changes
- Removed Redis dependency for OTP storage
- Implemented OTP storage directly in PostgreSQL database
- Added MSG91 integration for OTP delivery
- OTPs are now stored as hashed values in the database for security

### 2. User Service Changes
- Implemented token blacklisting using PostgreSQL instead of Redis
- Added automatic cleanup of expired blacklisted tokens
- Added logout endpoint to blacklist tokens on user logout

### 3. Admin Service Changes
- Implemented application-level in-memory caching
- Added cache invalidation for stale data
- Improved dashboard metrics and admin user listing performance

### 4. Infrastructure Changes
- Removed Redis/ElastiCache from Terraform configuration
- Added MSG91 configuration variables
- Updated service environment variables

## How to Use

### Starting Services
Use the `start-services.ps1` script to start all services:

```powershell
.\start-services.ps1

.\start-services.ps1 -Service otp-service

Use the test-db-connections.py script to verify database connectivity:
python test-db-connections.py

If needed, you can clean and reset all databases using:
.\clean-postgres-data.ps1

Configuration Required
MSG91 Integration:

Set MSG91_AUTH_KEY and MSG91_TEMPLATE_ID environment variables in the OTP service configuration
Update Terraform variables with your MSG91 credentials
Database Configuration:

Each service uses a dedicated PostgreSQL database
Make sure the database ports match the configuration in docker-compose files
JWT Secret Key:

Ensure the same JWT secret key is used across all services for token validation
Performance Considerations
Database Indexing:

The blacklisted_tokens table has indexes on token_hash and expires_at columns
Consider additional indexes based on query patterns
Caching Strategy:

The in-memory caching has configurable TTL values
Adjust cache durations based on data volatility and access patterns
Database Cleanup:

Expired blacklisted tokens are automatically cleaned up daily
Consider adjusting the cleanup frequency for high-traffic systems 
'@

WriteFile -Path $readmePath -Content $readmeContent 
Write-Host "Created migration documentation at $readmePath" -ForegroundColor Cyan

Write-Host "Project update completed successfully!" -ForegroundColor Green 
Write-Host "Next Steps:" -ForegroundColor Yellow 
Write-Host "1. Review the changes in each service" -ForegroundColor Yellow 
Write-Host "2. Set up MSG91 credentials for OTP service" -ForegroundColor Yellow 
Write-Host "3. Run the database test script to verify connections" -ForegroundColor Yellow 
Write-Host "4. Start services using the startup script" -ForegroundColor Yellow 
Write-Host "5. Review POSTGRES_MIGRATION.md for detailed documentation" -ForegroundColor Yellow