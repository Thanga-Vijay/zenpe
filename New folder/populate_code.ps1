# PowerShell script to populate code in microservice files
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

# User Service Files
$userServiceDir = Join-Path $baseDir "user-service"

# main.py for User Service
$mainPyContent = @'
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.routers import users
from app.database import create_tables

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

@app.on_event("startup")
async def startup():
    await create_tables()

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
'@

Set-FileContent -Path (Join-Path $userServiceDir "app\main.py") -Content $mainPyContent

# config.py for User Service
$configPyContent = @'
import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "User Service"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your_default_secret_key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/user_service")
    
    # AWS Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_SECRET_MANAGER_NAME: str = os.getenv("AWS_SECRET_MANAGER_NAME", "user-service-secrets")
    
    # Redis settings for JWT blacklisting
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    
    class Config:
        case_sensitive = True

settings = Settings()
'@

Set-FileContent -Path (Join-Path $userServiceDir "app\config.py") -Content $configPyContent

# database.py for User Service
$databasePyContent = @'
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

Set-FileContent -Path (Join-Path $userServiceDir "app\database.py") -Content $databasePyContent

# Dockerfile for User Service
$dockerfileContent = @'
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
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
'@

Set-FileContent -Path (Join-Path $userServiceDir "Dockerfile") -Content $dockerfileContent

# docker-compose.yml for User Service
$dockerComposeContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/user_service
      - SECRET_KEY=your_development_secret_key
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
      - POSTGRES_DB=user_service
    ports:
      - "5432:5432"
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

Set-FileContent -Path (Join-Path $userServiceDir "docker-compose.yml") -Content $dockerComposeContent

# requirements.txt for User Service
$requirementsContent = @'
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
redis==4.6.0
pytest==7.4.2
pytest-asyncio==0.21.1
httpx==0.25.0
'@

Set-FileContent -Path (Join-Path $userServiceDir "requirements.txt") -Content $requirementsContent

# Create user.py model
$userModelContent = @'
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    full_name = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    phone_number = Column(String(20), unique=True, index=True, nullable=False)
    password_hash = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    profile = relationship("UserProfile", back_populates="user", uselist=False)
    login_attempts = relationship("LoginAttempt", back_populates="user")
    
    def __repr__(self):
        return f"<User {self.full_name}>"

class UserProfile(Base):
    __tablename__ = "user_profiles"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    dob = Column(DateTime, nullable=True)
    address = Column(Text, nullable=True)
    referral_code = Column(String(50), unique=True, index=True)
    referred_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="profile")
    
    def __repr__(self):
        return f"<UserProfile {self.id}>"

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    ip_address = Column(String(50))
    status = Column(String(20))  # Success/Failure
    attempted_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="login_attempts")
    
    def __repr__(self):
        return f"<LoginAttempt {self.id} {self.status}>"
'@

Set-FileContent -Path (Join-Path $userServiceDir "app\models\user.py") -Content $userModelContent

# Now you can continue adding more files...

Write-Host "Basic files for User Service have been populated."
Write-Host "You can continue adding more files and content to complete all microservices."