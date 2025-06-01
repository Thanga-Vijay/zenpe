import os
from typing import Optional, Dict, Any, List
from datetime import timedelta
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
    
    # Email Configuration
    MAIL_USERNAME: str = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.getenv("MAIL_PASSWORD", "")
    MAIL_FROM: str = os.getenv("MAIL_FROM", "kyc@yourdomain.com")
    MAIL_PORT: int = int(os.getenv("MAIL_PORT", "587"))
    MAIL_SERVER: str = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_SSL_TLS: bool = True
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@yourdomain.com")
    
    # Security settings
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key")
    ADMIN_WHITELISTED_IPS: List[str] = os.getenv("ADMIN_WHITELISTED_IPS", "127.0.0.1").split(",")
    SESSION_TIMEOUT_MINUTES: int = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
    
    # Document settings
    ALLOWED_DOCUMENT_TYPES: List[str] = ["aadhaar_card", "pan_card", "passport", "driving_license", "voter_id"]
    MAX_DOCUMENT_SIZE_MB: int = 5
    DOCUMENT_RETENTION_DAYS: int = int(os.getenv("DOCUMENT_RETENTION_DAYS", "1825"))  # 5 years default
    
    # Verification settings
    VERIFICATION_CHECKLIST_REQUIRED: bool = True
    FOUR_EYES_PRINCIPLE_ENABLED: bool = True
    
    class Config:
        case_sensitive = True

settings = Settings()
