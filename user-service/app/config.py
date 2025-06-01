import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "User Service"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your_default_secret_key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # Changed to 1 hour from 8 days
    
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/user_service")
    
    # AWS Settings
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
    AWS_SECRET_MANAGER_NAME: str = os.getenv("AWS_SECRET_MANAGER_NAME", "user-service-secrets")
    
    # Remove Redis settings as we're not using it anymore
    
    # Cache settings
    TOKEN_CACHE_TTL: int = 300  # 5 minutes cache for token blacklist
    
    class Config:
        case_sensitive = True

settings = Settings()
