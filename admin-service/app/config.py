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
