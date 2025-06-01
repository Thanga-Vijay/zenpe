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
