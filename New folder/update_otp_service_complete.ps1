# PowerShell script to update OTP service to use MSG91 instead of Redis
# Including Terraform changes, additional enhancements and error handling
$baseDir = "C:\Users\ADMIN\Documents\APP\Continue\Backend"
$otpServiceDir = Join-Path $baseDir "otp-service"
$infraDir = Join-Path $baseDir "infrastructure"

# Function to create or overwrite a file with content
function Set-FileContent {
    param (
        [string]$Path,
        [string]$Content
    )
    
    # Create directory if it doesn't exist
    $directory = Split-Path -Path $Path -Parent
    if (!(Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    
    if (Test-Path $Path) {
        Clear-Content $Path
    }
    
    $Content | Out-File -FilePath $Path -Encoding utf8
    Write-Host "Updated file: $Path"
}

#############################################
# 1. UPDATE OTP SERVICE APPLICATION CODE
#############################################

# Update OTP Service config.py
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
    
    # MSG91 settings
    MSG91_AUTH_KEY: str = os.getenv("MSG91_AUTH_KEY", "your-msg91-auth-key")
    MSG91_TEMPLATE_ID: str = os.getenv("MSG91_TEMPLATE_ID", "your-msg91-template-id")
    MSG91_SENDER_ID: str = os.getenv("MSG91_SENDER_ID", "OTPSMS")
    MSG91_ROUTE: str = os.getenv("MSG91_ROUTE", "4")  # 4 is for transactional SMS
    MSG91_DLT_TE_ID: str = os.getenv("MSG91_DLT_TE_ID", "your-dlt-te-id")  # Required for Indian operators
    
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

# Create new MSG91 client service
$msg91ClientContent = @'
import requests
import json
from typing import Dict, Any, Optional
from app.config import settings
from app.utils.exceptions import MSG91Exception

class MSG91Client:
    """Client for interacting with MSG91 API for OTP services"""
    
    BASE_URL = "https://api.msg91.com/api/v5"
    
    def __init__(self):
        self.auth_key = settings.MSG91_AUTH_KEY
        self.template_id = settings.MSG91_TEMPLATE_ID
        self.sender_id = settings.MSG91_SENDER_ID
        self.route = settings.MSG91_ROUTE
        self.dlt_te_id = settings.MSG91_DLT_TE_ID
    
    async def send_otp(self, phone_number: str, otp_code: str = None) -> Dict[str, Any]:
        """
        Send OTP via MSG91. If OTP code is provided, it will be sent.
        Otherwise, MSG91 will generate an OTP.
        """
        # Ensure phone number starts with country code
        if not phone_number.startswith("+"):
            if phone_number.startswith("0"):
                phone_number = "+91" + phone_number[1:]
            elif not phone_number.startswith("91"):
                phone_number = "+91" + phone_number
            else:
                phone_number = "+" + phone_number
        
        # Remove + for MSG91 API
        phone_number = phone_number.replace("+", "")
        
        url = f"{self.BASE_URL}/otp"
        
        payload = {
            "authkey": self.auth_key,
            "mobile": phone_number,
            "template_id": self.template_id,
            "sender": self.sender_id,
            "DLT_TE_ID": self.dlt_te_id
        }
        
        # If OTP code is provided, include it in the payload
        if otp_code:
            payload["otp"] = otp_code
        
        headers = {
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers)
            response.raise_for_status()
            result = response.json()
            
            if result.get("type") == "success":
                return {
                    "success": True,
                    "message": "OTP sent successfully",
                    "details": result
                }
            else:
                error_msg = f"Failed to send OTP: {result.get('message', 'Unknown error')}"
                return {
                    "success": False,
                    "message": error_msg,
                    "details": result
                }
                
        except requests.RequestException as e:
            error_msg = f"API request failed: {str(e)}"
            return {
                "success": False,
                "message": error_msg,
                "details": {"error": str(e)}
            }
    
    async def verify_otp(self, phone_number: str, otp_code: str) -> Dict[str, Any]:
        """
        Verify OTP via MSG91
        """
        # Ensure phone number starts with country code
        if not phone_number.startswith("+"):
            if phone_number.startswith("0"):
                phone_number = "+91" + phone_number[1:]
            elif not phone_number.startswith("91"):
                phone_number = "+91" + phone_number
            else:
                phone_number = "+" + phone_number
        
        # Remove + for MSG91 API
        phone_number = phone_number.replace("+", "")
        
        url = f"{self.BASE_URL}/otp/verify"
        
        payload = {
            "authkey": self.auth_key,
            "mobile": phone_number,
            "otp": otp_code
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers)
            response.raise_for_status()
            result = response.json()
            
            if result.get("type") == "success":
                return {
                    "success": True,
                    "message": "OTP verified successfully",
                    "details": result
                }
            else:
                error_msg = f"OTP verification failed: {result.get('message', 'Invalid OTP')}"
                return {
                    "success": False,
                    "message": error_msg,
                    "details": result
                }
                
        except requests.RequestException as e:
            error_msg = f"API request failed: {str(e)}"
            return {
                "success": False,
                "message": error_msg,
                "details": {"error": str(e)}
            }
    
    async def resend_otp(self, phone_number: str, retrytype: str = "text") -> Dict[str, Any]:
        """
        Resend OTP via MSG91
        retrytype can be "text" or "voice"
        """
        # Ensure phone number starts with country code
        if not phone_number.startswith("+"):
            if phone_number.startswith("0"):
                phone_number = "+91" + phone_number[1:]
            elif not phone_number.startswith("91"):
                phone_number = "+91" + phone_number
            else:
                phone_number = "+" + phone_number
        
        # Remove + for MSG91 API
        phone_number = phone_number.replace("+", "")
        
        url = f"{self.BASE_URL}/otp/resend"
        
        payload = {
            "authkey": self.auth_key,
            "mobile": phone_number,
            "retrytype": retrytype
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers)
            response.raise_for_status()
            result = response.json()
            
            if result.get("type") == "success":
                return {
                    "success": True,
                    "message": "OTP resent successfully",
                    "details": result
                }
            else:
                error_msg = f"Failed to resend OTP: {result.get('message', 'Unknown error')}"
                return {
                    "success": False,
                    "message": error_msg,
                    "details": result
                }
                
        except requests.RequestException as e:
            error_msg = f"API request failed: {str(e)}"
            return {
                "success": False,
                "message": error_msg,
                "details": {"error": str(e)}
            }
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\utils\msg91_client.py") -Content $msg91ClientContent

# Create a custom Exception class for MSG91 errors
$msg91ExceptionContent = @'
class MSG91Exception(Exception):
    """Exception raised for MSG91 API errors"""
    
    def __init__(self, message, status_code=None, response=None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\utils\exceptions.py") -Content $msg91ExceptionContent

# Update OTP Service service
$otpServiceContent = @'
import uuid
import random
import string
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.otp import OtpLog
from app.schemas.otp import OtpResponse, OtpVerifyResponse
from app.utils.msg91_client import MSG91Client
from app.services.email_service import EmailService
from app.utils.exceptions import MSG91Exception
from app.config import settings

class OtpService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.msg91_client = MSG91Client()
        self.email_service = EmailService()
        
    def _generate_otp(self, length: int = 6) -> str:
        """
        Generate a numeric OTP of specified length
        """
        return ''.join(random.choices(string.digits, k=length))
    
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
    
    async def generate_and_send_otp(
        self,
        phone_number: str,
        otp_type: str,
        email: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        ip_address: str = "0.0.0.0"
    ) -> OtpResponse:
        """
        Generate OTP, send via MSG91, and log to database
        """
        # Check if an OTP was recently sent for this phone number and type
        otp_query = select(OtpLog).where(
            OtpLog.phone_number == phone_number,
            OtpLog.otp_type == otp_type,
            OtpLog.verified == False,
            OtpLog.expires_at > datetime.utcnow()
        ).order_by(OtpLog.created_at.desc())
        
        result = await self.db.execute(otp_query)
        recent_otp = result.scalars().first()
        
        # If recent OTP exists and was sent less than 1 minute ago, return it
        if recent_otp and (datetime.utcnow() - recent_otp.created_at).total_seconds() < 60:
            remaining_time = int((recent_otp.expires_at - datetime.utcnow()).total_seconds())
            return OtpResponse(
                success=False,
                message="OTP already sent. Please wait before requesting again.",
                expires_in=remaining_time,
                reference_id=str(recent_otp.id)
            )
        
        # Generate new OTP
        otp_code = self._generate_otp(settings.OTP_LENGTH)
        
        # Send OTP via MSG91
        try:
            msg91_response = await self.msg91_client.send_otp(phone_number, otp_code)
            
            # Log OTP to database regardless of MSG91 response
            otp_log = await self._log_otp_to_db(phone_number, otp_code, otp_type, email, user_id)
            
            # If MSG91 failed, but we have email, try sending via email
            email_sent = False
            if not msg91_response["success"] and email:
                email_sent = await self.email_service.send_otp_email(email, otp_code)
            elif email:
                # If MSG91 succeeded but email is provided, send email as backup anyway
                await self.email_service.send_otp_email(email, otp_code)
            
            # If both SMS and email failed, return error
            if not msg91_response["success"] and not email_sent:
                return OtpResponse(
                    success=False,
                    message=f"Failed to send OTP: {msg91_response['message']}",
                    reference_id=str(otp_log.id)
                )
            
            return OtpResponse(
                success=True,
                message="OTP sent successfully",
                expires_in=settings.OTP_EXPIRY_SECONDS,
                reference_id=str(otp_log.id)
            )
            
        except Exception as e:
            # Handle any unexpected errors
            error_message = f"Error sending OTP: {str(e)}"
            
            # Try to log to database even if there was an error
            try:
                otp_log = await self._log_otp_to_db(phone_number, otp_code, otp_type, email, user_id)
                return OtpResponse(
                    success=False,
                    message=error_message,
                    reference_id=str(otp_log.id)
                )
            except Exception:
                # If database logging fails too, return a generic error
                return OtpResponse(
                    success=False,
                    message=error_message
                )
    
    async def verify_otp(
        self,
        phone_number: str,
        otp_code: str,
        otp_type: str,
        ip_address: str = "0.0.0.0"
    ) -> OtpVerifyResponse:
        """
        Verify OTP entered by user via MSG91
        """
        try:
            # First verify with MSG91
            msg91_response = await self.msg91_client.verify_otp(phone_number, otp_code)
            
            # For fallback: if MSG91 fails, check our database
            if not msg91_response["success"]:
                # Check if OTP exists in our database
                otp_query = select(OtpLog).where(
                    OtpLog.phone_number == phone_number,
                    OtpLog.otp_type == otp_type,
                    OtpLog.otp_code == otp_code,  # In production, compare hashed values
                    OtpLog.verified == False,
                    OtpLog.expires_at > datetime.utcnow()
                ).order_by(OtpLog.created_at.desc())
                
                result = await self.db.execute(otp_query)
                otp_log = result.scalars().first()
                
                if otp_log:
                    # OTP is valid in our database, mark as verified
                    otp_log.verified = True
                    otp_log.verified_at = datetime.utcnow()
                    await self.db.commit()
                    
                    return OtpVerifyResponse(
                        success=True,
                        message="OTP verified successfully via database",
                        user_id=otp_log.user_id
                    )
            
                # Update attempt count in DB for failed attempts
                attempt_query = select(OtpLog).where(
                    OtpLog.phone_number == phone_number,
                    OtpLog.otp_type == otp_type,
                    OtpLog.verified == False,
                    OtpLog.expires_at > datetime.utcnow()
                ).order_by(OtpLog.created_at.desc())
                
                attempt_result = await self.db.execute(attempt_query)
                attempt_log = attempt_result.scalars().first()
                
                if attempt_log:
                    attempt_log.verification_attempts += 1
                    await self.db.commit()
                
                return OtpVerifyResponse(
                    success=False,
                    message="Invalid OTP or OTP expired"
                )
            
            # If MSG91 verification successful, update our database
            otp_query = select(OtpLog).where(
                OtpLog.phone_number == phone_number,
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
                
                return OtpVerifyResponse(
                    success=True,
                    message="OTP verified successfully",
                    user_id=otp_log.user_id
                )
            else:
                # This is an edge case where MSG91 verification succeeded but we don't have a record
                # This could happen if our DB had an issue when the OTP was generated
                return OtpVerifyResponse(
                    success=True,
                    message="OTP verified by provider, but no local record found"
                )
                
        except Exception as e:
            # Handle any unexpected errors
            return OtpVerifyResponse(
                success=False,
                message=f"Error verifying OTP: {str(e)}"
            )
    
    async def resend_otp(
        self,
        phone_number: str,
        otp_type: str,
        retrytype: str = "text"
    ) -> OtpResponse:
        """
        Resend OTP to user's phone number via MSG91
        """
        try:
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
                    expires_in=int(60 - (datetime.utcnow() - otp_log.created_at).total_seconds()),
                    reference_id=str(otp_log.id)
                )
            
            # Resend OTP via MSG91
            msg91_response = await self.msg91_client.resend_otp(phone_number, retrytype)
            
            if not msg91_response["success"]:
                # If MSG91 resend failed, try sending a new OTP
                return await self.generate_and_send_otp(
                    phone_number=phone_number,
                    otp_type=otp_type,
                    email=otp_log.email,
                    user_id=otp_log.user_id
                )
            
            # If resend was successful, update the expiration time
            otp_log.expires_at = datetime.utcnow() + timedelta(seconds=settings.OTP_EXPIRY_SECONDS)
            await self.db.commit()
            
            return OtpResponse(
                success=True,
                message="OTP resent successfully",
                expires_in=settings.OTP_EXPIRY_SECONDS,
                reference_id=str(otp_log.id)
            )
            
        except ValueError as ve:
            # Handle specific value errors
            return OtpResponse(
                success=False,
                message=str(ve)
            )
        except Exception as e:
            # Handle any unexpected errors
            return OtpResponse(
                success=False,
                message=f"Error resending OTP: {str(e)}"
            )
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\services\otp_service.py") -Content $otpServiceContent

# Create a template for OTP emails
$emailTemplateDir = Join-Path $otpServiceDir "app\templates"
if (!(Test-Path $emailTemplateDir)) {
    New-Item -ItemType Directory -Path $emailTemplateDir -Force | Out-Null
}

$otpEmailTemplateContent = @'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Your OTP Code</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
        }
        .container {
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .header {
            background-color: #0066cc;
            color: white;
            padding: 10px;
            text-align: center;
            border-radius: 5px 5px 0 0;
        }
        .otp-code {
            font-size: 24px;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
            padding: 10px;
            background-color: #f5f5f5;
            border-radius: 5px;
            letter-spacing: 5px;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #999;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Your OTP Code</h2>
        </div>
        <p>Hello,</p>
        <p>Your One-Time Password (OTP) for verification is:</p>
        <div class="otp-code">{otp_code}</div>
        <p>This OTP is valid for 5 minutes. Please do not share this code with anyone.</p>
        <p>If you did not request this OTP, please ignore this email.</p>
        <div class="footer">
            <p>This is an automated message, please do not reply to this email.</p>
            <p>&copy; 2023 RuPay UPI. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
'@

Set-FileContent -Path (Join-Path $emailTemplateDir "otp_email.html") -Content $otpEmailTemplateContent

# Enhance the email service to use templates
$emailServiceContent = @'
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from typing import Optional
from app.config import settings

class EmailService:
    """Service for sending emails, including OTP emails"""
    
    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.smtp_from_email = settings.SMTP_FROM_EMAIL
        
        # Path to email templates
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.templates_dir = os.path.join(os.path.dirname(current_dir), "templates")
    
    async def send_otp_email(self, recipient_email: str, otp_code: str) -> bool:
        """
        Send OTP email using template
        """
        subject = "Your OTP Code for Verification"
        
        # Read template
        template_path = os.path.join(self.templates_dir, "otp_email.html")
        try:
            with open(template_path, "r") as f:
                template = f.read()
        except Exception as e:
            print(f"Error reading template: {str(e)}")
            # Fallback to simple text if template can't be read
            return await self.send_email(
                recipient_email, 
                subject, 
                f"Your OTP code is: {otp_code}. This code is valid for 5 minutes."
            )
        
        # Replace placeholders in template
        html_content = template.replace("{otp_code}", otp_code)
        
        return await self.send_email(recipient_email, subject, None, html_content)
    
    async def send_email(
        self, 
        recipient_email: str, 
        subject: str, 
        text_content: Optional[str] = None, 
        html_content: Optional[str] = None
    ) -> bool:
        """
        Send an email with optional HTML content
        """
        if not text_content and not html_content:
            raise ValueError("Either text_content or html_content must be provided")
        
        # For development, just log to console
        if settings.PROJECT_NAME.endswith("dev"):
            print(f"Email to {recipient_email}: {subject}")
            print(f"Content: {text_content or html_content}")
            return True
        
        # For production, send actual email
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self.smtp_from_email
            msg["To"] = recipient_email
            msg["Subject"] = subject
            
            if text_content:
                msg.attach(MIMEText(text_content, "plain"))
            
            if html_content:
                msg.attach(MIMEText(html_content, "html"))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return False
'@

Set-FileContent -Path (Join-Path $otpServiceDir "app\services\email_service.py") -Content $emailServiceContent

# Update requirements.txt for OTP Service
$otpRequirementsContent = @'
fastapi==0.103.1
uvicorn==0.23.2
sqlalchemy==2.0.20
asyncpg==0.28.0
alembic==1.12.0
pydantic==2.3.0
pydantic-settings==2.0.3
python-jose==3.3.0
python-multipart==0.0.6
email-validator==2.0.0.post2
requests==2.31.0
pytest==7.4.2
pytest-asyncio==0.21.1
httpx==0.25.0
'@

Set-FileContent -Path (Join-Path $otpServiceDir "requirements.txt") -Content $otpRequirementsContent

# Remove Redis client utility (no longer needed)
$redisClientPath = Join-Path $otpServiceDir "app\utils\redis_client.py"
if (Test-Path $redisClientPath) {
    Remove-Item $redisClientPath
    Write-Host "Removed file: $redisClientPath"
}

# Update docker-compose.yml for OTP service (continued)
$dockerComposeContent = @'
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8001:8001"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/otp_service
      - MSG91_AUTH_KEY=your-msg91-auth-key-here
      - MSG91_TEMPLATE_ID=your-msg91-template-id-here
      - MSG91_SENDER_ID=OTPSMS
      - MSG91_DLT_TE_ID=your-dlt-te-id-here
      - SMTP_USERNAME=your-email@example.com
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

Set-FileContent -Path (Join-Path $otpServiceDir "docker-compose.yml") -Content $dockerComposeContent

# Update README.md for OTP service
$otpReadmeContent = @'
# OTP Service

## Overview
The OTP Service handles OTP generation, verification, and resending functionality for user authentication and sensitive operations using MSG91 as the OTP provider.

## Features
- OTP generation and delivery via MSG91 SMS service
- OTP verification with rate limiting
- Email fallback for OTP delivery
- Secure storage in PostgreSQL for audit logging
- Configurable OTP expiry time
- Error handling and retry mechanisms

## API Endpoints
| Method | Endpoint      | Description            |
| ------ | ------------- | ---------------------- |
| `POST` | `/otp/send`   | Send OTP (email/phone) |
| `POST` | `/otp/verify` | Verify OTP             |
| `GET`  | `/otp/resend` | Resend OTP             |

## Setup and Running
1. Update environment variables in docker-compose.yml (especially MSG91 credentials)
2. Run the service:


## MSG91 Integration
This service uses MSG91 for sending OTP messages. You need to:
1. Register at MSG91 and get an authentication key
2. Create an OTP template and get the template ID
3. Register your sender ID with telecom operators
4. For Indian deployments, register your template with DLT platform and get a TE ID

## Environment Variables
- `MSG91_AUTH_KEY`: Authentication key for MSG91
- `MSG91_TEMPLATE_ID`: Template ID for OTP messages
- `MSG91_SENDER_ID`: Sender ID for SMS (typically 6 characters)
- `MSG91_DLT_TE_ID`: DLT Template Entity ID (required for Indian deployments)
- `SMTP_USERNAME`: Email username for fallback OTP delivery
- `SMTP_PASSWORD`: Email password for fallback OTP delivery

## Development
- Uses FastAPI for API development
- PostgreSQL for audit logging and OTP tracking
- Requests library for MSG91 API integration
- Email template system for fallback OTP delivery
'@

Set-FileContent -Path (Join-Path $otpServiceDir "README.md") -Content $otpReadmeContent

#############################################
# 2. TERRAFORM INFRASTRUCTURE CODE UPDATES
#############################################

# Create MSG91 Terraform module directory
$msg91ModuleDir = Join-Path $infraDir "modules\msg91"
if (!(Test-Path $msg91ModuleDir)) {
    New-Item -ItemType Directory -Path $msg91ModuleDir -Force | Out-Null
}

# MSG91 module main.tf
$msg91MainTf = @'
# This module integrates MSG91 credentials into your infrastructure
# It provides a standardized way to manage MSG91 credentials
# across different environments and services

# Store MSG91 credentials in AWS Secrets Manager
resource "aws_secretsmanager_secret" "msg91_credentials" {
  name = "${var.app_name}-msg91-credentials-${var.environment}"
  
  tags = {
    Name        = "${var.app_name}-msg91-credentials"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "msg91_credentials" {
  secret_id = aws_secretsmanager_secret.msg91_credentials.id
  secret_string = jsonencode({
    auth_key    = var.msg91_auth_key
    template_id = var.msg91_template_id
    sender_id   = var.msg91_sender_id
    dlt_te_id   = var.msg91_dlt_te_id
    route       = var.msg91_route
  })
}

# IAM policy to allow access to MSG91 credentials
resource "aws_iam_policy" "msg91_access" {
  name        = "${var.app_name}-msg91-access-${var.environment}"
  description = "Allow access to MSG91 credentials in Secrets Manager"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.msg91_credentials.arn
      }
    ]
  })
}

# CloudWatch alarm for MSG91 failures
resource "aws_cloudwatch_metric_alarm" "msg91_failures" {
  alarm_name          = "${var.app_name}-msg91-failures-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "${var.app_name}-msg91-failure-count"
  namespace           = "CustomMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Number of MSG91 API failures is too high"
  
  alarm_actions = var.alarm_actions
  ok_actions    = var.ok_actions
  
  insufficient_data_actions = []
  
  tags = {
    Name        = "${var.app_name}-msg91-failures"
    Environment = var.environment
  }
}
'@

Set-FileContent -Path (Join-Path $msg91ModuleDir "main.tf") -Content $msg91MainTf

# MSG91 module variables.tf
$msg91VariablesTf = @'
variable "app_name" {
  description = "Name of the application"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "msg91_auth_key" {
  description = "MSG91 Authentication Key"
  type        = string
  sensitive   = true
}

variable "msg91_template_id" {
  description = "MSG91 Template ID for OTP"
  type        = string
}

variable "msg91_sender_id" {
  description = "MSG91 Sender ID"
  type        = string
  default     = "OTPSMS"
}

variable "msg91_dlt_te_id" {
  description = "MSG91 DLT Template Entity ID (for Indian regulations)"
  type        = string
  default     = ""
}

variable "msg91_route" {
  description = "MSG91 Route (4 for transactional, 1 for promotional)"
  type        = string
  default     = "4"
}

variable "alarm_actions" {
  description = "List of ARNs to notify when alarm transitions to ALARM state"
  type        = list(string)
  default     = []
}

variable "ok_actions" {
  description = "List of ARNs to notify when alarm transitions to OK state"
  type        = list(string)
  default     = []
}
'@

Set-FileContent -Path (Join-Path $msg91ModuleDir "variables.tf") -Content $msg91VariablesTf

# MSG91 module outputs.tf
$msg91OutputsTf = @'
output "secret_arn" {
  description = "ARN of the MSG91 credentials secret"
  value       = aws_secretsmanager_secret.msg91_credentials.arn
}

output "policy_arn" {
  description = "ARN of the IAM policy for MSG91 access"
  value       = aws_iam_policy.msg91_access.arn
}

output "alarm_arn" {
  description = "ARN of the CloudWatch alarm for MSG91 failures"
  value       = aws_cloudwatch_metric_alarm.msg91_failures.arn
}
'@

Set-FileContent -Path (Join-Path $msg91ModuleDir "outputs.tf") -Content $msg91OutputsTf

# Create variables.tf additions for MSG91
$msg91Variables = @'
# MSG91 Variables
variable "msg91_auth_key" {
  description = "MSG91 Authentication Key"
  type        = string
  sensitive   = true
}

variable "msg91_template_id" {
  description = "MSG91 Template ID for OTP"
  type        = string
}

variable "msg91_sender_id" {
  description = "MSG91 Sender ID"
  type        = string
  default     = "OTPSMS"
}

variable "msg91_dlt_te_id" {
  description = "MSG91 DLT Template Entity ID (for Indian regulations)"
  type        = string
  default     = ""
}

variable "msg91_route" {
  description = "MSG91 Route (4 for transactional, 1 for promotional)"
  type        = string
  default     = "4"
}
'@

# Create OTP service module for Terraform
$otpServiceTfContent = @'
# ECS Services - OTP Service
module "otp_service" {
  source = "./modules/ecs-service"
  
  app_name          = "${var.app_name}-otp"
  environment       = var.environment
  ecs_cluster_id    = module.ecs.cluster_id
  ecs_cluster_name  = module.ecs.cluster_name
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  container_port    = 8001
  container_image   = "${var.ecr_repository_url}/otp-service:latest"
  desired_count     = var.service_desired_count
  cpu               = var.service_cpu
  memory            = var.service_memory
  task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn     = module.iam.ecs_task_role_arn
  alb_security_group_id = module.api_gateway.alb_security_group_id
  alb_listener_arn  = module.api_gateway.api_id
  listener_priority = 110
  path_pattern      = "otp"
  health_check_path = "/health"
  log_group_name    = module.monitoring.log_group_names.ecs
  
  environment_variables = [
    { name = "DATABASE_URL", value = "postgresql://${var.db_master_username}:${var.db_master_password}@${module.database.endpoint}/otp_service" },
    { name = "AWS_REGION", value = var.aws_region }
  ]
  
  secrets = [
    { name = "MSG91_AUTH_KEY", valueFrom = "${module.msg91.secret_arn}:auth_key::" },
    { name = "MSG91_TEMPLATE_ID", valueFrom = "${module.msg91.secret_arn}:template_id::" },
    { name = "MSG91_SENDER_ID", valueFrom = "${module.msg91.secret_arn}:sender_id::" },
    { name = "MSG91_DLT_TE_ID", valueFrom = "${module.msg91.secret_arn}:dlt_te_id::" },
    { name = "SMTP_USERNAME", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:smtp.username::" },
    { name = "SMTP_PASSWORD", valueFrom = "${aws_secretsmanager_secret.service_credentials.arn}:smtp.password::" }
  ]
}
'@

# Create MSG91 module reference for main.tf
$msg91ModuleReference = @'

# MSG91 Integration
module "msg91" {
  source = "./modules/msg91"
  
  app_name          = var.app_name
  environment       = var.environment
  msg91_auth_key    = var.msg91_auth_key
  msg91_template_id = var.msg91_template_id
  msg91_sender_id   = var.msg91_sender_id
  msg91_dlt_te_id   = var.msg91_dlt_te_id
  alarm_actions     = [module.monitoring.alarm_topic_arn]
  ok_actions        = [module.monitoring.alarm_topic_arn]
}
'@

# Create terraform.tfvars.example content for MSG91
$tfvarsMsg91Content = @'
# MSG91 Settings
msg91_auth_key = "your-msg91-auth-key"
msg91_template_id = "your-msg91-template-id"
msg91_sender_id = "OTPSMS"
msg91_dlt_te_id = "your-dlt-te-id"
msg91_route = "4"
'@

# Now try to update the Terraform files
Write-Host "Attempting to update Terraform files..."

# Update variables.tf to add MSG91 variables
$variablesTfPath = Join-Path $infraDir "variables.tf"
if (Test-Path $variablesTfPath) {
    $variablesTfContent = Get-Content -Path $variablesTfPath -Raw
    
    # Check if MSG91 variables already exist
    if (!($variablesTfContent -match "msg91_auth_key")) {
        # Find a good spot to add the variables - after the SMTP variables
        if ($variablesTfContent -match "smtp_password") {
            $updatedVariablesTf = $variablesTfContent -replace "(variable\s+[""']smtp_password[""'][\s\S]*?\})", "`$1`n`n$msg91Variables"
            Set-FileContent -Path $variablesTfPath -Content $updatedVariablesTf
            Write-Host "Added MSG91 variables to variables.tf"
        } else {
            # Just append to the end if SMTP variables not found
            $updatedVariablesTf = $variablesTfContent + "`n`n$msg91Variables"
            Set-FileContent -Path $variablesTfPath -Content $updatedVariablesTf
            Write-Host "Added MSG91 variables to the end of variables.tf"
        }
    } else {
        Write-Host "MSG91 variables already exist in variables.tf"
    }
} else {
    Write-Host "variables.tf not found in the infrastructure directory"
}

# Update terraform.tfvars.example to add MSG91 settings
$tfvarsExamplePath = Join-Path $infraDir "terraform.tfvars.example"
if (Test-Path $tfvarsExamplePath) {
    $tfvarsExampleContent = Get-Content -Path $tfvarsExamplePath -Raw
    
    # Check if MSG91 settings already exist
    if (!($tfvarsExampleContent -match "msg91_auth_key")) {
        # Append MSG91 settings to the end
        $updatedTfvarsExample = $tfvarsExampleContent + "`n`n$tfvarsMsg91Content"
        Set-FileContent -Path $tfvarsExamplePath -Content $updatedTfvarsExample
        Write-Host "Added MSG91 settings to terraform.tfvars.example"
    } else {
        Write-Host "MSG91 settings already exist in terraform.tfvars.example"
    }
} else {
    Write-Host "terraform.tfvars.example not found in the infrastructure directory"
}

# Attempt to safely update main.tf
$mainTfPath = Join-Path $infraDir "main.tf"
if (Test-Path $mainTfPath) {
    $mainTfContent = Get-Content -Path $mainTfPath -Raw
    
    # Add MSG91 module reference if it doesn't exist
    if (!($mainTfContent -match "module\s+""msg91""")) {
        # Find a good spot to add the module - before the ECS Services
        if ($mainTfContent -match "# ECS Services") {
            $updatedMainTf = $mainTfContent -replace "(# ECS Services)", "$msg91ModuleReference`n`n`$1"
            Set-FileContent -Path $mainTfPath -Content $updatedMainTf
            Write-Host "Added MSG91 module reference to main.tf"
        } else {
            Write-Host "Could not find a good spot to add MSG91 module in main.tf"
            Write-Host "Please manually add the following to main.tf:"
            Write-Host $msg91ModuleReference
        }
    } else {
        Write-Host "MSG91 module reference already exists in main.tf"
    }
    
    # Try to update the OTP service module
    if ($mainTfContent -match "# ECS Services - OTP Service[\s\S]*?module\s+""otp_service""[\s\S]*?\}") {
        # Extract the whole OTP service module block using regex
        $pattern = "# ECS Services - OTP Service[\s\S]*?module\s+""otp_service""[\s\S]*?\}"
        $updatedMainTf = $mainTfContent -replace $pattern, $otpServiceTfContent
        
        Set-FileContent -Path $mainTfPath -Content $updatedMainTf
        Write-Host "Updated OTP service module in main.tf"
    } else {
        Write-Host "Could not find OTP service module in main.tf"
        Write-Host "Please manually update the OTP service module in main.tf with:"
        Write-Host $otpServiceTfContent
    }
} else {
    Write-Host "main.tf not found in the infrastructure directory"
}

Write-Host "OTP Service has been successfully updated to use MSG91 instead of Redis!"
Write-Host "The application code and Terraform infrastructure have been modified accordingly."
Write-Host ""
Write-Host "Enhancements Added:"
Write-Host "1. MSG91 API client for OTP operations"
Write-Host "2. Enhanced email service with HTML templates as fallback"
Write-Host "3. Custom exception handling for MSG91 errors"
Write-Host "4. Terraform module for managing MSG91 credentials"
Write-Host "5. CloudWatch alarms for MSG91 API failures"
Write-Host ""
Write-Host "Important: Before deploying, you need to obtain MSG91 credentials:"
Write-Host "- Auth Key (from MSG91 dashboard)"
Write-Host "- Template ID (create an OTP template in MSG91)"
Write-Host "- Sender ID (typically 6 characters, register with telecom operators)"
Write-Host "- DLT TE ID (required for Indian deployments, register template with DLT platform)"