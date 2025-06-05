# PowerShell script to update OTP service to use MSG91 while preserving existing functionality
$baseDir = "C:\Users\ADMIN\Documents\APP\Continue\Backend"
$otpServiceDir = Join-Path $baseDir "otp-service"

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

# Function to add MSG91 client to utils folder
function Add-MSG91Client {
    $msg91ClientContent = @'
import requests
import json
from typing import Dict, Any, Optional
from app.config import settings
from fastapi import HTTPException

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
                return {
                    "success": False,
                    "message": f"Failed to send OTP: {result.get('message', 'Unknown error')}",
                    "details": result
                }
                
        except requests.RequestException as e:
            return {
                "success": False,
                "message": f"API request failed: {str(e)}",
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
                return {
                    "success": False,
                    "message": f"OTP verification failed: {result.get('message', 'Invalid OTP')}",
                    "details": result
                }
                
        except requests.RequestException as e:
            return {
                "success": False,
                "message": f"API request failed: {str(e)}",
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
                return {
                    "success": False,
                    "message": f"Failed to resend OTP: {result.get('message', 'Unknown error')}",
                    "details": result
                }
                
        except requests.RequestException as e:
            return {
                "success": False,
                "message": f"API request failed: {str(e)}",
                "details": {"error": str(e)}
            }
'@

    Set-FileContent -Path (Join-Path $otpServiceDir "app\utils\msg91_client.py") -Content $msg91ClientContent
}

# Function to update config.py to add MSG91 settings
function Update-ConfigFile {
    $configPath = Join-Path $otpServiceDir "app\config.py"
    
    if (Test-Path $configPath) {
        $configContent = Get-Content -Path $configPath -Raw
        
        # Check if MSG91 settings already exist
        if (!($configContent -match "MSG91_AUTH_KEY")) {
            # Add MSG91 settings after OTP settings
            $msg91Settings = @'

    # MSG91 settings
    MSG91_AUTH_KEY: str = os.getenv("MSG91_AUTH_KEY", "your-msg91-auth-key")
    MSG91_TEMPLATE_ID: str = os.getenv("MSG91_TEMPLATE_ID", "your-msg91-template-id")
    MSG91_SENDER_ID: str = os.getenv("MSG91_SENDER_ID", "OTPSMS")
    MSG91_ROUTE: str = os.getenv("MSG91_ROUTE", "4")  # 4 is for transactional SMS
    MSG91_DLT_TE_ID: str = os.getenv("MSG91_DLT_TE_ID", "your-dlt-te-id")  # Required for Indian operators
'@
            
            # Find OTP settings section and add MSG91 settings after it
            $otpSettingsPattern = "# OTP settings[\s\S]*?OTP_LENGTH[^\r\n]*\r?\n"
            if ($configContent -match $otpSettingsPattern) {
                $updatedConfig = $configContent -replace $otpSettingsPattern, "$&$msg91Settings`n"
                Set-FileContent -Path $configPath -Content $updatedConfig
                Write-Host "Updated config.py with MSG91 settings"
            } else {
                Write-Host "Could not find OTP settings section in config.py"
            }
        } else {
            Write-Host "MSG91 settings already exist in config.py"
        }
    } else {
        Write-Host "config.py not found, creating it from scratch..."
        
        $newConfigContent = @'
import os
from typing import Optional, Dict, Any
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "OTP Service"
    API_V1_STR: str = "/api/v1"
    
    # OTP settings
    OTP_EXPIRY_SECONDS: int = 300  # 5 minutes
    OTP_LENGTH: int = 6
    
    # MSG91 settings
    MSG91_AUTH_KEY: str = os.getenv("MSG91_AUTH_KEY", "your-msg91-auth-key")
    MSG91_TEMPLATE_ID: str = os.getenv("MSG91_TEMPLATE_ID", "your-msg91-template-id")
    MSG91_SENDER_ID: str = os.getenv("MSG91_SENDER_ID", "OTPSMS")
    MSG91_ROUTE: str = os.getenv("MSG91_ROUTE", "4")  # 4 is for transactional SMS
    MSG91_DLT_TE_ID: str = os.getenv("MSG91_DLT_TE_ID", "your-dlt-te-id")  # Required for Indian operators
    
    # Database settings - For OTP logs
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/otp_service")
    
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
        Set-FileContent -Path $configPath -Content $newConfigContent
    }
}

# Function to update OTP service to use MSG91
function Update-OtpService {
    $otpServicePath = Join-Path $otpServiceDir "app\services\otp_service.py"
    
    if (Test-Path $otpServicePath) {
        $otpServiceContent = Get-Content -Path $otpServicePath -Raw
        
        # Check if MSG91 client is already imported
        if (!($otpServiceContent -match "from app\.utils\.msg91_client import MSG91Client")) {
            # Replace Redis client import with MSG91 client import
            if ($otpServiceContent -match "from app\.utils\.redis_client import RedisClient") {
                $otpServiceContent = $otpServiceContent -replace "from app\.utils\.redis_client import RedisClient", "from app.utils.msg91_client import MSG91Client"
            } else {
                # Add MSG91Client import if Redis import not found
                $importPattern = "import\s+[\w\s,]+\r?\n"
                if ($otpServiceContent -match $importPattern) {
                    $lastImport = $matches[0]
                    $otpServiceContent = $otpServiceContent -replace $lastImport, "$lastImport`nfrom app.utils.msg91_client import MSG91Client`n"
                }
            }
            
            # Replace RedisClient initialization with MSG91Client
            $otpServiceContent = $otpServiceContent -replace "self\.redis\s*=\s*RedisClient\(\)", "self.msg91_client = MSG91Client()"
            
            # Save the updated content
            Set-FileContent -Path $otpServicePath -Content $otpServiceContent
            Write-Host "Updated OTP service to use MSG91"
        } else {
            Write-Host "MSG91 client already imported in OTP service"
        }
    } else {
        Write-Host "OTP service file not found, creating a new one with MSG91 integration..."
        
        $newOtpServiceContent = @'
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
from app.config import settings

class OtpService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.msg91_client = MSG91Client()
        
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
        msg91_response = await self.msg91_client.send_otp(phone_number, otp_code)
        
        # Log OTP to database regardless of MSG91 response
        otp_log = await self._log_otp_to_db(phone_number, otp_code, otp_type, email, user_id)
        
        # If MSG91 failed, but we have email, try sending via email
        email_sent = False
        if not msg91_response["success"] and email:
            email_sent = await self._send_email(email, otp_code)
        
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
        # First verify with MSG91
        msg91_response = await self.msg91_client.verify_otp(phone_number, otp_code)
        
        if not msg91_response["success"]:
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
    
    async def resend_otp(
        self,
        phone_number: str,
        otp_type: str,
        retrytype: str = "text"
    ) -> OtpResponse:
        """
        Resend OTP to user's phone number via MSG91
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
'@
        Set-FileContent -Path $otpServicePath -Content $newOtpServiceContent
    }
}

# Function to update docker-compose.yml
function Update-DockerCompose {
    $dockerComposePath = Join-Path $otpServiceDir "docker-compose.yml"
    
    if (Test-Path $dockerComposePath) {
        $dockerComposeContent = Get-Content -Path $dockerComposePath -Raw
        
        # Check if MSG91 environment variables already exist
        if (!($dockerComposeContent -match "MSG91_AUTH_KEY")) {
            # Replace or add environment variables section
            $envPattern = "environment:[\s\S]*?- DATABASE_URL=[\s\S]*?\r?\n"
            $msg91Env = @'
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/otp_service
      - MSG91_AUTH_KEY=your-msg91-auth-key-here
      - MSG91_TEMPLATE_ID=your-msg91-template-id-here
      - MSG91_SENDER_ID=OTPSMS
      - MSG91_DLT_TE_ID=your-dlt-te-id-here
'@
            
            if ($dockerComposeContent -match $envPattern) {
                $dockerComposeContent = $dockerComposeContent -replace $envPattern, $msg91Env + "`n"
            } else {
                Write-Host "Could not find environment section in docker-compose.yml, please update manually"
            }
            
            # Remove Redis service if it exists
            $redisServicePattern = "\s+redis:[\s\S]*?volumes:(?=\r?\n)"
            if ($dockerComposeContent -match $redisServicePattern) {
                $dockerComposeContent = $dockerComposeContent -replace $redisServicePattern, "`n`nvolumes:"
            }
            
            # Save the updated content
            Set-FileContent -Path $dockerComposePath -Content $dockerComposeContent
            Write-Host "Updated docker-compose.yml with MSG91 environment variables"
        } else {
            Write-Host "MSG91 environment variables already exist in docker-compose.yml"
        }
    } else {
        Write-Host "docker-compose.yml not found, creating it from scratch..."
        
        $newDockerComposeContent = @'
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
        Set-FileContent -Path $dockerComposePath -Content $newDockerComposeContent
    }
}

# Function to update requirements.txt
function Update-Requirements {
    $requirementsPath = Join-Path $otpServiceDir "requirements.txt"
    
    if (Test-Path $requirementsPath) {
        $requirementsContent = Get-Content -Path $requirementsPath -Raw
        
        # Check if requests is already in requirements
        if (!($requirementsContent -match "requests==")) {
            # Add requests library
            $requirementsContent = $requirementsContent + "`nrequests==2.31.0"
            
            # Remove redis if it exists
            $requirementsContent = $requirementsContent -replace "redis==.*\r?\n", ""
            
            # Save the updated content
            Set-FileContent -Path $requirementsPath -Content $requirementsContent
            Write-Host "Updated requirements.txt to add requests and remove redis"
        } else {
            Write-Host "requests library already in requirements.txt"
        }
    } else {
        Write-Host "requirements.txt not found, creating it from scratch..."
        
        $newRequirementsContent = @'
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
        Set-FileContent -Path $requirementsPath -Content $newRequirementsContent
    }
}

# Remove Redis client file if it exists
function Remove-RedisClient {
    $redisClientPath = Join-Path $otpServiceDir "app\utils\redis_client.py"
    if (Test-Path $redisClientPath) {
        Remove-Item $redisClientPath
        Write-Host "Removed Redis client file: $redisClientPath"
    }
}

# Main execution
Write-Host "Starting OTP Service update to use MSG91 instead of Redis..."

# Check if OTP service directory exists
if (!(Test-Path $otpServiceDir)) {
    Write-Host "OTP Service directory not found at: $otpServiceDir"
    exit 1
}

# Create utils directory if it doesn't exist
$utilsDir = Join-Path $otpServiceDir "app\utils"
if (!(Test-Path $utilsDir)) {
    New-Item -ItemType Directory -Path $utilsDir -Force | Out-Null
}

# Add MSG91 client
Add-MSG91Client

# Update config.py
Update-ConfigFile

# Update OTP service
Update-OtpService

# Update docker-compose.yml
Update-DockerCompose

# Update requirements.txt
Update-Requirements

# Remove Redis client
Remove-RedisClient

Write-Host "OTP Service successfully updated to use MSG91 instead of Redis!"
Write-Host "Please check the updated files and make any additional adjustments if needed."