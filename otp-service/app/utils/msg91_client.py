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
