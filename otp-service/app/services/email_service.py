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
