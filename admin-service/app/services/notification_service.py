import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, update, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
import boto3
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.models.admin import Notification, EmailTemplate
from app.schemas.admin import NotificationCreate
from app.config import settings

class NotificationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        
        # Initialize AWS SNS client
        self.sns = boto3.client(
            'sns',
            region_name=settings.AWS_REGION
        )
    
    async def send_notification(self, notification_data: NotificationCreate, sender_id: uuid.UUID) -> Notification:
        """
        Send notification to user or admin
        """
        # Create notification record
        notification = Notification(
            user_id=notification_data.user_id,
            admin_id=notification_data.admin_id,
            type=notification_data.type,
            title=notification_data.title,
            message=notification_data.message,
            metadata=notification_data.metadata,
            status="Pending"
        )
        
        self.db.add(notification)
        await self.db.commit()
        await self.db.refresh(notification)
        
        # Process notification based on type
        try:
            if notification.type == "Email":
                await self._send_email_notification(notification)
            elif notification.type == "SMS":
                await self._send_sms_notification(notification)
            elif notification.type == "In-App":
                # In-app notifications don't need to be sent externally
                notification.status = "Sent"
            else:
                raise ValueError(f"Unsupported notification type: {notification.type}")
            
            # Update notification status
            if notification.status == "Pending":
                notification.status = "Sent"
                notification.sent_at = datetime.utcnow()
            
        except Exception as e:
            notification.status = "Failed"
            notification.metadata["error"] = str(e)
        
        await self.db.commit()
        await self.db.refresh(notification)
        return notification
    
    async def _send_email_notification(self, notification: Notification) -> None:
        """
        Send email notification
        """
        if not notification.user_id and not notification.admin_id:
            raise ValueError("No recipient specified for email notification")
        
        # In a real implementation, you'd get user/admin email from respective services
        # For this demo, we'll assume the email is stored in metadata
        recipient_email = notification.metadata.get("email", "recipient@example.com")
        
        # Check if we need to use a template
        template_name = notification.metadata.get("template_name")
        if template_name:
            # Get template
            template_query = select(EmailTemplate).where(EmailTemplate.template_name == template_name)
            template_result = await self.db.execute(template_query)
            template = template_result.scalars().first()
            
            if not template:
                raise ValueError(f"Email template not found: {template_name}")
            
            # Replace variables in template
            subject = template.subject
            body = template.body
            
            # Replace variables
            template_vars = notification.metadata.get("template_vars", {})
            for var_name, var_value in template_vars.items():
                placeholder = f"{{{{{var_name}}}}}"
                body = body.replace(placeholder, str(var_value))
                subject = subject.replace(placeholder, str(var_value))
        else:
            # Use direct message
            subject = notification.title
            body = notification.message
        
        # In a real implementation, send via SMTP or SES
        # For this demo, just log
        print(f"Email to {recipient_email}: {subject} - {body}")
        
        # In production, this would be uncommented:
        """
        try:
            msg = MIMEMultipart()
            msg['From'] = settings.SMTP_FROM_EMAIL
            msg['To'] = recipient_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            server = smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT)
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            raise
        """
    
    async def _send_sms_notification(self, notification: Notification) -> None:
        """
        Send SMS notification
        """
        if not notification.user_id and not notification.admin_id:
            raise ValueError("No recipient specified for SMS notification")
        
        # In a real implementation, you'd get user/admin phone from respective services
        # For this demo, we'll assume the phone is stored in metadata
        recipient_phone = notification.metadata.get("phone", "+1234567890")
        
        # In a real implementation, send via SNS or third-party SMS provider
        # For this demo, just log
        print(f"SMS to {recipient_phone}: {notification.message}")
        
        # In production, this would be uncommented:
        """
        try:
            response = self.sns.publish(
                PhoneNumber=recipient_phone,
                Message=notification.message,
                MessageAttributes={
                    'AWS.SNS.SMS.SenderID': {
                        'DataType': 'String',
                        'StringValue': settings.SMS_SENDER_ID
                    }
                }
            )
            print(f"SMS sent: {response}")
        except Exception as e:
            print(f"Error sending SMS: {str(e)}")
            raise
        """
    
    async def get_notification_logs(
        self,
        user_id: Optional[uuid.UUID] = None,
        admin_id: Optional[uuid.UUID] = None,
        type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> List[Notification]:
        """
        Get notification logs with optional filters
        """
        query = select(Notification)
        
        # Apply filters
        filters = []
        if user_id:
            filters.append(Notification.user_id == user_id)
        if admin_id:
            filters.append(Notification.admin_id == admin_id)
        if type:
            filters.append(Notification.type == type)
        if status:
            filters.append(Notification.status == status)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(desc(Notification.sent_at if Notification.sent_at else Notification.id))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_user_notifications(
        self,
        user_id: uuid.UUID,
        is_read: Optional[bool] = None,
        limit: int = 10,
        offset: int = 0
    ) -> List[Notification]:
        """
        Get notifications for a user
        """
        query = select(Notification).where(
            Notification.user_id == user_id,
            Notification.type == "In-App"
        )
        
        if is_read is not None:
            query = query.where(Notification.is_read == is_read)
        
        query = query.order_by(desc(Notification.sent_at if Notification.sent_at else Notification.id))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def mark_notification_read(self, notification_id: uuid.UUID, user_id: uuid.UUID) -> None:
        """
        Mark a notification as read
        """
        query = select(Notification).where(
            Notification.id == notification_id,
            Notification.user_id == user_id
        )
        
        result = await self.db.execute(query)
        notification = result.scalars().first()
        
        if not notification:
            raise ValueError("Notification not found or does not belong to user")
        
        notification.is_read = True
        await self.db.commit()
