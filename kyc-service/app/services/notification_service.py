from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

class NotificationService:
    def __init__(self):
        self.mail_config = ConnectionConfig(
            MAIL_USERNAME = settings.MAIL_USERNAME,
            MAIL_PASSWORD = settings.MAIL_PASSWORD,
            MAIL_FROM = settings.MAIL_FROM,
            MAIL_PORT = settings.MAIL_PORT,
            MAIL_SERVER = settings.MAIL_SERVER,
            MAIL_SSL_TLS = settings.MAIL_SSL_TLS
        )
        self.fastmail = FastMail(self.mail_config)
    
    async def notify_new_kyc_request(self, kyc_request_id: uuid.UUID):
        message = MessageSchema(
            subject="New KYC Request for Review",
            recipients=[settings.ADMIN_EMAIL],
            body=f"New KYC request {kyc_request_id} is waiting for verification"
        )
        await self.fastmail.send_message(message)