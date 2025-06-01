import uuid
from sqlalchemy import Column, String, DateTime, Text, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from app.database import Base

class OtpLog(Base):
    __tablename__ = "otp_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False)
    otp_code = Column(String(10))  # Store hashed OTP for security
    otp_type = Column(String(20))  # login/kyc/payment
    phone_number = Column(String(20), nullable=False)
    email = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    verified = Column(Boolean, default=False)
    verification_attempts = Column(Integer, default=0)
    verified_at = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<OtpLog {self.id} {self.otp_type}>"
