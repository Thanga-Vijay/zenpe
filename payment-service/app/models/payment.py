import uuid
from sqlalchemy import Column, String, DateTime, Numeric, Integer, Boolean, ForeignKey, Text, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class Transaction(Base):
    __tablename__ = "transactions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    amount = Column(Numeric(10, 2), nullable=False)
    status = Column(String(20), default="Initiated")  # Initiated/Processing/Success/Failed
    upi_id = Column(String(100), nullable=False)
    credit_card_last4 = Column(String(4), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    payment_gateway_txn_id = Column(String(100), nullable=True)
    payment_method = Column(String(50), nullable=True)  # VISA/MasterCard/RuPay
    payment_gateway_response = Column(JSONB, default={})
    
    # Relationships
    settlement = relationship("Settlement", back_populates="transaction", uselist=False)
    retry_logs = relationship("PaymentRetryLog", back_populates="transaction")
    failed_transaction = relationship("FailedTransaction", back_populates="transaction", uselist=False)
    
    # Indices
    __table_args__ = (
        Index('idx_txn_user_created', "user_id", "created_at"),
        Index('idx_txn_status', "status"),
    )
    
    def __repr__(self):
        return f"<Transaction {self.id} {self.status}>"

class Settlement(Base):
    __tablename__ = "settlements"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    transaction_id = Column(UUID(as_uuid=True), ForeignKey("transactions.id", ondelete="CASCADE"), unique=True)
    settled_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="Pending")  # Pending/Settled/Failed
    retry_count = Column(Integer, default=0)
    settlement_reference = Column(String(100), nullable=True)
    settlement_response = Column(JSONB, default={})
    
    # Relationships
    transaction = relationship("Transaction", back_populates="settlement")
    
    def __repr__(self):
        return f"<Settlement {self.id} {self.status}>"

class PaymentRetryLog(Base):
    __tablename__ = "payment_retry_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    transaction_id = Column(UUID(as_uuid=True), ForeignKey("transactions.id", ondelete="CASCADE"))
    retry_reason = Column(Text, nullable=False)
    retried_at = Column(DateTime, default=datetime.utcnow)
    attempt_number = Column(Integer, default=1)
    success = Column(Boolean, default=False)
    response = Column(JSONB, default={})
    
    # Relationships
    transaction = relationship("Transaction", back_populates="retry_logs")
    
    def __repr__(self):
        return f"<PaymentRetryLog {self.id} {self.success}>"

class FailedTransaction(Base):
    __tablename__ = "failed_transactions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    transaction_id = Column(UUID(as_uuid=True), ForeignKey("transactions.id", ondelete="CASCADE"), unique=True)
    failure_reason = Column(Text, nullable=False)
    failed_at = Column(DateTime, default=datetime.utcnow)
    error_code = Column(String(50), nullable=True)
    error_details = Column(JSONB, default={})
    refund_initiated = Column(Boolean, default=False)
    refund_status = Column(String(20), nullable=True)  # Initiated/Completed/Failed
    refund_reference = Column(String(100), nullable=True)
    
    # Relationships
    transaction = relationship("Transaction", back_populates="failed_transaction")
    
    def __repr__(self):
        return f"<FailedTransaction {self.id} {self.refund_status}>"
