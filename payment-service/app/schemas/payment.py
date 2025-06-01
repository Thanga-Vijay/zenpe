import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator, condecimal

class PaymentBase(BaseModel):
    amount: condecimal(max_digits=10, decimal_places=2)  # type: ignore
    upi_id: str
    
class PaymentCreate(PaymentBase):
    credit_card_token: str
    credit_card_last4: str
    payment_method: Optional[str] = None
    
class PaymentResponse(PaymentBase):
    id: uuid.UUID
    status: str
    created_at: datetime
    updated_at: datetime
    credit_card_last4: str
    payment_method: Optional[str] = None
    
    class Config:
        orm_mode = True

class PaymentStatusResponse(BaseModel):
    id: uuid.UUID
    status: str
    amount: condecimal(max_digits=10, decimal_places=2)  # type: ignore
    upi_id: str
    created_at: datetime
    updated_at: datetime
    payment_gateway_txn_id: Optional[str] = None
    
    class Config:
        orm_mode = True

class PaymentHistoryItem(PaymentStatusResponse):
    payment_method: Optional[str] = None
    credit_card_last4: str
    
    class Config:
        orm_mode = True

class SettlementBase(BaseModel):
    transaction_id: uuid.UUID
    
class SettlementCreate(SettlementBase):
    pass
    
class SettlementResponse(SettlementBase):
    id: uuid.UUID
    status: str
    settled_at: Optional[datetime] = None
    retry_count: int
    settlement_reference: Optional[str] = None
    
    class Config:
        orm_mode = True

class FailedTransactionResponse(BaseModel):
    id: uuid.UUID
    transaction_id: uuid.UUID
    failure_reason: str
    failed_at: datetime
    error_code: Optional[str] = None
    refund_initiated: bool
    refund_status: Optional[str] = None
    
    class Config:
        orm_mode = True

class PaymentWebhookEvent(BaseModel):
    event_type: str
    transaction_id: uuid.UUID
    payment_gateway_txn_id: str
    status: str
    amount: condecimal(max_digits=10, decimal_places=2)  # type: ignore
    gateway_response: Dict[str, Any]
