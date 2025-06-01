import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from decimal import Decimal
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.payment import Transaction, PaymentRetryLog, FailedTransaction, Settlement
from app.schemas.payment import PaymentCreate, PaymentResponse, PaymentStatusResponse, PaymentHistoryItem
from app.services.payment_gateway import PaymentGateway
from app.services.event_service import EventService
from app.config import settings

class PaymentService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.payment_gateway = PaymentGateway()
        self.event_service = EventService()
    
    async def initiate_payment(self, user_id: uuid.UUID, payment_data: PaymentCreate) -> Transaction:
        """
        Initiate a payment from credit card to UPI
        """
        # Create transaction record
        transaction = Transaction(
            user_id=user_id,
            amount=payment_data.amount,
            upi_id=payment_data.upi_id,
            credit_card_last4=payment_data.credit_card_last4,
            payment_method=payment_data.payment_method,
            status="Initiated"
        )
        self.db.add(transaction)
        await self.db.commit()
        await self.db.refresh(transaction)
        
        try:
            # Call payment gateway to process the payment
            payment_result = await self.payment_gateway.process_payment(
                amount=payment_data.amount,
                card_token=payment_data.credit_card_token,
                upi_id=payment_data.upi_id,
                transaction_id=str(transaction.id)
            )
            
            # Update transaction with gateway response
            transaction.payment_gateway_txn_id = payment_result.get("gateway_txn_id")
            transaction.status = "Processing"
            transaction.payment_gateway_response = payment_result
            
            # Publish event to EventBridge
            await self.event_service.publish_payment_event(
                transaction_id=transaction.id,
                status="Processing",
                amount=payment_data.amount,
                payment_gateway_txn_id=payment_result.get("gateway_txn_id"),
                user_id=user_id
            )
            
        except Exception as e:
            # Handle payment gateway errors
            transaction.status = "Failed"
            
            # Create failed transaction record
            failed_transaction = FailedTransaction(
                transaction_id=transaction.id,
                failure_reason=str(e),
                error_code="PAYMENT_GATEWAY_ERROR",
                error_details={"error": str(e)}
            )
            self.db.add(failed_transaction)
            
            # Publish failure event
            await self.event_service.publish_payment_event(
                transaction_id=transaction.id,
                status="Failed",
                amount=payment_data.amount,
                user_id=user_id,
                error=str(e)
            )
        
        await self.db.commit()
        await self.db.refresh(transaction)
        
        # Create settlement record for successful initiations
        if transaction.status == "Processing":
            settlement = Settlement(
                transaction_id=transaction.id,
                status="Pending"
            )
            self.db.add(settlement)
            await self.db.commit()
        
        return transaction
    
    async def get_payment_status(self, txn_id: uuid.UUID, user_id: uuid.UUID) -> Transaction:
        """
        Get status of a payment transaction
        """
        query = select(Transaction).where(
            Transaction.id == txn_id,
            Transaction.user_id == user_id
        )
        result = await self.db.execute(query)
        transaction = result.scalars().first()
        
        if not transaction:
            raise ValueError(f"Transaction not found with ID: {txn_id}")
        
        # If transaction is in Processing state for too long, check with gateway
        if (transaction.status == "Processing" and 
            (datetime.utcnow() - transaction.updated_at).total_seconds() > settings.TRANSACTION_TIMEOUT_SECONDS):
            try:
                # Call payment gateway to check status
                gateway_status = await self.payment_gateway.check_payment_status(
                    transaction.payment_gateway_txn_id
                )
                
                # Update transaction status based on gateway response
                if gateway_status.get("status") == "SUCCESS":
                    transaction.status = "Success"
                elif gateway_status.get("status") == "FAILED":
                    transaction.status = "Failed"
                    
                    # Create failed transaction record
                    failed_transaction = FailedTransaction(
                        transaction_id=transaction.id,
                        failure_reason="Payment failed at gateway",
                        error_code=gateway_status.get("error_code"),
                        error_details=gateway_status
                    )
                    self.db.add(failed_transaction)
                
                transaction.payment_gateway_response.update(gateway_status)
                await self.db.commit()
                await self.db.refresh(transaction)
                
                # Publish status update event
                await self.event_service.publish_payment_event(
                    transaction_id=transaction.id,
                    status=transaction.status,
                    amount=transaction.amount,
                    payment_gateway_txn_id=transaction.payment_gateway_txn_id,
                    user_id=transaction.user_id
                )
            except Exception as e:
                # Log error but don't change transaction status
                print(f"Error checking gateway status: {str(e)}")
        
        return transaction
    
    async def get_payment_history(
        self, 
        user_id: uuid.UUID, 
        limit: int = 10, 
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[Transaction]:
        """
        Get payment transaction history for a user
        """
        query = select(Transaction).where(Transaction.user_id == user_id)
        
        if status:
            query = query.where(Transaction.status == status)
        
        query = query.order_by(desc(Transaction.created_at)).offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_failed_transaction(self, txn_id: uuid.UUID, user_id: uuid.UUID) -> FailedTransaction:
        """
        Get details of a failed transaction
        """
        query = select(FailedTransaction).join(Transaction).where(
            Transaction.id == txn_id,
            Transaction.user_id == user_id,
            Transaction.status == "Failed"
        )
        
        result = await self.db.execute(query)
        failed_transaction = result.scalars().first()
        
        if not failed_transaction:
            raise ValueError(f"Failed transaction not found for ID: {txn_id}")
        
        return failed_transaction
    
    async def process_webhook_event(self, event_data: Dict[str, Any]) -> None:
        """
        Process webhook events from payment gateway
        """
        # Validate event data
        if "transaction_id" not in event_data or "status" not in event_data:
            raise ValueError("Invalid webhook event data")
        
        # Find transaction by gateway transaction ID
        gateway_txn_id = event_data.get("transaction_id")
        query = select(Transaction).where(
            Transaction.payment_gateway_txn_id == gateway_txn_id
        )
        
        result = await self.db.execute(query)
        transaction = result.scalars().first()
        
        if not transaction:
            raise ValueError(f"Transaction not found for gateway ID: {gateway_txn_id}")
        
        # Update transaction based on webhook event
        status = event_data.get("status")
        if status == "SUCCESS" and transaction.status != "Success":
            transaction.status = "Success"
        elif status == "FAILED" and transaction.status != "Failed":
            transaction.status = "Failed"
            
            # Create failed transaction record if not exists
            failed_query = select(FailedTransaction).where(
                FailedTransaction.transaction_id == transaction.id
            )
            failed_result = await self.db.execute(failed_query)
            if not failed_result.scalars().first():
                failed_transaction = FailedTransaction(
                    transaction_id=transaction.id,
                    failure_reason="Payment failed (webhook notification)",
                    error_code=event_data.get("error_code"),
                    error_details=event_data
                )
                self.db.add(failed_transaction)
        
        # Update transaction data
        transaction.payment_gateway_response.update(event_data)
        transaction.updated_at = datetime.utcnow()
        
        await self.db.commit()
        
        # Publish event to EventBridge
        await self.event_service.publish_payment_event(
            transaction_id=transaction.id,
            status=transaction.status,
            amount=transaction.amount,
            payment_gateway_txn_id=transaction.payment_gateway_txn_id,
            user_id=transaction.user_id,
            webhook_data=event_data
        )
