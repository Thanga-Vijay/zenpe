import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.payment import Transaction, Settlement
from app.services.upi_service import UpiService
from app.services.event_service import EventService
from app.config import settings

class SettlementService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.upi_service = UpiService()
        self.event_service = EventService()
    
    async def trigger_settlement(self, transaction_id: uuid.UUID) -> Settlement:
        """
        Trigger settlement for a transaction
        """
        # Get transaction with settlement
        query = select(Transaction).where(
            Transaction.id == transaction_id,
            Transaction.status == "Success"
        ).options(
            selectinload(Transaction.settlement)
        )
        
        result = await self.db.execute(query)
        transaction = result.scalars().first()
        
        if not transaction:
            raise ValueError(f"Successful transaction not found with ID: {transaction_id}")
        
        # Check if settlement already exists
        if transaction.settlement:
            if transaction.settlement.status == "Settled":
                raise ValueError(f"Transaction already settled at: {transaction.settlement.settled_at}")
            
            settlement = transaction.settlement
        else:
            # Create new settlement
            settlement = Settlement(
                transaction_id=transaction_id,
                status="Pending"
            )
            self.db.add(settlement)
            await self.db.commit()
            await self.db.refresh(settlement)
        
        # Process settlement if it's pending or failed
        if settlement.status in ["Pending", "Failed"]:
            try:
                # Call UPI service to process settlement
                settlement_result = await self.upi_service.process_settlement(
                    amount=transaction.amount,
                    upi_id=transaction.upi_id,
                    transaction_id=str(transaction.id),
                    settlement_id=str(settlement.id)
                )
                
                # Update settlement based on result
                settlement.status = "Settled"
                settlement.settled_at = datetime.utcnow()
                settlement.settlement_reference = settlement_result.get("reference_id")
                settlement.settlement_response = settlement_result
                
                # Publish event
                await self.event_service.publish_settlement_event(
                    transaction_id=transaction.id,
                    settlement_id=settlement.id,
                    status="Settled",
                    amount=transaction.amount,
                    user_id=transaction.user_id
                )
                
            except Exception as e:
                # Handle settlement failure
                settlement.status = "Failed"
                settlement.retry_count += 1
                settlement.settlement_response = {"error": str(e)}
                
                # Publish failure event
                await self.event_service.publish_settlement_event(
                    transaction_id=transaction.id,
                    settlement_id=settlement.id,
                    status="Failed",
                    amount=transaction.amount,
                    user_id=transaction.user_id,
                    error=str(e)
                )
            
            await self.db.commit()
            await self.db.refresh(settlement)
        
        return settlement
    
    async def get_settlements_by_user(
        self,
        user_id: uuid.UUID,
        transaction_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        limit: int = 10,
        offset: int = 0
    ) -> List[Settlement]:
        """
        Get settlements for a user's transactions
        """
        query = select(Settlement).join(Transaction).where(Transaction.user_id == user_id)
        
        if transaction_id:
            query = query.where(Settlement.transaction_id == transaction_id)
        
        if status:
            query = query.where(Settlement.status == status)
        
        query = query.order_by(desc(Settlement.settled_at if Settlement.settled_at else Settlement.id))
        query = query.offset(offset).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_settlements_by_status(self, status: str, limit: int = 50) -> List[Settlement]:
        """
        Get settlements by status (for admin use)
        """
        query = select(Settlement).where(
            Settlement.status == status
        ).order_by(
            Settlement.id
        ).limit(limit)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def retry_settlement(self, settlement_id: uuid.UUID) -> Settlement:
        """
        Retry a failed settlement
        """
        # Get settlement with transaction
        query = select(Settlement).where(
            Settlement.id == settlement_id,
            Settlement.status == "Failed"
        ).options(
            selectinload(Settlement.transaction)
        )
        
        result = await self.db.execute(query)
        settlement = result.scalars().first()
        
        if not settlement:
            raise ValueError(f"Failed settlement not found with ID: {settlement_id}")
        
        if settlement.retry_count >= settings.MAX_RETRY_ATTEMPTS:
            raise ValueError(f"Maximum retry attempts reached: {settlement.retry_count}")
        
        # Increment retry count
        settlement.retry_count += 1
        await self.db.commit()
        
        # Process the settlement
        try:
            # Call UPI service to process settlement
            settlement_result = await self.upi_service.process_settlement(
                amount=settlement.transaction.amount,
                upi_id=settlement.transaction.upi_id,
                transaction_id=str(settlement.transaction.id),
                settlement_id=str(settlement.id)
            )
            
            # Update settlement based on result
            settlement.status = "Settled"
            settlement.settled_at = datetime.utcnow()
            settlement.settlement_reference = settlement_result.get("reference_id")
            settlement.settlement_response = settlement_result
            
            # Publish event
            await self.event_service.publish_settlement_event(
                transaction_id=settlement.transaction.id,
                settlement_id=settlement.id,
                status="Settled",
                amount=settlement.transaction.amount,
                user_id=settlement.transaction.user_id
            )
            
        except Exception as e:
            # Handle settlement failure
            settlement.status = "Failed"
            settlement.settlement_response = {"error": str(e)}
            
            # Publish failure event
            await self.event_service.publish_settlement_event(
                transaction_id=settlement.transaction.id,
                settlement_id=settlement.id,
                status="Failed",
                amount=settlement.transaction.amount,
                user_id=settlement.transaction.user_id,
                error=str(e)
            )
        
        await self.db.commit()
        await self.db.refresh(settlement)
        return settlement
