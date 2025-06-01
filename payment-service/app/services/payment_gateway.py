from typing import Dict, Any
from decimal import Decimal
import json
import razorpay
from app.config import settings

class PaymentGateway:
    def __init__(self):
        # Initialize Razorpay client
        self.client = razorpay.Client(
            auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
        )
    
    async def process_payment(
        self,
        amount: Decimal,
        card_token: str,
        upi_id: str,
        transaction_id: str
    ) -> Dict[str, Any]:
        """
        Process payment through Razorpay
        For development, simulate payment gateway response
        """
        # In a real implementation, call Razorpay API
        # For development, simulate gateway response
        
        # Convert Decimal to paise (Razorpay uses smallest currency unit)
        amount_in_paise = int(amount * 100)
        
        # Simulate Razorpay payment
        try:
            # In production, this would be a real API call:
            # payment = self.client.payment.create({
            #     'amount': amount_in_paise,
            #     'currency': 'INR',
            #     'payment_capture': '1',
            #     'notes': {
            #         'transaction_id': transaction_id,
            #         'upi_id': upi_id
            #     }
            # })
            
            # Simulated response
            gateway_txn_id = f"pay_{transaction_id.replace('-', '')[:16]}"
            
            return {
                "gateway_txn_id": gateway_txn_id,
                "status": "created",
                "amount": str(amount),
                "currency": "INR",
                "created_at": "2023-09-15T10:30:00Z",
                "card_id": card_token,
                "upi_id": upi_id
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"Payment gateway error: {str(e)}")
            raise ValueError(f"Payment processing failed: {str(e)}")
    
    async def check_payment_status(self, gateway_txn_id: str) -> Dict[str, Any]:
        """
        Check payment status with Razorpay
        For development, simulate payment gateway response
        """
        # In a real implementation, call Razorpay API
        # For development, simulate gateway response
        
        try:
            # In production, this would be a real API call:
            # payment = self.client.payment.fetch(gateway_txn_id)
            
            # Simulated response - assume payment succeeded
            return {
                "gateway_txn_id": gateway_txn_id,
                "status": "SUCCESS",
                "amount": "1000.00",
                "currency": "INR",
                "created_at": "2023-09-15T10:30:00Z",
                "updated_at": "2023-09-15T10:31:00Z"
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"Payment gateway status check error: {str(e)}")
            raise ValueError(f"Payment status check failed: {str(e)}")
    
    async def process_refund(
        self,
        gateway_txn_id: str,
        amount: Decimal = None
    ) -> Dict[str, Any]:
        """
        Process refund through Razorpay
        For development, simulate refund response
        """
        # In a real implementation, call Razorpay API
        # For development, simulate gateway response
        
        try:
            # In production, this would be a real API call:
            # refund = self.client.payment.refund(gateway_txn_id, {
            #     'amount': int(amount * 100) if amount else None
            # })
            
            # Simulated response
            refund_id = f"rfnd_{gateway_txn_id[4:]}"
            
            return {
                "refund_id": refund_id,
                "payment_id": gateway_txn_id,
                "status": "processed",
                "amount": str(amount) if amount else "1000.00",
                "currency": "INR",
                "created_at": "2023-09-15T11:00:00Z"
            }
            
        except Exception as e:
            # Log error and re-raise
            print(f"Payment gateway refund error: {str(e)}")
            raise ValueError(f"Refund processing failed: {str(e)}")
