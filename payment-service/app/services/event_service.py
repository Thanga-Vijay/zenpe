import uuid
import json
import boto3
from decimal import Decimal
from typing import Dict, Any, Optional
from app.config import settings

class DecimalEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for Decimal values
    """
    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        if isinstance(o, uuid.UUID):
            return str(o)
        return super(DecimalEncoder, self).default(o)

class EventService:
    def __init__(self):
        # Initialize AWS EventBridge client
        self.eventbridge = boto3.client(
            'events',
            region_name=settings.AWS_REGION
        )
        
        # Initialize AWS SQS client
        self.sqs = boto3.client(
            'sqs',
            region_name=settings.AWS_REGION
        )
    
    async def publish_payment_event(
        self,
        transaction_id: uuid.UUID,
        status: str,
        amount: Decimal,
        user_id: uuid.UUID,
        payment_gateway_txn_id: Optional[str] = None,
        error: Optional[str] = None,
        webhook_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Publish payment event to EventBridge
        For development, just log the event
        """
        event_detail = {
            "event_type": f"payment.{status.lower()}",
            "transaction_id": str(transaction_id),
            "status": status,
            "amount": str(amount),
            "user_id": str(user_id),
            "timestamp": f"{datetime.utcnow().isoformat()}Z"
        }
        
        if payment_gateway_txn_id:
            event_detail["payment_gateway_txn_id"] = payment_gateway_txn_id
        
        if error:
            event_detail["error"] = error
            
        if webhook_data:
            event_detail["webhook_data"] = webhook_data
        
        # In production, publish to EventBridge
        # try:
        #     response = self.eventbridge.put_events(
        #         Entries=[
        #             {
        #                 'Source': 'payment.service',
        #                 'DetailType': f'payment.{status.lower()}',
        #                 'Detail': json.dumps(event_detail, cls=DecimalEncoder),
        #                 'EventBusName': settings.AWS_EVENTBRIDGE_BUS
        #             }
        #         ]
        #     )
        #     print(f"Published event: {response}")
        # except Exception as e:
        #     print(f"Error publishing event: {str(e)}")
        
        # For development, just log the event
        print(f"PAYMENT EVENT: {json.dumps(event_detail, cls=DecimalEncoder)}")
    
    async def publish_settlement_event(
        self,
        transaction_id: uuid.UUID,
        settlement_id: uuid.UUID,
        status: str,
        amount: Decimal,
        user_id: uuid.UUID,
        error: Optional[str] = None
    ) -> None:
        """
        Publish settlement event to EventBridge and SQS
        For development, just log the event
        """
        event_detail = {
            "event_type": f"settlement.{status.lower()}",
            "transaction_id": str(transaction_id),
            "settlement_id": str(settlement_id),
            "status": status,
            "amount": str(amount),
            "user_id": str(user_id),
            "timestamp": f"{datetime.utcnow().isoformat()}Z"
        }
        
        if error:
            event_detail["error"] = error
        
        # In production, publish to EventBridge
        # try:
        #     response = self.eventbridge.put_events(
        #         Entries=[
        #             {
        #                 'Source': 'settlement.service',
        #                 'DetailType': f'settlement.{status.lower()}',
        #                 'Detail': json.dumps(event_detail, cls=DecimalEncoder),
        #                 'EventBusName': settings.AWS_EVENTBRIDGE_BUS
        #             }
        #         ]
        #     )
        #     print(f"Published event: {response}")
        # except Exception as e:
        #     print(f"Error publishing event: {str(e)}")
        
        # For successful settlements, also send to SQS for notification
        if status == "Settled":
            # In production, send to SQS
            # try:
            #     response = self.sqs.send_message(
            #         QueueUrl=settings.AWS_SQS_QUEUE_URL,
            #         MessageBody=json.dumps(event_detail, cls=DecimalEncoder)
            #     )
            #     print(f"Sent to SQS: {response}")
            # except Exception as e:
            #     print(f"Error sending to SQS: {str(e)}")
            
            # For development, just log the event
            print(f"SQS MESSAGE: {json.dumps(event_detail, cls=DecimalEncoder)}")
        
        # For development, log all events
        print(f"SETTLEMENT EVENT: {json.dumps(event_detail, cls=DecimalEncoder)}")
