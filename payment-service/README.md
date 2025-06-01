# Payment and Settlement Service

## Overview
The Payment and Settlement Service handles credit card to UPI payment processing and settlement operations.

## Features
- Credit card to UPI payment processing
- Payment status tracking
- Settlement management
- Transaction history
- Integration with payment gateway (Razorpay)
- Event-driven architecture with AWS EventBridge

## API Endpoints
| Method | Endpoint                    | Description                     |
| ------ | --------------------------- | ------------------------------- |
| `POST` | `/payments/initiate`        | Start credit card → UPI payment |
| `GET`  | `/payments/status/{txn_id}` | Fetch payment status            |
| `GET`  | `/payments/history`         | Get user transaction history    |
| `POST` | `/settlements/trigger`      | Trigger manual settlement       |
| `GET`  | `/settlements/status`       | View settlement details         |

## Setup and Running
1. Update environment variables in docker-compose.yml (especially payment gateway credentials)
2. Run the service:

## Development
- Uses FastAPI for API development
- PostgreSQL for transaction data
- Razorpay for payment processing
- AWS EventBridge for event publishing
- AWS SQS for asynchronous processing
- SQLAlchemy for ORM