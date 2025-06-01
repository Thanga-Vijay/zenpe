# KYC Service

## Overview
The KYC Service handles document upload, storage, and verification for Know Your Customer (KYC) processes.

## Features
- Document upload to S3 (ID cards, address proofs, etc.)
- Admin verification workflow
- Status tracking
- Audit logging for all operations

## API Endpoints
| Method | Endpoint            | Description                   |
| ------ | ------------------- | ----------------------------- |
| `POST` | `/kyc/upload`       | Upload KYC documents          |
| `GET`  | `/kyc/status`       | Check current status          |
| `GET`  | `/kyc/history`      | List previous KYC attempts    |
| `POST` | `/kyc/admin/verify` | Admin verifies KYC            |
| `POST` | `/kyc/admin/reject` | Admin rejects KYC with reason |

## Setup and Running
1. Update environment variables in docker-compose.yml
2. Run the service:

## Development
- Uses FastAPI for API development
- PostgreSQL for data storage
- AWS S3 for document storage
- SQLAlchemy for ORM