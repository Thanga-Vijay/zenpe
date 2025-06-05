# RuPay to UPI Payment Application

## Project Overview
This application allows users to make UPI payments using RuPay credit cards with security compliance, full transaction auditing, and a mobile-first experience.

## Microservices Architecture
The application is built using a microservices architecture with the following components:

### 1. User Service
Manages user accounts, authentication, and profile data.

### 2. OTP Service
Handles OTP generation, verification for secure authentication.

### 3. KYC Service
Manages KYC document uploads, verification workflow.

### 4. Payment + Settlement Service
Processes credit card to UPI payments and settlements.

### 5. Admin + Notification Service
Provides admin dashboard, notification management, and audit logging.

## Key Workflows

### User Onboarding
1. User registers via Web or Mobile app
2. User gets OTP (via OTP Service & Redis)
3. User completes KYC (via KYC Service)

### Transaction Flow
1. User initiates payment to a UPI ID via frontend
2. API Gateway routes request to Payment Service
3. Payment Service interacts with Razorpay and logs event to EventBridge
4. Settlement Service handles UPI payout
5. Notifications sent via Notification Service

### Admin Operations
1. Admin logs in through Admin Panel
2. Views dashboards, manages users, handles disputes
3. Operates via secure Admin Service APIs

## Deployment Architecture
- All microservices deployed in AWS ECS Fargate
- API Gateway exposing public endpoints
- Internal services using VPC Link + Internal ALB
- Aurora PostgreSQL for data storage
- Redis for OTP, SQS for async jobs, EventBridge for events
- S3 for document storage
- Secrets Manager for credentials

## Development Setup
Each microservice has its own Docker configuration for local development:


## API Documentation
Each service has its own API documentation available at `/docs` when running locally.

## Infrastructure
Infrastructure is managed using Terraform in the `infrastructure/` directory.
