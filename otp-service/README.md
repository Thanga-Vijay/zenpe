# OTP Service

## Overview
The OTP Service handles OTP generation, verification, and resending functionality for user authentication and sensitive operations using MSG91 as the OTP provider.

## Features
- OTP generation and delivery via MSG91 SMS service
- OTP verification with rate limiting
- Email fallback for OTP delivery
- Secure storage in PostgreSQL for audit logging
- Configurable OTP expiry time
- Error handling and retry mechanisms

## API Endpoints
| Method | Endpoint      | Description            |
| ------ | ------------- | ---------------------- |
| `POST` | `/otp/send`   | Send OTP (email/phone) |
| `POST` | `/otp/verify` | Verify OTP             |
| `GET`  | `/otp/resend` | Resend OTP             |

## Setup and Running
1. Update environment variables in docker-compose.yml (especially MSG91 credentials)
2. Run the service:


## MSG91 Integration
This service uses MSG91 for sending OTP messages. You need to:
1. Register at MSG91 and get an authentication key
2. Create an OTP template and get the template ID
3. Register your sender ID with telecom operators
4. For Indian deployments, register your template with DLT platform and get a TE ID

## Environment Variables
- `MSG91_AUTH_KEY`: Authentication key for MSG91
- `MSG91_TEMPLATE_ID`: Template ID for OTP messages
- `MSG91_SENDER_ID`: Sender ID for SMS (typically 6 characters)
- `MSG91_DLT_TE_ID`: DLT Template Entity ID (required for Indian deployments)
- `SMTP_USERNAME`: Email username for fallback OTP delivery
- `SMTP_PASSWORD`: Email password for fallback OTP delivery

## Development
- Uses FastAPI for API development
- PostgreSQL for audit logging and OTP tracking
- Requests library for MSG91 API integration
- Email template system for fallback OTP delivery
