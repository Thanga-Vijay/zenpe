# Redis to PostgreSQL Migration Guide

This document explains the changes made to remove Redis dependencies and implement PostgreSQL-based alternatives.

## Changes Made

### 1. OTP Service Changes
- Removed Redis dependency for OTP storage
- Implemented OTP storage directly in PostgreSQL database
- Added MSG91 integration for OTP delivery
- OTPs are now stored as hashed values in the database for security

### 2. User Service Changes
- Implemented token blacklisting using PostgreSQL instead of Redis
- Added automatic cleanup of expired blacklisted tokens
- Added logout endpoint to blacklist tokens on user logout

### 3. Admin Service Changes
- Implemented application-level in-memory caching
- Added cache invalidation for stale data
- Improved dashboard metrics and admin user listing performance

### 4. Infrastructure Changes
- Removed Redis/ElastiCache from Terraform configuration
- Added MSG91 configuration variables
- Updated service environment variables

## How to Use

### Starting Services
Use the `start-services.ps1` script to start all services:

```powershell
.\start-services.ps1

.\start-services.ps1 -Service otp-service

Use the test-db-connections.py script to verify database connectivity:
python test-db-connections.py

If needed, you can clean and reset all databases using:
.\clean-postgres-data.ps1

Configuration Required
MSG91 Integration:

Set MSG91_AUTH_KEY and MSG91_TEMPLATE_ID environment variables in the OTP service configuration
Update Terraform variables with your MSG91 credentials
Database Configuration:

Each service uses a dedicated PostgreSQL database
Make sure the database ports match the configuration in docker-compose files
JWT Secret Key:

Ensure the same JWT secret key is used across all services for token validation
Performance Considerations
Database Indexing:

The blacklisted_tokens table has indexes on token_hash and expires_at columns
Consider additional indexes based on query patterns
Caching Strategy:

The in-memory caching has configurable TTL values
Adjust cache durations based on data volatility and access patterns
Database Cleanup:

Expired blacklisted tokens are automatically cleaned up daily
Consider adjusting the cleanup frequency for high-traffic systems 
