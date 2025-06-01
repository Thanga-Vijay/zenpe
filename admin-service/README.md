# Admin and Notification Service

## Overview
The Admin and Notification Service handles admin operations, notifications to users, and audit logging.

## Features
- Admin dashboard with metrics
- User management (block/unblock)
- Notification system (email, SMS, in-app)
- Comprehensive audit logging
- Role-based access control

## API Endpoints
| Method | Endpoint              | Description                |
| ------ | --------------------- | -------------------------- |
| `GET`  | `/admin/dashboard`    | View metrics, logs         |
| `POST` | `/admin/block-user`   | Block a user               |
| `GET`  | `/notifications/logs` | Fetch notifications sent   |
| `POST` | `/notifications/send` | Send message to user/admin |
| `POST` | `/admin/audit/log`    | Manually log an action     |

## Setup and Running
1. Update environment variables in docker-compose.yml
2. Run the service:

## Development
- Uses FastAPI for API development
- PostgreSQL for data storage
- AWS SNS for notifications
- SQLAlchemy for ORM