# User Service

## Overview
The User Service handles user registration, authentication, profile management, and referral functionality.

## Features
- User registration and login with JWT authentication
- Profile management (update profile details)
- Referral system
- Secure password hashing with bcrypt

## API Endpoints
| Method | Endpoint          | Description             |
| ------ | ----------------- | ----------------------- |
| `POST` | `/users/register` | Register new user       |
| `POST` | `/users/login`    | Authenticate user (JWT) |
| `GET`  | `/users/profile`  | Fetch user profile      |
| `PUT`  | `/users/profile`  | Update profile          |
| `GET`  | `/users/referral` | Get referral info       |

## Setup and Running
1. Update environment variables in docker-compose.yml
2. Run the service:

## Development
- Uses FastAPI for API development
- PostgreSQL for database
- Redis for token management
- SQLAlchemy for ORM