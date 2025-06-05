@echo off
REM Start all microservices in separate windows

start "Admin Service" cmd /k docker-compose -f admin-service/docker-compose.yml up --build
timeout /t 5 /nobreak > nul

start "OTP Service" cmd /k docker-compose -f otp-service/docker-compose.yml up --build
timeout /t 5 /nobreak > nul

start "User Service" cmd /k docker-compose -f user-service/docker-compose.yml up --build
timeout /t 5 /nobreak > nul

start "KYC Service" cmd /k docker-compose -f kyc-service/docker-compose.yml up --build
timeout /t 5 /nobreak > nul

start "Payment Service" cmd /k docker-compose -f payment-service/docker-compose.yml up --build
