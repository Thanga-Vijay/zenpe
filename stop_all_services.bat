@echo off
REM Stop all microservices

docker-compose -f admin-service/docker-compose.yml down
docker-compose -f otp-service/docker-compose.yml down
docker-compose -f user-service/docker-compose.yml down
docker-compose -f kyc-service/docker-compose.yml down
docker-compose -f payment-service/docker-compose.yml down
