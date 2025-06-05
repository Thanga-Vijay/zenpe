@echo off
echo Creating microservice folder structure...

set BASE_DIR=C:\Users\ADMIN\Documents\APP\Continue\Backend

:: Create base directory if it doesn't exist
if not exist "%BASE_DIR%" mkdir "%BASE_DIR%"

:: Define microservices
set SERVICES=user-service otp-service kyc-service payment-service admin-service

for %%s in (%SERVICES%) do (
    echo Creating structure for %%s...
    
    :: Create service directory
    if not exist "%BASE_DIR%\%%s" mkdir "%BASE_DIR%\%%s"
    
    :: Create main structure
    mkdir "%BASE_DIR%\%%s\app"
    mkdir "%BASE_DIR%\%%s\tests"
    
    :: Create app subdirectories
    for %%d in (models routers schemas services utils) do (
        mkdir "%BASE_DIR%\%%s\app\%%d"
        type nul > "%BASE_DIR%\%%s\app\%%d\__init__.py"
    )
    
    :: Create root __init__.py
    type nul > "%BASE_DIR%\%%s\app\__init__.py"
    
    :: Create test directory files
    type nul > "%BASE_DIR%\%%s\tests\__init__.py"
    type nul > "%BASE_DIR%\%%s\tests\conftest.py"
    
    :: Create common files
    type nul > "%BASE_DIR%\%%s\Dockerfile"
    type nul > "%BASE_DIR%\%%s\docker-compose.yml"
    type nul > "%BASE_DIR%\%%s\requirements.txt"
    type nul > "%BASE_DIR%\%%s\README.md"
    
    :: Create core Python files
    type nul > "%BASE_DIR%\%%s\app\main.py"
    type nul > "%BASE_DIR%\%%s\app\config.py"
    type nul > "%BASE_DIR%\%%s\app\database.py"
    
    :: Create service-specific test files
    type nul > "%BASE_DIR%\%%s\tests\test_%%s.py"
)

echo Microservice folder structure created successfully at %BASE_DIR%
pause