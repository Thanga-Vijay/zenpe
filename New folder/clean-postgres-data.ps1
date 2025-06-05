# PowerShell script to clean and reset PostgreSQL data
param(
    [switch]$Force
)

# Services and their database details
$services = @(
    @{
        Name = "User Service"
        Port = 5432
        Database = "user_service"
    },
    @{
        Name = "OTP Service"
        Port = 5433
        Database = "otp_service"
    },
    @{
        Name = "KYC Service"
        Port = 5434
        Database = "kyc_service"
    },
    @{
        Name = "Payment Service"
        Port = 5435
        Database = "payment_service"
    },
    @{
        Name = "Admin Service"
        Port = 5436
        Database = "admin_service"
    }
)

# PostgreSQL credentials
$pgUser = "postgres"
$pgPassword = "password"
$pgHost = "localhost"

# Check if psql is available
$psqlExists = $null
try {
    $psqlExists = Get-Command "psql" -ErrorAction SilentlyContinue
} catch {
    $psqlExists = $null
}

if (-not $psqlExists) {
    Write-Host "âŒ PostgreSQL client (psql) not found. Please install PostgreSQL client tools." -ForegroundColor Red
    exit 1
}

# Confirmation
if (-not $Force) {
    Write-Host "âš ï¸ WARNING: This will delete all data in the following databases:" -ForegroundColor Yellow
    foreach ($service in $services) {
        Write-Host "  - $($service.Name) (Port: $($service.Port), Database: $($service.Database))" -ForegroundColor Yellow
    }
    
    $confirmation = Read-Host "Are you sure you want to proceed? (y/n)"
    if ($confirmation -ne "y") {
        Write-Host "Operation cancelled." -ForegroundColor Cyan
        exit 0
    }
}

# Set environment variable for PostgreSQL password
$env:PGPASSWORD = $pgPassword

# Process each service
foreach ($service in $services) {
    Write-Host "Processing $($service.Name)..." -ForegroundColor Cyan
    
    # Try to connect to the database
    try {
        $connected = $false
        $output = psql -h $pgHost -p $service.Port -U $pgUser -d "postgres" -c "SELECT 1" 2>&1
        $connected = $?
        
        if ($connected) {
            # Drop and recreate database
            Write-Host "  Dropping database $($service.Database)..." -ForegroundColor Gray
            psql -h $pgHost -p $service.Port -U $pgUser -d "postgres" -c "DROP DATABASE IF EXISTS $($service.Database);" | Out-Null
            
            Write-Host "  Creating database $($service.Database)..." -ForegroundColor Gray
            psql -h $pgHost -p $service.Port -U $pgUser -d "postgres" -c "CREATE DATABASE $($service.Database);" | Out-Null
            
            Write-Host "âœ… Reset database for $($service.Name)" -ForegroundColor Green
        } else {
            Write-Host "âŒ Could not connect to PostgreSQL for $($service.Name) (Port: $($service.Port))" -ForegroundColor Red
        }
    } catch {
        Write-Host "âŒ Error processing $($service.Name): $_" -ForegroundColor Red
    }
}

# Clean up
$env:PGPASSWORD = ""

Write-Host "Database cleanup complete." -ForegroundColor Green
Write-Host "You can now restart your services to recreate the schema." -ForegroundColor Cyan
