# PowerShell script to start all services
param(
    [string]$Service = "all"
)

$services = @(
    @{
        Name = "user-service"
        Path = "user-service"
        Port = 8000
    },
    @{
        Name = "otp-service"
        Path = "otp-service"
        Port = 8001
    },
    @{
        Name = "kyc-service"
        Path = "kyc-service"
        Port = 8002
    },
    @{
        Name = "payment-service"
        Path = "payment-service"
        Port = 8003
    },
    @{
        Name = "admin-service"
        Path = "admin-service"
        Port = 8004
    }
)

function Start-Service {
    param (
        [string]$ServicePath,
        [string]$ServiceName,
        [int]$Port
    )
    
    Write-Host "Starting $ServiceName on port $Port..." -ForegroundColor Cyan
    
    # Check if the directory exists
    if (-not (Test-Path $ServicePath)) {
        Write-Host "âŒ Directory not found: $ServicePath" -ForegroundColor Red
        return
    }
    
    # Navigate to service directory
    Push-Location $ServicePath
    
    try {
        # Check if docker-compose is available
        $dockerComposeExists = $null
        try {
            $dockerComposeExists = Get-Command "docker-compose" -ErrorAction SilentlyContinue
        } catch {
            $dockerComposeExists = $null
        }
        
        if (-not $dockerComposeExists) {
            Write-Host "âŒ Docker Compose not found. Please install Docker Compose." -ForegroundColor Red
            return
        }
        
        # Start the service
        docker-compose up -d
        
        if ($?) {
            Write-Host "âœ… $ServiceName started successfully" -ForegroundColor Green
        } else {
            Write-Host "âŒ Failed to start $ServiceName" -ForegroundColor Red
        }
    } finally {
        # Return to original directory
        Pop-Location
    }
}

if ($Service -eq "all") {
    foreach ($svc in $services) {
        Start-Service -ServicePath $svc.Path -ServiceName $svc.Name -Port $svc.Port
    }
} else {
    $selectedService = $services | Where-Object { $_.Name -eq $Service }
    
    if ($selectedService) {
        Start-Service -ServicePath $selectedService.Path -ServiceName $selectedService.Name -Port $selectedService.Port
    } else {
        Write-Host "âŒ Service not found: $Service" -ForegroundColor Red
        Write-Host "Available services:" -ForegroundColor Yellow
        foreach ($svc in $services) {
            Write-Host "  - $($svc.Name)" -ForegroundColor Yellow
        }
    }
}

Write-Host "Done." -ForegroundColor Green
