#!/usr/bin/env pwsh
# Microsoft Extractor Suite - Module Import Script
# This script helps import the Microsoft Extractor Suite PowerShell module

param(
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "Microsoft Extractor Suite - Module Import Helper" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Get the module path
$modulePath = Join-Path $PSScriptRoot "Microsoft-Extractor-Suite.psd1"

if (-not (Test-Path $modulePath)) {
    Write-Error "Module manifest not found at: $modulePath"
    exit 1
}

# Check if module is already loaded
$existingModule = Get-Module -Name "Microsoft-Extractor-Suite" -ErrorAction SilentlyContinue

if ($existingModule) {
    if ($Force) {
        Write-Host "Removing existing module..." -ForegroundColor Yellow
        Remove-Module -Name "Microsoft-Extractor-Suite" -Force
    } else {
        Write-Host "Module is already loaded. Use -Force to reload." -ForegroundColor Yellow
        return
    }
}

# Import the module
try {
    Write-Host "Importing Microsoft Extractor Suite module..." -ForegroundColor Green
    
    if ($Verbose) {
        Import-Module $modulePath -Force -Verbose
    } else {
        Import-Module $modulePath -Force
    }
    
    Write-Host "✓ Module imported successfully!" -ForegroundColor Green
    Write-Host ""
    
    # Display available commands
    $commands = Get-Command -Module "Microsoft-Extractor-Suite" | Sort-Object Name
    
    if ($commands) {
        Write-Host "Available Commands:" -ForegroundColor Cyan
        Write-Host "==================" -ForegroundColor Cyan
        
        $commands | ForEach-Object {
            Write-Host "  • $($_.Name)" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "Total commands available: $($commands.Count)" -ForegroundColor Green
    } else {
        Write-Warning "No commands found in the module. The module may need to be built first."
    }
    
    Write-Host ""
    Write-Host "To get started:" -ForegroundColor Yellow
    Write-Host "  1. Run 'Connect-M365' to connect to Microsoft 365" -ForegroundColor White
    Write-Host "  2. Use 'Get-Command -Module Microsoft-Extractor-Suite' to see all available commands" -ForegroundColor White
    Write-Host "  3. Use 'Get-Help <CommandName>' for help on specific commands" -ForegroundColor White
    Write-Host ""
    
} catch {
    Write-Error "Failed to import module: $_"
    exit 1
}

# Check for dependencies
Write-Host "Checking dependencies..." -ForegroundColor Yellow

$requiredModules = @(
    'Microsoft.Graph',
    'ExchangeOnlineManagement',
    'Az.Accounts'
)

$missingModules = @()

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $missingModules += $module
    }
}

if ($missingModules.Count -gt 0) {
    Write-Host ""
    Write-Warning "The following PowerShell modules are recommended but not installed:"
    foreach ($module in $missingModules) {
        Write-Host "  • $module" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "To install missing modules, run:" -ForegroundColor Cyan
    foreach ($module in $missingModules) {
        Write-Host "  Install-Module -Name $module -Scope CurrentUser" -ForegroundColor White
    }
    Write-Host ""
}

Write-Host "Module import complete!" -ForegroundColor Green