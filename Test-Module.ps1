#!/usr/bin/env pwsh
# Quick test script for Microsoft Extractor Suite

Write-Host "Testing Microsoft Extractor Suite module..." -ForegroundColor Cyan

# Import the module
Import-Module ./Microsoft-Extractor-Suite.psd1 -Force

# Get available commands
$commands = Get-Command -Module Microsoft-Extractor-Suite

Write-Host "Found $($commands.Count) commands in the module" -ForegroundColor Green

# Test a simple command (this should work without authentication)
try {
    Get-Module Microsoft-Extractor-Suite | Format-List
    Write-Host "✓ Module loaded successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to load module: $_"
}
