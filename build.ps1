param(
    [string]$Configuration = "Release",
    [string]$OutputPath = ".\bin\Release\Microsoft-Extractor-Suite",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    if (Test-Path ".\bin") {
        Remove-Item ".\bin" -Recurse -Force
    }
    if (Test-Path ".\obj") {
        Remove-Item ".\obj" -Recurse -Force
    }
}

# Restore NuGet packages
Write-Host "Restoring NuGet packages..." -ForegroundColor Green
Push-Location ".\src"
try {
    dotnet restore
    if ($LASTEXITCODE -ne 0) {
        throw "Package restore failed"
    }
}
finally {
    Pop-Location
}

# Build the project
Write-Host "Building Microsoft.ExtractorSuite..." -ForegroundColor Green
Push-Location ".\src"
try {
    dotnet build -c $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }
}
finally {
    Pop-Location
}

# Publish to output directory
Write-Host "Publishing to $OutputPath..." -ForegroundColor Green
Push-Location ".\src"
try {
    dotnet publish -c $Configuration -o "..\$OutputPath" --no-build
    if ($LASTEXITCODE -ne 0) {
        throw "Publish failed"
    }
}
finally {
    Pop-Location
}

# Copy module manifest
Write-Host "Copying module manifest..." -ForegroundColor Green
Copy-Item ".\Microsoft-Extractor-Suite.psd1" "$OutputPath\" -Force

# Update module manifest to point to binary module
Write-Host "Updating module manifest for binary module..." -ForegroundColor Green
$manifestPath = Join-Path $OutputPath "Microsoft-Extractor-Suite.psd1"
$manifest = Get-Content $manifestPath -Raw

# Replace the RootModule from .psm1 to .dll
$manifest = $manifest -replace 'RootModule = ''Microsoft-Extractor-Suite.psm1''', 'RootModule = ''Microsoft.ExtractorSuite.dll'''

# Remove NestedModules since we're now a binary module
$manifest = $manifest -replace 'NestedModules = @\([^)]*\)', 'NestedModules = @()'

# Update RequiredAssemblies
$requiredAssemblies = @(
    'Microsoft.ExtractorSuite.dll',
    'Microsoft.Graph.dll',
    'Azure.Identity.dll',
    'Azure.Core.dll',
    'Microsoft.Identity.Client.dll',
    'Newtonsoft.Json.dll',
    'CsvHelper.dll'
)
$assembliesString = ($requiredAssemblies | ForEach-Object { "'$_'" }) -join ", "
$manifest = $manifest -replace 'RequiredAssemblies = @\(\)', "RequiredAssemblies = @($assembliesString)"

# Save updated manifest
$manifest | Set-Content $manifestPath -Encoding UTF8

# Copy Templates folder
if (Test-Path ".\Templates") {
    Write-Host "Copying Templates folder..." -ForegroundColor Green
    Copy-Item ".\Templates" "$OutputPath\" -Recurse -Force
}

# Create a test script
Write-Host "Creating test script..." -ForegroundColor Green
$testScript = @'
# Test script for Microsoft-Extractor-Suite binary module
$modulePath = Join-Path $PSScriptRoot "Microsoft-Extractor-Suite.psd1"

Write-Host "Importing module from: $modulePath" -ForegroundColor Cyan
Import-Module $modulePath -Force -Verbose

Write-Host "`nAvailable commands:" -ForegroundColor Green
Get-Command -Module Microsoft-Extractor-Suite | Format-Table Name, CommandType

Write-Host "`nModule information:" -ForegroundColor Green
Get-Module Microsoft-Extractor-Suite | Format-List

Write-Host "`nTesting Connect-M365 help:" -ForegroundColor Green
Get-Help Connect-M365

Write-Host "`nModule imported successfully!" -ForegroundColor Green
Write-Host "You can now test commands like:" -ForegroundColor Yellow
Write-Host "  Connect-M365" -ForegroundColor Yellow
Write-Host "  Get-UAL -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)" -ForegroundColor Yellow
Write-Host "  Disconnect-M365" -ForegroundColor Yellow
'@

$testScript | Set-Content "$OutputPath\Test-Module.ps1" -Encoding UTF8

Write-Host "`nBuild completed successfully!" -ForegroundColor Green
Write-Host "Output location: $OutputPath" -ForegroundColor Cyan
Write-Host "To test the module, run: $OutputPath\Test-Module.ps1" -ForegroundColor Yellow