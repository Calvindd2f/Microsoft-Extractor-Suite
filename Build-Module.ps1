#!/usr/bin/env pwsh
# Build script for Microsoft Extractor Suite
# This script builds the C# components if .NET SDK is available, or uses PowerShell scripts directly

param(
    [switch]$SkipDotNet,
    [switch]$Verbose,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

Write-Host "Microsoft Extractor Suite - Build Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$projectRoot = $PSScriptRoot
$srcPath = Join-Path $projectRoot "src"
$csprojPath = Join-Path $srcPath "Microsoft.ExtractorSuite.csproj"

# Function to check if dotnet is available
function Test-DotNetAvailable {
    try {
        $null = & dotnet --version 2>&1
        return $true
    } catch {
        return $false
    }
}

# Clean build artifacts if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    
    $cleanPaths = @(
        (Join-Path $srcPath "bin"),
        (Join-Path $srcPath "obj"),
        (Join-Path $projectRoot "bin"),
        (Join-Path $projectRoot "obj")
    )
    
    foreach ($path in $cleanPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force
            Write-Host "  Removed: $path" -ForegroundColor Gray
        }
    }
    
    Write-Host "Clean complete." -ForegroundColor Green
    Write-Host ""
}

# Check if we should build the C# components
if (-not $SkipDotNet -and (Test-Path $csprojPath)) {
    if (Test-DotNetAvailable) {
        Write-Host "Found .NET SDK. Building C# components..." -ForegroundColor Green
        
        try {
            # Restore packages
            Write-Host "Restoring NuGet packages..." -ForegroundColor Yellow
            & dotnet restore $csprojPath
            
            if ($LASTEXITCODE -ne 0) {
                throw "Package restore failed"
            }
            
            # Build the project
            Write-Host "Building project..." -ForegroundColor Yellow
            
            $buildArgs = @(
                "build",
                $csprojPath,
                "--configuration", "Release",
                "--no-restore",
                "-p:TreatWarningsAsErrors=false",
                "-p:WarningLevel=1",
                "-p:NoWarn=`"CS8600;CS8601;CS8602;CS8603;CS8604;CS8618;CS8625;CS8425;CS1591`""
            )
            
            if ($Verbose) {
                $buildArgs += "--verbosity", "detailed"
            }
            
            & dotnet @buildArgs
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ C# components built successfully!" -ForegroundColor Green
                
                # Copy output to module directory
                $outputPath = Join-Path $srcPath "bin\Release\netstandard2.0"
                $targetPath = Join-Path $projectRoot "bin"
                
                if (Test-Path $outputPath) {
                    if (-not (Test-Path $targetPath)) {
                        New-Item -ItemType Directory -Path $targetPath | Out-Null
                    }
                    
                    Copy-Item -Path (Join-Path $outputPath "*") -Destination $targetPath -Recurse -Force
                    Write-Host "✓ Build output copied to module directory" -ForegroundColor Green
                }
            } else {
                Write-Warning "C# build encountered errors. The module will use PowerShell scripts only."
                Write-Host "Run with -Verbose flag for detailed error information." -ForegroundColor Yellow
            }
            
        } catch {
            Write-Warning "Failed to build C# components: $_"
            Write-Host "The module will use PowerShell scripts only." -ForegroundColor Yellow
        }
    } else {
        Write-Warning ".NET SDK not found. Skipping C# component build."
        Write-Host "The module will use PowerShell scripts only." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To build C# components, install .NET SDK 8.0 or later from:" -ForegroundColor Cyan
        Write-Host "  https://dotnet.microsoft.com/download" -ForegroundColor White
    }
} else {
    Write-Host "Skipping C# component build (using PowerShell scripts only)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Verifying module structure..." -ForegroundColor Yellow

# Check required files
$requiredFiles = @(
    "Microsoft-Extractor-Suite.psd1",
    "Microsoft-Extractor-Suite.psm1"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $projectRoot $file
    if (-not (Test-Path $filePath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Error "Missing required files: $($missingFiles -join ', ')"
    exit 1
}

# Check Scripts directory
$scriptsPath = Join-Path $projectRoot "Scripts"
if (Test-Path $scriptsPath) {
    $scriptCount = (Get-ChildItem -Path $scriptsPath -Filter "*.ps1").Count
    Write-Host "✓ Found $scriptCount PowerShell scripts" -ForegroundColor Green
} else {
    Write-Warning "Scripts directory not found"
}

# Check Templates directory
$templatesPath = Join-Path $projectRoot "Templates"
if (Test-Path $templatesPath) {
    $templateCount = (Get-ChildItem -Path $templatesPath -Filter "*.json" | Where-Object { $_.Name -notlike "*.schema.json" }).Count
    Write-Host "✓ Found $templateCount template files" -ForegroundColor Green
} else {
    Write-Warning "Templates directory not found"
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Run './Import-Module.ps1' to import the module" -ForegroundColor White
Write-Host "  2. Run 'Connect-M365' to connect to Microsoft 365" -ForegroundColor White
Write-Host "  3. Use the various Get-* cmdlets to collect data" -ForegroundColor White
Write-Host ""

# Create a simple test script
$testScriptPath = Join-Path $projectRoot "Test-Module.ps1"
if (-not (Test-Path $testScriptPath)) {
    @'
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
'@ | Set-Content -Path $testScriptPath
    
    Write-Host "Created Test-Module.ps1 for quick testing" -ForegroundColor Gray
}