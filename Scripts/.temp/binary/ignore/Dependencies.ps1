#Requires -Version 5.1

<#
.SYNOPSIS
    This script verifies the required PowerShell modules used by the assessment tool are installed.
.DESCRIPTION
    Verifies a supported version of the modules required to support SCuBAGear are installed.
#>

$ErrorActionPreference = "Stop"

$requiredModulesPath = Join-Path -Path $PSScriptRoot -ChildPath "RequiredVersions.ps1"
if (-not (Test-Path -Path $requiredModulesPath)) {
    Write-Error "Unable to find required modules path at $requiredModulesPath"
    return
}

try {
    . $requiredModulesPath
} catch {
    Write-Error "Failed to load required modules: $_"
    return
}

if (-not $ModuleList -or $ModuleList.Count -eq 0) {
    throw "Required modules list is required."
}

$supportModulesPath = Join-Path -Path $PSScriptRoot -ChildPath "Modules\Support\Support.psm1"
if (-not (Test-Path -Path $supportModulesPath)) {
    Write-Error "Unable to find support modules path at $supportModulesPath"
    return
}

try {
    Import-Module -Name $supportModulesPath -Force
} catch {
    Write-Error "Failed to load support modules: $_"
    return
}

function Write-MissingModules {
    [CmdletBinding()]
    param ()

    if ($MissingModules.Count -eq 0) {
        Write-Host "All required modules are installed with supported versions." -ForegroundColor Green
        return
    }

    Write-Warning "
    The required supporting PowerShell modules are not installed with a supported version.
    Run Initialize-SCuBA to install all required dependencies.
    See Get-Help Initialize-SCuBA for more help."

    Write-Host "The following modules are not installed or have unsupported versions:" -ForegroundColor Yellow
    $MissingModules | ForEach-Object {
        Write-Host "$($_.ModuleName): $($_.ModuleVersion) to $($_.MaximumVersion)" -ForegroundColor Yellow
    }
}

$MissingModules = @()

foreach ($Module in $ModuleList) {
    Write-Debug "Evaluating module: $($Module.ModuleName)"
    $InstalledModuleVersions = Get-Module -ListAvailable -Name $($Module.ModuleName) -ErrorAction SilentlyContinue

    if ($InstalledModuleVersions -eq $null -or $InstalledModuleVersions.Count -eq 0) {
        $MissingModules += $Module
        continue
    }

    $FoundAcceptableVersion = $false

    foreach ($ModuleVersion in $InstalledModuleVersions) {
        if (($ModuleVersion.Version -ge $Module.ModuleVersion) -and ($ModuleVersion.Version -le $Module.MaximumVersion)) {
            $FoundAcceptableVersion = $true
            break
        }
    }

    if (-not $FoundAcceptableVersion) {
        $MissingModules += $Module
    }
}

Write-MissingModules

function Install-MissingModules {
    [CmdletBinding()]
    param ()

    $installedModules = @()

    foreach ($Module in $MissingModules) {
        Write-Host "Installing module: $($Module.ModuleName)" -ForegroundColor Cyan
        Install-Module -Name $Module.ModuleName -Force -AllowClobber
        $installedModules += Get-Module -Name $Module.ModuleName
    }

    if ($installedModules.Count -eq $MissingModules.Count) {
        Write-Host "All missing modules have been installed successfully." -ForegroundColor Green
    } else {
        Write-Warning "Some modules could not be installed. Please check the output and try again."
    }
}

if ($MissingModules.Count -gt 0) {
    Install-MissingModules
}
