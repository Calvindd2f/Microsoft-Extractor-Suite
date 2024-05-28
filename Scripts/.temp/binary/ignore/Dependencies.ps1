#Requires -Version 5.1

<#
.SYNOPSIS
    This script verifies the required PowerShell modules used by the assessment tool are installed.
.PARAMETER Force
    This will cause all required dependencies to be installed and updated to latest.
.DESCRIPTION
    Verifies a supported version of the modules required to support SCuBAGear are installed.
#>

$RequiredModulesPath = Join-Path -Path $PSScriptRoot -ChildPath "RequiredVersions.ps1"

if (-not (Test-Path -Path $RequiredModulesPath)) {
    Write-Error "Unable to find required modules path at $RequiredModulesPath"
    return
}

. $RequiredModulesPath

if (-not $ModuleList -or $ModuleList.Count -eq 0) {
    throw "Required modules list is required."
}

$SupportModulesPath = Join-Path -Path $PSScriptRoot -ChildPath "Modules\Support\Support.psm1"
Import-Module -Name $SupportModulesPath -Force

$MissingModules = @()

foreach ($Module in $ModuleList) {
    Write-Debug "Evaluating module: $($Module.ModuleName)"
    $InstalledModuleVersions = Get-Module -ListAvailable -Name $($Module.ModuleName)

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

if ($MissingModules.Count -gt 0) {
    # Set preferences for writing messages
    $PreferenceStack = New-Object -TypeName System.Collections.Stack
    $PreferenceStack.Push($WarningPreference)
    $WarningPreference = "Continue"

    Write-Warning "
    The required supporting PowerShell modules are not installed with a supported version.
    Run Initialize-SCuBA to install all required dependencies.
    See Get-Help Initialize-SCuBA for more help."

    Write-Debug "The following modules are not installed or have unsupported versions:"

    foreach ($Module in $MissingModules) {
        Write-Debug "`t$($Module.ModuleName) (required version: $($Module.ModuleVersion) to $($Module.MaximumVersion)))"
    }

    $WarningPreference = $PreferenceStack.Pop()
}
