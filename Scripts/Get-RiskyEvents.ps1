# Check if $PSScriptRoot is set
if (-not $PSScriptRoot) {
    $PSScriptRoot = $MyInvocation->MyCommand->ScriptBlock->File
}

# Load required module
try {
    Import-Module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"
} catch {
    Write-LogFile "Failed to import required module. Error: $_" -Color "Red"
    return
}

# Test if the user is connected to the required services
function Test-IsConnected {
    [CmdletBinding()]
    param()

    try {
        Get-MgUser -Top 1
        return $true
    } catch {
        return $false
    }
}

# Write log messages with better color coding
function Write-LogFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Color = "White"
    )

    Write-Host "$(Get-Date) [$Color]$Message[/]$($Host.UI.RawUI.BackgroundColor)"
}

# Write output to a file with better error handling
function Write-OutputFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Output,
        [string]$Content,
        [string]$Encoding = "UTF8"
    )

    try {
        $OutputDir = Split-Path $Output -Parent
        if (-not (Test-Path $OutputDir)) {
            New-Item -ItemType Directory -Force -Path $OutputDir
        }
        $Content | Out-File -FilePath $Output -Encoding $Encoding -Force -ErrorAction Stop
    } catch {
        Write-LogFile "Failed to write output to $Output. Error: $_" -Color "Red"
    }
}

# Convert objects to strings with better formatting
function ConvertTo-String {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [object]$InputObject
    )

    if ($InputObject -is [string]) {
        return $InputObject
    }

    if ($InputObject -is [hashtable]) {
        return $InputObject.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
    }

    if ($InputObject -is [array]) {
        return $InputObject -join ", "
    }

    return $InputObject.ToString()
}

# Convert location objects to strings with better formatting
function ConvertTo-Location {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [object]$Location
    )

    if ($Location -eq $null) {
        return ""
    }

    return "$($Location.City), $($Location.StateOrProvince), $($Location.CountryOrRegion), $($Location.PostalCode)"
}

# Convert additional properties to strings with better formatting
function ConvertTo-AdditionalProperties {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [object]$AdditionalProperties
    )

    if ($AdditionalProperties -eq $null) {
        return ""
    }

    $Properties = $AdditionalProperties.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
    return $Properties -join ", "
}

# Get risky users
function Get-RiskyUsers {
    [CmdletBinding()]
    param (
        [string]$OutputDir = "Output\UserInfo",
        [string]$Encoding = "UTF8",
        [switch]$Application,
        [switch]$Verbose
    )

    # Check if the user is connected
    if (-not (Test-IsConnected)) {
        Write-LogFile "Please connect to the required services before running this command." -Color "Red"
        return
    }

    # Write log message
    if ($Verbose) {
        Write-LogFile "[INFO] Running Get-RiskyUsers" -Color "Green"
    }

    $results = @()
    $count = 0

    try {
        Get-MgRiskyUser -All | ForEach-Object {
            $myObject = [PSCustomObject]@{
                History                           = "-"
                Id                                = "-"
                IsDeleted                         = "-"
                IsProcessing                      = "-"
                RiskDetail                        = "-"
                RiskLastUpdatedDateTime           = "-"
                RiskLevel                         = "-"
                RiskState                         = "-"
                UserDisplayName                   = "-"
                UserPrincipalName                 = "-"
                AdditionalProperties              = "-"
            }

            $myobject.History = $_.History
            $myobject.Id = $_.Id
            $myobject.IsDeleted = $_.IsDeleted
            $myobject.IsProcessing = $_.IsProcessing
            $myobject.RiskDetail = $_.RiskDetail
            $myobject.RiskLastUpdatedDateTime = $_.RiskLastUpdatedDateTime
            $myobject.RiskLevel = $_.RiskLevel
            $myobject.RiskState = $_.RiskState
            $myobject.UserDisplayName = $_.UserDisplayName
            $myobject.UserPrincipalName = $_.UserPrincipalName
            $myobject.AdditionalProperties = ConvertTo-AdditionalProperties $_.AdditionalProperties

            $results += $myObject
            $count++
        }
    } catch {
        Write-LogFile "Failed to get risky users. Error: $_" -Color "Red"
        return
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-RiskyUsers.csv"
    Write-OutputFile -Output $filePath -Content ($results | ConvertTo-Csv -NoTypeInformation) -Encoding $Encoding

    Write-LogFile "[INFO] A total of $count risky users found"
    Write-LogFile "[INFO] Output written to $filePath" -Color "Green"
}

# Get risky detections
function Get-RiskyDetections {
    [CmdletBinding()]
    param (
        [string]$OutputDir = "Output\UserInfo",
        [string]$Encoding = "UTF8",
        [switch]$Application,
        [switch]$Verbose
    )

    # Check if the user is connected
    if (-not (Test-IsConnected)) {
        Write-LogFile "Please connect to the required services before running this command." -Color "Red"
        return
    }

    # Write log message
    if ($Verbose) {
        Write-LogFile "[INFO] Running Get-RiskyDetections" -Color "Green"
    }

    $results = @()
    $count = 0

    try {
        Get-MgRiskDetection -All | ForEach-Object {
            $myObject = [PSCustomObject]@{
                Activity                        = "-"
                ActivityDateTime                = "-"
                AdditionalInfo                  = "-"
                CorrelationId                   = "-"
                DetectedDateTime                = "-"
                IPAddress                       = "-"
                Id                              = "-"
                LastUpdatedDateTime             = "-"
                City                            = "-"
                CountryOrRegion                 = "-"
                State                           = "-"
                RequestId                       = "-"
                RiskDetail                      = "-"
                RiskEventType                   = "-"
                RiskLevel                       = "-"
                riskState                       = "-"
                detectionTimingType             = "-"
                Source                          = "-"
                TokenIssuerType                 = "-"
                UserDisplayName                 = "-"
                UserId                          = "-"
                UserPrincipalName               = "-"
                AdditionalProperties            = "-"
            }

            $myobject.Activity = $_.Activity
            $myobject.ActivityDateTime = $_.ActivityDateTime
            $myobject.AdditionalInfo = $_.AdditionalInfo
            $myobject.CorrelationId = $_.CorrelationId
            $myobject.DetectedDateTime = $_.DetectedDateTime
            $myobject.IPAddress = $_.IPAddress
            $myobject.Id = $_.Id
            $myobject.LastUpdatedDateTime = $_.LastUpdatedDateTime
            $myobject.City = ConvertTo-Location $_.Location
            $myobject.CountryOrRegion = ConvertTo-Location $_.Location
            $myobject.State = ConvertTo-Location $_.Location
            $myobject.RequestId = $_.RequestId
            $myobject.RiskDetail = $_.RiskDetail
            $myobject.RiskEventType = $_.RiskEventType
            $myobject.RiskLevel = $_.RiskLevel
            $myobject.riskState = $_.riskState
            $myobject.detectionTimingType = $_.detectionTimingType
            $myobject.Source = $_.Source
            $myobject.TokenIssuerType = $_.TokenIssuerType
            $myobject.UserDisplayName = $_.UserDisplayName
            $myobject.UserId = $_.UserId
            $myobject.UserPrincipalName = $_.UserPrincipalName
            $myobject.AdditionalProperties = ConvertTo-AdditionalProperties $_.AdditionalProperties

            $results += $myObject
            $count++
        }
    } catch {
        Write-LogFile "Failed to get risky detections. Error: $_" -Color "Red"
        return
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-RiskyDetections.csv"
    Write-OutputFile -Output $filePath -Content ($results | ConvertTo-Csv -NoTypeInformation) -Encoding $Encoding

    Write-LogFile "[INFO] A total of $count risky detections found"
    Write-LogFile "[INFO] Output written to $filePath" -Color "Green"
}

