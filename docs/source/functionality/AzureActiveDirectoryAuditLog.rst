<#
Azure Active Directory Audit Log
- Use Get-ADAuditLogs to collect the contents of the Azure Active Directory Audit Log.
- This GraphAPI functionality is currently in beta. If you encounter any issues or have suggestions for improvements please let us know.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [DateTime]$startDate = (Get-Date).AddDays(-7),

    [Parameter(Mandatory=$false)]
    [DateTime]$endDate = (Get-Date).AddDays(-1),

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "Output\AzureAD",

    [Parameter(Mandatory=$false)]
    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
)

# Validate startDate and endDate
if ($startDate -gt $endDate) {
    Write-Error "Error: startDate cannot be later than endDate."
    return
}

# Create Output directory if it doesn't exist
if (!(Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir
}

# Get-ADAuditLogs function
function Get-ADAuditLogs {
    [CmdletBinding()]
    param()

    $headers = @{
        'Content-Type'  = 'application/json'
    }

    $queryParams = @{
        '$select'      = 'id,category,correlationId,result,resultReason,activityDisplayName,initiatedBy,targetResources,eventTime'
        '$filter'      = "eventTime ge $($startDate.ToString("s")) and eventTime le $($endDate.ToString("s"))"
    }

    $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits" `
        -Headers $headers `
        -Method Get `
        -Query $queryParams

    return $response.value
}

# Call Get-ADAuditLogs function
$auditLogs = Get-ADAuditLogs

# Save output to JSON file
$jsonOutput = $auditLogs | ConvertTo-Json
Set-Content -Path (Join-Path -Path $OutputDir -ChildPath "AuditLogs.json") -Value $jsonOutput -Encoding $Encoding

Write-Host "Azure Active Directory Audit Log saved to $(Join-Path -Path $OutputDir -ChildPath "AuditLogs.json")"
