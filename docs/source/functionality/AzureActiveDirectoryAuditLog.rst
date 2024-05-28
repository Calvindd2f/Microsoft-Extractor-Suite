<#
Azure Active Directory Audit Log
- Use Get-ADAuditLogs to collect the contents of the Azure Active Directory Audit Log.
- This GraphAPI functionality is currently in beta. If you encounter any issues or have suggestions for improvements please let us know.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$false)]
    [DateTime]$startDate = (Get-Date).AddDays(-7),

    [Parameter(Mandatory=$false)]
    [DateTime]$endDate = (Get-Date),

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "Output\AzureAD",

    [Parameter(Mandatory=$false)]
    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
)

# Validate startDate and endDate
if ($startDate -gt $endDate) {
    Write-Error "Start date cannot be later than the end date."
    exit 1
}

# Create output directory if it doesn't exist
if (!(Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir
}

# Get the Azure Active Directory Audit Log
$auditLogs = Get-ADAuditLogs -StartDate $startDate -EndDate $endDate

# Check if any logs were found
if ($auditLogs -eq $null -or $auditLogs.Count -eq 0) {
    Write-Warning "No audit logs found within the specified date range."
    exit 0
}

# Convert the audit logs to JSON
$json = $auditLogs | ConvertTo-Json

# Save the JSON to a file
$outputFile = "$OutputDir\AuditLogs_$(Get-Date -Format yyyy-MM-dd).json"
$json | Out-File -FilePath $outputFile -Encoding $Encoding

Write-Host "Audit logs saved to $outputFile"
