# Get-MailboxAuditLog.ps1

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$UserIds,

    [Parameter()]
    [datetime]$StartDate,

    [Parameter()]
    [datetime]$EndDate,

    [Parameter()]
    [string]$OutputDir = "Output\MailboxAuditLog",

    [Parameter()]
    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
)

# Set default start and end dates if not provided
if (-not $StartDate) {
    $StartDate = (Get-Date).AddDays(-90)
}
if (-not $EndDate) {
    $EndDate = Get-Date
}

# Validate start and end dates
if ($StartDate -gt $EndDate) {
    Write-Error "Start date cannot be later than the end date."
    exit 1
}

# Check if mailbox audit logging is enabled for the specified users
$auditLogs = Search-MailboxAuditLog -Identity $UserIds -LogonTypes Delegated -ShowDetails -ErrorAction SilentlyContinue

if (-not $auditLogs) {
    Write-Warning "Mailbox audit logging is not enabled for one or more of the specified users."
    exit 0
}

# Search for mailbox audit logs
try {
    $auditLogs = Search-MailboxAuditLog -Identity $UserIds -LogonTypes Delegated -ShowDetails -StartDate $StartDate -EndDate $EndDate
}
catch {
    Write-Error "Error searching for mailbox audit logs: $_"
    exit 1
}

# Format and output the results
$outputFile = Join-Path -Path $OutputDir -ChildPath ("mailboxAuditLog_$($UserIds)_$(Get-Date -Format yyyy-MM-dd).csv")
$auditLogs | Format-Table -AutoSize |
    Export-Csv -Path $outputFile -Encoding $Encoding -NoTypeInformation

Write-Host "Mailbox audit log saved to $($outputFile)"
