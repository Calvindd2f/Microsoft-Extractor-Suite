# Get-MailboxAuditLog.ps1

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string[]]$UserIds,

    [Parameter()]
    [datetime]$StartDate,

    [Parameter()]
    [datetime]$EndDate
)

if ($StartDate -and $EndDate) {
    $auditLogs = Search-MailboxAuditLog -Identity $UserIds -LogonTypes Delegated -ShowDetails -StartDate $StartDate -EndDate $EndDate
}
else {
    $auditLogs = Search-MailboxAuditLog -Identity $UserIds -LogonTypes Delegated -ShowDetails
}

$auditLogs | Format-Table -AutoSize
