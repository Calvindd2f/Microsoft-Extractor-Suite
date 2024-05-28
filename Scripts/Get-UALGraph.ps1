using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

Function Connect-MgGraph {
    [CmdletBinding()]
    param()

    try {
        Connect-MgGraph -Scopes AuditLogsQuery.Read.All -NoWelcome
    }
    catch {
        Write-Error "[ERROR] Failed to connect to Microsoft Graph: $_"
    }
}

Function Is-MgGraphConnected {
    [CmdletBinding()]
    param()

    try {
        Get-MgBetaSecurityAuditLogQuery -ErrorAction stop
        return $true
    }
    catch {
        return $false

