using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-AdminAuditLogs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$StartDate,

        [Parameter(Mandatory)]
        [string]$EndDate,

        [Parameter(Mandatory)]
        [string]$OutputDirectory
    )

    # Generate output file name
    $outputFileName = "{0}-AdminAuditLog.csv" -f [datetime]::Now.ToString('yyyyMMddHHmmss')
    $outputPath = Join-Path $OutputDirectory $outputFileName

    # Write log messages
    Write-LogFile -Message "[INFO] Running Get-AdminAuditLogs" -Color "Green"
    Write-LogFile -Message "[INFO] Extracting all available Admin Audit Logs between $($StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"

    # Set initial API URL
    $apiUrl = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=activityDateTime ge '$StartDate' and activityDateTime le '$EndDate'"

    # Retrieve and export audit logs
    do {
        $response = Invoke-RestMethod -Headers @{Authorization = "Bearer $token"} -Uri $apiUrl -Method Get -ContentType 'application/json'
        $auditLogs = $response.value

        if ($auditLogs) {
            $auditLogs | Export-Csv $outputPath -NoTypeInformation -Append -Encoding UTF8
            $apiUrl = $response.'@odata.nextLink'
        }
    } while ($apiUrl)

    Write-LogFile -Message "[INFO] Output is written to: $outputPath" -Color "Green"
}


#Convert this powershell Get-AdminAuditLog to use either the exchange or microsoft graph API to do tdo the operations. It needs pagination and memory management. It uses .NET objects directly from pwoershell to stream the logs into a file (csv)