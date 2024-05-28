using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

Function Get-UALGraph 
{
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]$searchName,
        [switch]$Application,
        [string]$OutputDir = "Output\UnifiedAuditLog",
        [string]$Encoding = "UTF8",
        [string]$startDate,
		[string]$endDate,
        [string[]]$RecordType = @(),
        [string]$Keyword = "",
        [string]$Service = "",
        [string[]]$Operations = @(),
        [string[]]$UserIds = @(),
        [string[]]$IPAddress = @()
    )

    if (!($Application.IsPresent)) {
        try {
            Connect-MgGraph -Scopes AuditLogsQuery.Read.All -NoWelcome
        }
        catch {
            Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes 'AuditLogsQuery.Read.All' before running this script" -Color "Red"
            break
        }
    }

    try {
        $areYouConnected = Get-MgBetaSecurityAuditLogQuery -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[ERROR] Failed to connect to Microsoft Graph API. $_" -Color "Red"
        break
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir
    }

    $script:startTime = Get-Date

    $params = @{
        "@odata.type" = "#microsoft.graph.security.auditLogQuery"
        displayName = $searchName
        filterStartDateTime = $script:startDate
        filterEndDateTime = $script:endDate
        recordTypeFilters = $RecordType
        keywordFilter = $Keyword
        serviceFilter = $Service
        operationFilters = $Operations
        userPrincipalNameFilters = $UserIds
        ipAddressFilters = $IPAddress
        objectIdFilters = @()
        administrativeUnitIdFilters = @()
        status = ""
    }

    $queryString = @{
        "auditLogQueryId" = (Invoke-MgGraphRequest -Uri "beta/security/auditLogs/queries" -Method POST -Body $params | Select-Object -ExpandProperty Id)
    } | ConvertTo-Json -Compress

    $startScan = Invoke-MgGraphRequest -Method GET -Uri "beta/security/auditLogs/queries/$($queryString.auditLogQueryId)"

    if ($startScan.Status -eq "succeeded") {
        DownloadUAL -scanId $queryString.auditLogQueryId -searchName $searchName -Encoding $Encoding -OutputDir $OutputDir
    }
    else {
        Write-logFile -Message "[ERROR] Failed to start Unified Audit Log search. $_" -Color "Red"
    }
}

Function DownloadUAL($scanId, $searchName, $Encoding, $OutputDir) {
    $date = Get-Date -Format "yyyyMMddHHmm"
    $outputFilePath = "$($date)-$searchName-UnifiedAuditLog.json"

    $pageSize = 1000
    $nextLink = "beta/security/auditLogs/queries/$scanId/results?`$top=$pageSize"

    $outputFileStream = [IO.File]::OpenWrite("$OutputDir/$outputFilePath")
    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink
            $response.Value | ForEach-Object {
                [System.Text.Json.JsonSerializer]::SerializeToUtf8Bytes($_) | ForEach-Object {
                    [void]$outputFileStream.Write($_)
                }
            }

            if (-not [string]::IsNullOrEmpty($response.'@odata.nextLink')) {
                $nextLink = $response.'@odata.nextLink'
            }
            else {
                $nextLink = $null
            }
        } while ($nextLink)
    }
    finally {
        $outputFileStream.Dispose()
    }

    write-logFile -Message "[INFO] Audit log records have been saved to $outputFilePath" -Color "Green"
    $endTime = Get-Date
    $runtime = $endTime - $script:startTime
    write-logFile -Message "[INFO] Total runtime (HH:MM:SS): $($runtime.Hours):$($runtime.Minutes):$($runtime.Seconds)" -Color "Green"
}

