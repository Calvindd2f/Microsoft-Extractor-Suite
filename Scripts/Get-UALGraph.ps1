Function Get-UnifiedAuditLogGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$SearchName,
        [switch]$Application,
        [string]$OutputDir = "Output\UnifiedAuditLog",
        [string]$Encoding = "UTF8",
        [string]$StartDate,
        [string]$EndDate,
        [string[]]$RecordTypes = @(),
        [string]$Keyword = "",
        [string]$Service = "",
        [string[]]$Operations = @(),
        [string[]]$UserIds = @(),
        [string[]]$IPAddresses = @(),
        [string]$OutputDir = "Output\UnifiedAuditLog",
        [string]$OutFormat = "CSV",
        [string]$OutEncoding = "UTF8",
        [AllowNull()]
        [int]$Interval,
        [switch]$MergeOutput,
        [switch]$Application
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes AuditLogsQuery.Read.All -NoWelcome
    }

    try {
        $null = Get-MgBetaSecurityAuditLogQuery -ErrorAction stop
    }
    catch {
        Write-Error "You must call Connect-MgGraph -Scopes 'AuditLogsQuery.Read.All' before running this script"
        break
    }

    $StartDate = [DateTime]::Today.AddDays(-90) if (!$StartDate)
    $EndDate = [DateTime]::Now if (!$EndDate)

    $params = @{
        "@odata.type" = "#microsoft.graph.security.auditLogQuery"
        DisplayName = $SearchName
        FilterStartDateTime = $StartDate
        FilterEndDateTime = $EndDate
        RecordTypeFilters = $RecordTypes
        KeywordFilter = $Keyword
        ServiceFilter = $Service
        OperationFilters = $Operations
        UserPrincipalNameFilters = $UserIds
        IPAddressFilters = $IPAddresses
        ObjectIdFilters = @()
        AdministrativeUnitIdFilters = @()
        Status = ""
    }

    $queryString = $params | ConvertTo-Json -Compress

    do {
        $auditLogQuery = Invoke-MgGraphRequest -Method GET -Uri "beta/security/auditLogs/queries/$($startScan.Id)"

        if ($auditLogQuery.Status -eq "running") {
            Start-Sleep -Seconds 10
        }
        elseif ($auditLogQuery.Status -eq "failed") {
            Write-Error "Unified Audit Log search failed."
            break
        }
        elseif ($auditLogQuery.Status -eq "succeeded") {
            $customObjects = Fetch-AuditLogRecords -ScanId $startScan.Id -Encoding $Encoding -OutputDir $OutputDir
            ConvertTo-Json -InputObject $customObjects -Depth 100 | Out-File -FilePath "$OutputDir\$($date)-$SearchName-UnifiedAuditLog.json" -Encoding $Encoding
            break
        }
        else {
            Start-Sleep -Seconds 10
        }
    } while ($true)
}

Function Fetch-AuditLogRecordsGraph {
    param(
        [string]$ScanId,
        [string]$Encoding,
        [string]$OutputDir
    )

    $customObjects = @()
    $pageSize = 1000
    $nextLink = "beta/security/auditLogs/queries/$ScanId/results?`$top=$pageSize"

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink
        $customObjects += $response.Value | ForEach-Object {
            [PSCustomObject]@{
                AdministrativeUnits = $_.AdministrativeUnits
                AuditData = $_.AuditData
                AuditLogRecordType = $_.AuditLogRecordType
                ClientIP = $_.ClientIP
                CreatedDateTime = $_.CreatedDateTime
                Id = $_.Id
                ObjectId = $_.ObjectId
                Operation = $_.Operation
                OrganizationId = $_.OrganizationId
                Service = $_.Service
                UserId = $_.UserId
                UserPrincipalName = $_.UserPrincipalName
                UserType = $_.UserType
                AdditionalProperties = $_.AdditionalProperties
            }
        }

        if ($response.'@odata.nextLink') {
            $nextLink = $response.'@odata.nextLink'
        }
        else {
            $nextLink = $null
        }
    } while ($nextLink)

    $customObjects
}
