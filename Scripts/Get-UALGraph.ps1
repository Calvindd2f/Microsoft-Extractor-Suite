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
    }
}

Function Print-Usage {
    [CmdletBinding()]
    param()

    Write-Host "Usage: .\Get-UALGraph.ps1 -SearchName <searchName> [-StartDate <startDate>] [-EndDate <endDate>] [-RecordType <RecordType>] [-Keyword <Keyword>] [-Service <Service>] [-Operations <Operations>] [-UserIds <UserIds>] [-IPAddress <IPAddress>] [-OutputDir <OutputDir>] [-Encoding <Encoding>] [-Application]"
}

Function Get-UALGraph 
{
    [CmdletBinding()]
    param(
		[Parameter(Mandatory=$true)]
        [string]$SearchName,

        [switch]$Application,

        [string]$OutputDir = "Output\UnifiedAuditLog",

        [string]$Encoding = "UTF8",

        [datetime]$StartDate,

		[datetime]$EndDate,

        [string[]]$RecordType = @(),

        [string]$Keyword = "",

        [string]$Service = "",

        [string[]]$Operations = @(),

        [string[]]$UserIds = @(),

        [string[]]$IPAddress = @()
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph
    }

    if (![Is-MgGraphConnected]) {
        Write-Error "[ERROR] You must call Connect-MgGraph -Scopes 'AuditLogsQuery.Read.All' before running this script"
        return
    }

    if ($StartDate -and $EndDate -and $EndDate -lt $StartDate) {
        Write-Error "[ERROR] EndDate must be later than StartDate"
        return
    }

    $startDateParam = if ($StartDate) { $StartDate.ToString("yyyy-MM-ddTHH:mm:ssZ") }
    $endDateParam = if ($EndDate) { $EndDate.ToString("yyyy-MM-ddTHH:mm:ssZ") }

    $params = @{
        "@odata.type" = "#microsoft.graph.security.auditLogQuery"
        displayName = $SearchName
        filterStartDateTime = $startDateParam
        filterEndDateTime = $endDateParam
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
        "auditLogQueryId" = (Invoke-MgGraphRequest -Method POST -Uri "beta/security/auditLogs/queries" -Body ($params | ConvertTo-Json)).Id
    } | ConvertTo-Json -Compress

    $scanId = (Invoke-MgGraphRequest -Method GET -Uri "beta/security/auditLogs/queries" -Body $queryString).Id

    $response = Invoke-MgGraphRequest -Method GET -Uri "beta/security/auditLogs/queries/$scanId/results?`$top=1000"

    $outputFilePath = "$($OutputDir)\$($SearchName)_UnifiedAuditLog.json"

    $outputFileStream = [IO.File]::OpenWrite($outputFilePath)

    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $response.'@odata.nextLink'
            $response.Value | ForEach-Object {
                [System.Text.Json.JsonSerializer]::SerializeToUtf8Bytes($_) | ForEach-Object {
                    [void]$outputFileStream.Write($_)
                }
            }
        } while (-not [string]::IsNullOrEmpty($response.'@odata.nextLink'))
    }
    finally {
        $outputFileStream.Dispose()
    }

    Write-Host "[INFO] Audit log records have been saved to $outputFilePath"
}

# Check if the user called the script with the correct syntax
if ($MyInvocation.Line.Length -lt $MyInvocation.MyCommand.Definition.Length) {
    Print-Usage
    exit
}

# Call the Get-UALGraph function
Get-UALGraph @PSBoundParameters
