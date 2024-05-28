function Get-ADSignInLogsGraph
{
    <#
    .SYNOPSIS
        Gets Azure AD sign-in logs with pagination.
    .DESCRIPTION
        Collects the contents of the Azure Active Directory sign-in logs using the GraphAPI with pagination.
        Outputs are written to a specified directory.
    .PARAMETER startDate
        Specifies the date from which all logs need to be collected.
    .PARAMETER endDate
        Specifies the end date until which all logs need to be collected.
    .PARAMETER OutputDir
        Specifies the output directory. Default: "Output\AzureAD"
    .PARAMETER Encoding
        Specifies the encoding of the JSON output file. Default: UTF8
    .PARAMETER Application
        Specifies App-only access for authentication and authorization.
        Default: Delegated access (access on behalf a user)
    .PARAMETER MergeOutput
        Specifies if output files should be merged into a single file. Default: No
    .PARAMETER UserIds
        Filters log entries by the user account that performed the actions.
    .EXAMPLE
        Get-ADSignInLogsGraph
        Retrieves all sign-in logs.
    .EXAMPLE
        Get-ADSignInLogsGraph -endDate '2023-04-12'
        Retrieves sign-in logs until 2023-04-12.
    #>
[CmdletBinding()]
param(
    [string]$startDate,
    [string]$endDate,
    [string]$OutputDir = 'Output\AzureAD',
    [string]$UserIds,
    [string]$Encoding = 'UTF8',
    [switch]$Application,
    [switch]$MergeOutput
)

if ([string]::IsNullOrWhiteSpace($OutputDir.Split('\')[0])){mkdir -Force $OutputDir>$null}


# Test if connected to graph with correct scopes

try {
    if([string]::IsNullOrEmpty($scopes))
    {
        $scopes=@('AuditLog.Read.All','Directory.Read.All')
    }
    foreach ($s in $scopes){
        if ((get-mgcontext).Scopes -match $s)
        {
            $connected -eq $true
        }
        else{
            $connected -eq $false
        }
    }
catch {
   [ex
}
finally {
   <#Do this after the try block regardless of whether an exception occurred or not#>
}
Connect-MgGraph -Scopes 'AuditLog.Read.All', 'Directory.Read.All' -NoWelcome


$queryFilter = @()
if ($startDate)
{
    $queryFilter += "createdDateTime ge '$startDate'"
}
if ($endDate)
{
    $queryFilter += "createdDateTime le '$endDate'"
}
if ($UserIds)
{
    $queryFilter += "userPrincipalName eq '$UserIds'"
}

$apiUri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns'
$filter = $queryFilter -join ' and '
$params = @{
    Uri    = "$apiUri`?`$filter=$filter"
    Method = 'GET'
}
    try
    {
        Do
        {
            $response = Invoke-MgGraphRequest @params
            $logs = $response.Content | ConvertFrom-Json

            $date = Get-Date -Format 'yyyyMMddHHmmss'
            $filePath = Join-Path -Path $OutputDir -ChildPath "$($date)-SignInLogsGraph.json"
            $logs.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding

            Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green

            $params.Uri = $response.'@odata.nextLink'

            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        } While ($response.'@odata.nextLink')

        if ($MergeOutput)
        {
            Merge-OutputFiles -OutputDir $OutputDir -Encoding $Encoding
        }
    }
    catch
    {
        Write-Error "Error fetching data: $_" -ForegroundColor Red
    }
    finally
    {
        Write-Host '[INFO] Process completed.' -ForegroundColor Green
    }
}

function Merge-OutputFiles
{
    param(
        [string]$OutputDir,
        [string]$Encoding
    )
    $mergedFilePath = Join-Path -Path $OutputDir -ChildPath 'SignInLogs-Combined.json'
    $allLogs = Get-ChildItem -Path $OutputDir -Filter '*.json' |
    Get-Content -Raw | ConvertFrom-Json

    $allLogs | ConvertTo-Json -Depth 100 | Set-Content -Path $mergedFilePath -Encoding $Encoding
    Write-Host "[INFO] All logs merged into $mergedFilePath" -ForegroundColor Green
}

function Get-ADAuditLogsGraph
{
    <#
    .SYNOPSIS
        Get directory audit logs using direct API calls.
    .DESCRIPTION
        Uses direct API calls to fetch the contents of the Azure Active Directory Audit logs using RESTful endpoints.
        Outputs are written to "Output\AzureAD\AuditlogsGraph.json"
    .PARAMETER StartDate
        Specifies the date from which logs should be collected.
    .PARAMETER EndDate
        Specifies the end date until which logs should be collected.
    .PARAMETER OutputDir
        Specifies the output directory.
        Default: "Output\AzureAD"
    .PARAMETER UserIds
        Filters the log entries by the account of the user who performed the actions.
    .PARAMETER Encoding
        Specifies the encoding of the JSON output file.
        Default: "UTF8"
    #>
    [CmdletBinding()]
    param(
        [string]$StartDate,
        [string]$EndDate,
        [string]$OutputDir = 'Output\AzureAD',
        [string]$UserIds,
        [string]$Encoding = 'UTF8'
    )

    #Assert-OutputDir

    $baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits'
    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
    if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri?$filterQuery"

    try
    {
        Do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl
            $logs = $response.Content | ConvertFrom-Json

            $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
            $filePath = Join-Path $OutputDir "$($date)-AuditlogsGraph.json"
            $logs.value | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
            Write-Host "[INFO] Audit logs written to $filePath" -ForegroundColor Green

            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()  # Manage memory by forcing garbage collection
            [System.GC]::WaitForPendingFinalizers()
        } While ($response.'@odata.nextLink')
    }
    catch
    {
        Write-Error "Error fetching data: $_" -ForegroundColor Red
    }
    finally
    {
        # Clean up resources explicitly after the loop
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}


