using "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

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
    [datetime]$startDate = (date).AddDays(-30).ToString('yyyy-MM-ddT00:00:00'), #'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    [datetime]$endDate = [datetime]::Now.ToString('yyyy-MM-ddT00:00:00'), ,
    [string]$OutputDir = "$((pwd).path)\Output\",
    [string]$UserIds,
    [string]$Encoding = 'UTF8',
    [switch]$Application,
    [switch]$MergeOutput
)

if ([string]::IsNullOrWhiteSpace($OutputDir.Split('\')[0])){mkdir -Force $OutputDir>$null}

# Test if connected to graph with correct scopes
$scopes = @('AuditLog.Read.All', 'Directory.Read.All')
if (-not $connected = $scopes -eq (get-mgcontext).Scopes)
{
    Assert-False -Message "Failed to connect to the correct scopes: $scopes"
    Connect-MgGraph -Scopes $scopes -NoWelcome >> null
}



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

$baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?'
$queryParameters = @()
if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
$filterQuery = $queryParameters -join ' and '
$apiUrl = "$baseUri``$filterQuery"

    try
    {
        Do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $baseUri -ContentType 'application/json' ;
            $logs = $response;
            $date = [datetime]::Now.ToString('yyyy-MM-ddTHH:mm:ss');
            $filePath = "ADSignInLogsGraph.json"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM ;
            Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green;
            $baseUri= $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        } While ($response.'@odata.nextLink')
    }
    catch [Exception]
    {
        Write-Error "Error fetching data: $_"
    }
    finally
    {
        # Clean up resources explicitly after the loop
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
    
    if ($MergeOutput)
    {
        try
        {
            Write-Host '[INFO] Merging output files...' -ForegroundColor Green ;
            $mergedFile="ADSignInLogsGraph-Combined.json"
            Merge-OutputFiles -OutputDir $OutputDir -Encoding $Encoding -mergedFile $mergedFile
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
}

function Merge-OutputFiles
{
    param(
        [string]$OutputDir,
        [string]$Encoding,
        [string]$mergedFile,
    )
    
    $mergedFilePath = Join-Path -Path $OutputDir -ChildPath $mergedFile
    
    $allLogs = Get-ChildItem -Path $OutputDir -Filter '*.json' | ForEach-Object {
        $content = [System.IO.File]::ReadAllText($_.FullName)
        [System.Text.Json.JsonSerializer]::Deserialize($content, [object].GetType())
    }
    
    $jsonOutput = [System.Text.Json.JsonSerializer]::Serialize($allLogs, [object].GetType(), [System.Text.Json.JsonSerializer]::GetOptions())
    [System.IO.File]::WriteAllText($mergedFilePath, $jsonOutput, [System.Text.Encoding]::$Encoding)
    
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
        [datetime]$startDate = (date).AddDays(-30).ToString('yyyy-MM-ddT00:00:00'), #'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        [datetime]$endDate = [datetime]::Now.ToString('yyyy-MM-ddT00:00:00'), ,
        [string]$OutputDir = "$((pwd).path)\Output\",
        [string]$UserIds,
        [string]$Encoding = 'UTF8'
    )

    #https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime -lt 2024-05-15T20:39:51 and activityDateTime -ge 2024-04-15T20:39:51 and initiatedBy/user/id eq c@lvin.ie

    $baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?'#`$filter=activityDateTime+-lt+2024-05-15T20:39:51+and+activityDateTime+-ge+2024-04-15T20:39:51+and+initiatedBy/user/id+eq+c@lvin.ie'
    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
    if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri``$filterQuery"

    try
    {
        Do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $baseUri -ContentType 'application/json' ;
            $logs = $response;
            $date = [datetime]::Now.ToString('yyyy-MM-ddTHH:mm:ss');
            $filePath = "AuditlogsGraph.json";
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM ;
            Write-Host "[INFO] Audit logs written to $filePath" -ForegroundColor Green ;
            $baseUri= $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        } While ($response.'@odata.nextLink')
    }
    catch
    {
        Write-Error "Error fetching data: $_"
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


