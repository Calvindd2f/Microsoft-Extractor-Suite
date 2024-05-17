using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-ADSignInLogs
{
    [CmdletBinding()]
    param(
        [datetime]$StartDate = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddT00:00:00'),
        [datetime]$EndDate = Get-Date.ToString('yyyy-MM-ddT00:00:00'),
        [string]$OutputDirectory = "$((Get-Location).Path)\Output\",
        [string]$UserIds,
        [string]$Encoding = 'UTF8',
        [switch]$Application,
        [switch]$MergeOutput
    )
    
    #if ([string]::IsNullOrWhiteSpace($OutputDir.Split('\')[0])){mkdir -Force $OutputDir>$null}
    $requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All')
    if (!(Get-MgContext).Scopes -contains $requiredScopes)
    {
        try
        {
            Connect-MgGraph -Scopes $requiredScopes
        }
        catch
        {
            throw $_.Exception
        }
    }
    
    $baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?'
    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
    if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri$filterQuery"
    
    try
    {
        Do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $baseUri -ContentType 'application/json'
            $logs = $response
            $date = Get-Date.ToString('yyyy-MM-ddTHH:mm:ss')
            $filePath = "ADSignInLogsGraph.json"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green
            $baseUri = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
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
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
    
    if ($MergeOutput)
    {
        try
        {
            Write-Host '[INFO] Merging output files...' -ForegroundColor Green
            $mergedFile = "ADSignInLogsGraph-Combined.json"
            Merge-OutputFiles -OutputDirectory $OutputDirectory -Encoding $Encoding -MergedFile $mergedFile
        }
        catch
        {
            Write-Error "Error merging files: $_" -ForegroundColor Red
        }
        finally
        {
            Write-Host '[INFO] Process completed.' -ForegroundColor Green
        }
    }
}

function Get-ADAuditLogsGraph
{
    [CmdletBinding()]
    param(
        [datetime]$StartDate = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddT00:00:00'),
        [datetime]$EndDate = (Get-Date).ToString('yyyy-MM-ddT00:00:00'),
        [string]$OutputDirectory = Join-Path -Path (Get-Location).Path -ChildPath "Output\",
        [string]$UserIds,
        [string]$Encoding = 'UTF8'
    )

    $baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?'
    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
    if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri$filterQuery"

    try
    {
        Do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $baseUri -ContentType 'application/json'
            $logs = $response
            $filePath = "AuditlogsGraph.json"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "[INFO] Audit logs written to $filePath" -ForegroundColor Green
            $baseUri = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
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


