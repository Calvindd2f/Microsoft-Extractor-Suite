using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

# This contains functions for getting Azure AD logging

function Get-ADSignInLogs
{
    [CmdletBinding()]
    param(
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        [datetime]$EndDate = Get-Date,
        [string]$OutputDir = "$PSScriptRoot\Output\",
        [string]$UserIds,
        [switch]$MergeOutput,
        [string]$Encoding = 'UTF8',
        [int]$Interval
    )

    Write-Log -Message "[INFO] Running Get-ADSignInLogs" -Color "Green"

    $dateStamp = Get-Date -Format "yyyyMMddHHmmss"
    #if ([string]::IsNullOrWhiteSpace($OutputDir.Split('\')[0])){mkdir -Force "$OutputDir\AzureAD\$date">$null}
    #if ([string]::IsNullOrEmpty($UserIds){Write-LogFile -Message "[INFO] UserIDs not specificed."}

    if (-not $UserIds)
    {
        Write-Log -Message "[INFO] UserIDs not specified."
    }

    $filePath = "$OutputDir$($dateStamp)-AuditLogSignIn.json"

    $baseUri = 'https://graph.microsoft.com/v1.0'
    # (Find-MgGraphCommand -Command Get-AzureADAuditLogSignIn).CommandI[1]
    $resourcePath = (Find-MgGraphCommand -Command Get-MgBetaAuditLogSignIn).URI[1]
    $baseUri = "$baseUri$resourcePath`?"

    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
    if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri``$filterQuery"

    try
    {
        do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
            $logs = $response
            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green
            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        } while ($response.'@odata.nextLink')
    }
    catch [Exception]
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
            $mergedFile = "$OutputDir$($dateStamp)-AuditLogSignIn-MERGED.json
            Merge-OutputFiles -OutputDir $outputDir -Encoding $Encoding -mergedFile $mergedFile
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

function Get-ADAuditLogs 
{
    [CmdletBinding()]
    param(
        [datetime]$StartDate = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddT00:00:00'),
        [datetime]$EndDate = (Get-Date).ToString('yyyy-MM-ddT00:00:00'),
        [string]$OutputDir = "$((Get-Location).Path)\Output\",
        [string]$UserIds,
        [string]$Encoding = 'UTF8'
    )

    $dateStamp = Get-Date -Format "yyyyMMddHHmmss"
    $filePath = "$OutputDir$($dateStamp)-AuditLogDirectoryAudit.json"
   
    Write-Log -Message "[INFO] Collecting the Directory Audit Logs"

    $baseUri = 'https://graph.microsoft.com/v1.0'
    #(find-MgGraphCommand -Command Get-AzureADAuditLogDirectoryAudit).Command[1] -eq Get-MgBetaAuditLogDirectoryAudit
    $resourcePath = (Find-MgGraphCommand -Command Get-MgBetaAuditLogDirectoryAudit).URI[1]
    $baseUri = "$baseUri$resourcePath`?"

    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $StartDate" }
    if ($EndDate) { $queryParameters += "activityDateTime le $EndDate" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri$filterQuery"

    try
    {
        do
        {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
            $logs = $response
            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "[INFO] Directory logs written to $filePath" -ForegroundColor Green
            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
        } while ($response.'@odata.nextLink')
    }
    catch [Exception]
    {
        Write-Error "Error fetching data: $_"
    }
    finally
    {
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
    }
    
    Write-Log -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
}