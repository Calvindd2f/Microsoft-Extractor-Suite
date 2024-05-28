using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-ADSignInLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        [Parameter(Mandatory=$false)]
        [datetime]$EndDate = Get-Date,
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = "$((Get-Location).Path)\Output\",
        [Parameter(Mandatory=$false)]
        [string]$UserIds,
        [Parameter(Mandatory=$false)]
        [string]$Encoding = 'UTF8',
        [Parameter(Mandatory=$false)]
        [switch]$Application,
        [Parameter(Mandatory=$false)]
        [switch]$MergeOutput
    )

    $requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All')
    EnsureScopes $requiredScopes

    $baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?'
    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $($StartDate.ToString('yyyy-MM-ddTHH:mm:ss'))" }
    if ($EndDate) { $queryParameters += "activityDateTime le $($EndDate.ToString('yyyy-MM-ddTHH:mm:ss'))" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri$filterQuery"

    try {
        Do {
            $response = Invoke-MgGraphRequest -Method Get -Uri $baseUri -ContentType 'application/json'
            $logs = $response
            $filePath = "ADSignInLogsGraph.json"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green
            $baseUri = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        } While ($response.'@odata.nextLink')
    }
    catch {
        Write-Error "Error fetching data: $_"
    }
    finally {
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }

    if ($MergeOutput) {
        try {
            Write-Host '[INFO] Merging output files...' -ForegroundColor Green
            $mergedFile = "ADSignInLogsGraph-Combined.json"
            Merge-OutputFiles -OutputDirectory $OutputDirectory -Encoding $Encoding -MergedFile $mergedFile
        }
        catch {
            Write-Error "Error merging files: $_" -ForegroundColor Red
        }
        finally {
            Write-Host '[INFO] Process completed.' -ForegroundColor Green
        }
    }
}

function Get-ADAuditLogsGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        [Parameter(Mandatory=$false)]
        [datetime]$EndDate = (Get-Date),
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = Join-Path -Path (Get-Location).Path -ChildPath "Output\",
        [Parameter(Mandatory=$false)]
        [string]$UserIds,
        [Parameter(Mandatory=$false)]
        [string]$Encoding = 'UTF8'
    )

    $requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All')
    EnsureScopes $requiredScopes

    $baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?'
    $queryParameters = @()
    if ($StartDate) { $queryParameters += "`$filter=activityDateTime ge $($StartDate.ToString('yyyy-MM-ddTHH:mm:ss'))" }
    if ($EndDate) { $queryParameters += "activityDateTime le $($EndDate.ToString('yyyy-MM-ddTHH:mm:ss'))" }
    if ($UserIds) { $queryParameters += " and initiatedBy/user/id eq $UserIds" }
    $filterQuery = $queryParameters -join ' and '
    $apiUrl = "$baseUri$filterQuery"

    try {
        Do {
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
    catch {
        Write-Error "Error fetching data: $_"
    }
    finally {
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function EnsureScopes($requiredScopes) {
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
}

function Merge-OutputFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,
        [Parameter(Mandatory=$true)]
        [string]$Encoding,
        [Parameter(Mandatory=$true)]
        [string]$MergedFile
    )

    $files = Get-ChildItem -Path $OutputDirectory -Filter *.json

    if ($files.Count -eq 0) {
        Write-Warning "No JSON files found in the output directory: $OutputDirectory"
        return
    }

    $mergedContent = @()

    foreach ($file in $files) {
        $content = Get-Content -Path $file.FullName -Encoding $Encoding
        $mergedContent += $content
    }

    $mergedContent | Out-File -FilePath $MergedFile -Encoding $Encoding
    Write-Host "[INFO] Merged output files to: $MergedFile" -ForegroundColor Green
}
