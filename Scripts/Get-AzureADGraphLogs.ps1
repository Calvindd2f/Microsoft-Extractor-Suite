using module  "$PSScriptRoot\Microsoft-Extractor-Suite.psm1";

function Get-ADSignInLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [datetime]$StartDate = (Get-Date).AddDays(-30),
        [Parameter(Mandatory=$false)]
        [datetime]$EndDate = Get-Date,
        [Parameter(Mandatory=$false)]
        [string[]]$UserIds,
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = Join-Path -Path (Get-Location).Path -ChildPath "Output\",
        [Parameter(Mandatory=$false)]
        [string]$Encoding = 'UTF8',
        [Parameter(Mandatory=$false)]
        [switch]$Application,
        [Parameter(Mandatory=$false)]
        [switch]$MergeOutput
    )

    $requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All')
    EnsureScopes $requiredScopes

    $apiUrl = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?'
    $queryParameters = @{}
    if ($StartDate) { $queryParameters['$filter'] = "activityDateTime ge $($StartDate.ToString('yyyy-MM-ddTHH:mm:ss'))" }
    if ($EndDate) { $queryParameters['$filter'] += " and activityDateTime le $($EndDate.ToString('yyyy-MM-ddTHH:mm:ss'))" }
    if ($UserIds) { $queryParameters['$filter'] += " and initiatedBy/user/id eq $($UserIds -join ' or ')" }

    try {
        $logs = Invoke-GraphRequest -Method Get -Uri $apiUrl -QueryParameters $queryParameters
        $filePath = "ADSignInLogsGraph_$(Get-Date -Format yyyy-MM-dd_HH-mm-ss).json"
        $logs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM -Force
        Write-Host "[INFO] Sign-in logs written to $filePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Error fetching data: $_"
    }
    finally {
        Remove-Variable logs -ErrorAction Ignore
    }

    if ($MergeOutput) {
        try {
            Write-Host '[INFO] Merging output files...' -ForegroundColor Green
            $mergedFile = "ADSignInLogsGraph-Combined_$(Get-Date -Format yyyy-MM-dd_HH-mm-ss).json"
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
        [string[]]$UserIds,
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory = Join-Path -Path (Get-Location).Path -ChildPath "Output\",
        [Parameter(Mandatory=$false)]
        [string]$Encoding = 'UTF8'
    )

    $requiredScopes = @('AuditLog.Read.All', 'Directory.Read.All')
    EnsureScopes $requiredScopes

    $apiUrl = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?'
    $queryParameters = @{}
    if ($StartDate) { $queryParameters['$filter'] = "activityDateTime ge $($StartDate.ToString('yyyy-MM-ddTHH:mm:ss'))" }
    if ($EndDate) { $queryParameters['$filter'] += " and activityDateTime le $($EndDate.ToString('yyyy-MM-ddTHH:mm-ss'))" }
    if ($UserIds) { $queryParameters['$filter'] += " and initiatedBy/user/id eq $($UserIds -join ' or ')" }

    try {
        $logs = Invoke-GraphRequest -Method Get -Uri $apiUrl -QueryParameters $queryParameters
        $filePath = "AuditlogsGraph_$(Get-Date -Format yyyy-MM-dd_HH-mm-ss).json"
        $logs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM -Force
        Write-Host "[INFO] Audit logs written to $filePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Error fetching data: $_"
    }
    finally {
        Remove-Variable logs -ErrorAction Ignore
    }
}

function Invoke-GraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter(Mandatory=$false)]
        [hashtable]$QueryParameters
    )

    $headers = @{
        'Authorization' = 'Bearer ' + (Get-MgAccessToken).AccessToken
        'ConsistencyLevel' = 'eventual'
    }

    if ($QueryParameters) {
        $Uri += '?' + ($QueryParameters | foreach { "$($_.Key)=$($_.Value)" } | join '&')
    }

    try {
        $response = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json'
    }
    catch {
        throw $_.Exception
    }

    return $response
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

    $mergedContent | Out-File -FilePath $MergedFile -Encoding $Encoding -Force
    Write-Host "[INFO] Merged output files to: $MergedFile" -ForegroundColor Green
}
