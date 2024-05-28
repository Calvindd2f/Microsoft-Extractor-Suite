using module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"

function Get-ADSignInLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$StartDate,
        [Parameter(Mandatory=$true)]
        [datetime]$EndDate,
        [Parameter(Mandatory=$true)]
        [string]$OutputDir,
        [string]$UserIds,
        [switch]$MergeOutput,
        [string]$Encoding = 'UTF8',
        [int]$Interval
    )

    Write-Log -Message "Running Get-ADSignInLogs" -Color "Green"

    $outputFiles = Get-OutputFiles -OutputDir $OutputDir -FilePrefix "$($StartDate)-AuditLogSignIn" -FileExtension json

    $dateStamp = Get-Date -Format "yyyyMMddHHmmss"
    $filePath = Join-Path $OutputDir "$($dateStamp)-AuditLogSignIn.json"

    $baseUri = 'https://graph.microsoft.com/v1.0'
    $resourcePath = (Find-MgGraphCommand -Command Get-MgBetaAuditLogSignIn).URI[1]
    $baseUri = "$baseUri$resourcePath?"

    $queryParameters = @{
        filter = @{
            properties = @{
                activityDateTime = @{
                    ge = $StartDate
                    le = $EndDate
                }
            }
        }
    }

    if ($UserIds) {
        $queryParameters.filter.properties.initiatedBy = @{
            user = @{
                id = $UserIds
            }
        }
    }

    $apiUrl = "$baseUri$($queryParameters.filter.properties.activityDateTime.ge),$($queryParameters.filter.properties.activityDateTime.le),$($queryParameters.filter.properties.initiatedBy.user.id | ToQueryString)/@odata.type=#microsoft.graph.auditLogSignIn"

    try {
        do {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
            $logs = $response

            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "Sign-in logs written to $filePath" -ForegroundColor Green

            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            Start-Sleep -Seconds $Interval

        } while ($response.'@odata.nextLink')
    }
    catch {
        Write-Error "Error fetching data: $_"
    }
    finally {
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
    }

    if ($MergeOutput) {
        try {
            Write-Host 'Merging output files...' -ForegroundColor Green
            $mergedFile = Join-Path $OutputDir "$($dateStamp)-AuditLogSignIn-MERGED.json"
            Merge-OutputFiles -OutputDir $OutputDir -Encoding $Encoding -mergedFile $mergedFile -Files $outputFiles
        }
        catch {
            Write-Error "Error merging files: $_" -ForegroundColor Red
        }
        finally {
            Write-Host 'Process completed.' -ForegroundColor Green
        }
    }
}

function Get-ADAuditLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$StartDate,
        [Parameter(Mandatory=$true)]
        [datetime]$EndDate,
        [Parameter(Mandatory=$true)]
        [string]$OutputDir,
        [string]$UserIds,
        [string]$Encoding = 'UTF8'
    )

    $dateStamp = Get-Date -Format "yyyyMMddHHmmss"
    $filePath = Join-Path $OutputDir "$($dateStamp)-AuditLogDirectoryAudit.json"

    Write-Log -Message "Collecting the Directory Audit Logs"

    $baseUri = 'https://graph.microsoft.com/v1.0'
    $resourcePath = (Find-MgGraphCommand -Command Get-MgBetaAuditLogDirectoryAudit).URI[1]
    $baseUri = "$baseUri$resourcePath?"

    $queryParameters = @{
        filter = @{
            properties = @{
                activityDateTime = @{
                    ge = $StartDate
                    le = $EndDate
                }
            }
        }
    }

    if ($UserIds) {
        $queryParameters.filter.properties.initiatedBy = @{
            user = @{
                id = $UserIds
            }
        }
    }

    $apiUrl = "$baseUri$($queryParameters.filter.properties.activityDateTime.ge),$($queryParameters.filter.properties.activityDateTime.le),$($queryParameters.filter.properties.initiatedBy.user.id | ToQueryString)/@odata.type=#microsoft.graph.auditLogDirectoryAudit"

    try {
        do {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
            $logs = $response

            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "Directory logs written to $filePath" -ForegroundColor Green

            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            Start-Sleep -Seconds $Interval

        } while ($response.'@odata.nextLink')
    }
    catch {
        Write-Error "Error fetching data: $_"
    }
    finally {
        Remove-Variable response -ErrorAction Ignore
        Remove-Variable logs -ErrorAction Ignore
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
    }

    Write-Log -Message "Directory audit logs written to $filePath" -Color "Green"
}

function Merge-OutputFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDir,
        [Parameter(Mandatory=$true)]
        [string]$Encoding,
        [Parameter(Mandatory=$true)]
        [string]$mergedFile,
        [Parameter(Mandatory=$false)]
        [string[]]$Files
    )

    if ($Files) {
        $filesToMerge = $Files
    }
    else {
        $filesToMerge = Get-ChildItem -Path $OutputDir -Filter *.json
    }

    if ($filesToMerge.Count -eq 0) {
        Write-Log -Message "No JSON files found in the output directory." -Color "Yellow"
        return
    }

    $mergedContent = @()

    foreach ($file in $filesToMerge) {
        try {
            $content = Get-Content -Path $file.FullName -Encoding $Encoding
            $mergedContent += $content
        }
        catch {
            Write-Error "Error reading file: $_" -ForegroundColor Red
        }
    }

    $mergedContent | ConvertFrom-Json | ConvertTo-Json -Depth 100 | Out-File -FilePath $mergedFile -Encoding utf8BOM
    Write-Log -Message "Output files merged successfully." -Color "Green"
}

function Get-OutputFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputDir,
        [Parameter(Mandatory=$true)]
        [string]$FilePrefix,
        [Parameter(Mandatory=$true)]
        [string]$FileExtension
    )

    $outputFiles = Get-ChildItem -Path $OutputDir -Filter "$($FilePrefix)*$($FileExtension)"

    return $outputFiles
}

function ToQueryString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Properties
    )

    $queryString = $Properties -join ','

    return $queryString
}
