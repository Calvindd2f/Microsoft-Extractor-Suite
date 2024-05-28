using module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"

function Get-ADSignInAuditLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$StartDate,
        [Parameter(Mandatory=$true)]
        [datetime]$EndDate,
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,
        [string]$UserIds,
        [switch]$MergeOutput,
        [string]$Encoding = 'UTF8',
        [int]$Interval
    )

    Write-Log -Message "Starting Get-ADSignInAuditLogs" -Color "Green"

    $outputFiles = Get-OutputFiles -OutputDir $OutputDirectory -FilePrefix "$($StartDate)-SignInAudit" -FileExtension json

    $dateStamp = Get-Date -Format "yyyyMMddHHmmss"
    $filePath = Join-Path $OutputDirectory "$($dateStamp)-SignInAudit.json"

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

    $response = Try {
        $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
        return $response
    }
    Catch {
        Write-Error "Error fetching data: $_"
        return $null
    }

    if ($response) {
        do {
            $logs = $response

            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "Sign-in audit logs written to $filePath" -ForegroundColor Green

            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            Start-Sleep -Seconds $Interval

            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'

        } while ($response.'@odata.nextLink')
    }

    if ($MergeOutput) {
        try {
            Write-Host 'Merging output files...' -ForegroundColor Green
            $mergedFile = Join-Path $OutputDirectory "$($dateStamp)-SignInAudit-MERGED.json"
            Merge-OutputFiles -OutputDir $OutputDirectory -Encoding $Encoding -mergedFile $mergedFile -Files $outputFiles
        }
        catch {
            Write-Error "Error merging files: $_" -ForegroundColor Red
        }
        finally {
            Write-Host 'Process completed.' -ForegroundColor Green
        }
    }

    Write-Log -Message "Sign-in audit logs written to $filePath" -Color "Green"
}

function Get-ADDirectoryAuditLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [datetime]$StartDate,
        [Parameter(Mandatory=$true)]
        [datetime]$EndDate,
        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory,
        [string]$UserIds,
        [string]$Encoding = 'UTF8'
    )

    $dateStamp = Get-Date -Format "yyyyMMddHHmmss"
    $filePath = Join-Path $OutputDirectory "$($dateStamp)-DirectoryAudit.json"

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

    $response = Try {
        $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
        return $response
    }
    Catch {
        Write-Error "Error fetching data: $_"
        return $null
    }

    if ($response) {
        do {
            $logs = $response

            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM
            Write-Host "Directory audit logs written to $filePath" -ForegroundColor Green

            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            Start-Sleep -Seconds $Interval

            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'

        } while ($response.'@odata.nextLink')
    }

    Write-Log -Message "Directory audit logs written to $filePath" -Color "Green"
}

# ... (rest of the functions remain the same)
