using module "$PSScriptRoot\Microsoft-Extractor-Suite.psm1"

function ConvertTo-QueryString {
    param([hashtable]$Parameters)
    return ($Parameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
}

function ConvertTo-Iso8601 {
    param([datetime]$Date)
    return $Date.ToString('s') + 'Z'
}

function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter()]
        [hashtable]$Headers,
        [Parameter()]
        [hashtable]$QueryParameters,
        [Parameter()]
        [object]$Body
    )

    $headers = @{
        'Content-Type' = 'application/json'
    }
    if ($Headers) {
        $headers.AddRange($Headers)
    }

    $queryParameters = @{
        filter = @{
            properties = @{
                activityDateTime = @{
                    ge = ConvertTo-Iso8601 (Get-Date $queryParameters.filter.properties.activityDateTime.ge)
                    le = ConvertTo-Iso8601 (Get-Date $queryParameters.filter.properties.activityDateTime.le)
                }
            }
        }
    }
    if ($queryParameters) {
        $queryParameters = ConvertTo-QueryString $queryParameters.filter
    }

    $apiUrl = "$Uri?$queryParameters"

    try {
        $response = Invoke-RestMethod -Method $Method -Uri $apiUrl -Headers $headers -Body $Body
        return $response
    }
    catch {
        Write-Error "Error fetching data: $_"
        return $null
    }
}

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

    if ($StartDate -gt $EndDate) {
        Write-Error "Start date cannot be later than end date."
        return
    }

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

    $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl

    if ($response) {
        do {
            $logs = $response

            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM -ErrorAction Stop
            Write-Host "Sign-in audit logs written to $filePath" -ForegroundColor Green

            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            Start-Sleep -Seconds $Interval

            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl

        } while ($response.'@odata.nextLink')
    }

    if ($MergeOutput) {
        try {
            Write-Host 'Merging output files...' -ForegroundColor Green
            $mergedFile = Join-Path $OutputDirectory "$($dateStamp)-SignInAudit-MERGED.json"
            Merge-OutputFiles -OutputDir $OutputDirectory -Encoding $Encoding -mergedFile $mergedFile -Files $outputFiles -ErrorAction Stop
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

    if ($StartDate -gt $EndDate) {
        Write-Error "Start date cannot be later than end date."
        return
    }

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

    $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl

    if ($response) {
        do {
            $logs = $response

            $currentDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            $logs.Values | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding utf8BOM -ErrorAction Stop
            Write-Host "Directory audit logs written to $filePath" -ForegroundColor Green

            $apiUrl = $response.'@odata.nextLink'  # Update the URL to the nextLink for pagination
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()

            Start-Sleep -Seconds $Interval

            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl

        } while ($response.'@odata.nextLink')
    }

    Write-Log -Message "Directory audit logs written to $filePath" -Color "Green"
}

# ... (rest of the functions remain the same)
