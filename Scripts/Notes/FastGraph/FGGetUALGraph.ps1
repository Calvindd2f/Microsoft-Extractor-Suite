<# ---------- Helpers for POST + PS5.1-safe JSON prop access ----------
#

function Invoke-GraphPost {
    param(
        [Parameter(Mandatory)][string]$Uri,     # absolute or relative to /{version}/
        [Parameter(Mandatory)][string]$BodyJson,
        [hashtable]$ExtraHeaders
    )
    $client = New-HttpClient
    if ($Uri -notmatch '^https?://') {
        $Uri = "$($script:BaseGraphUri)/$($script:GraphVersion)/$Uri"
    }

    $attempt = 0
    while ($true) {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Uri)
        $req.Content = [System.Net.Http.StringContent]::new($BodyJson, [System.Text.Encoding]::UTF8, 'application/json')
        if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { [void]$req.Headers.TryAddWithoutValidation($k,[string]$ExtraHeaders[$k]) } }

        $resp = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ($resp.IsSuccessStatusCode) {
            return [System.Text.Json.JsonDocument]::Parse($resp.Content.ReadAsStream())
        }

        if ($resp.StatusCode -in ([System.Net.HttpStatusCode]::TooManyRequests, [System.Net.HttpStatusCode]::ServiceUnavailable, [System.Net.HttpStatusCode]::GatewayTimeout)) {
            $retryAfter = 0
            if ($resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) {
                $retryAfter = [int][math]::Ceiling($resp.Headers.RetryAfter.Delta.Value.TotalSeconds)
            }
            $attempt++
            if ($retryAfter -le 0) { $retryAfter = [Math]::Min(60,[Math]::Pow(2,$attempt)) + (Get-Random -Minimum 0 -Maximum 250)/1000.0 }
            Start-Sleep -Seconds $retryAfter
            continue
        }

        $err = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        throw "POST $Uri failed: $($resp.StatusCode) $err"
    }
}

function Get-JsonPropString {
    param([System.Text.Json.JsonElement]$Element,[string]$Name)
    foreach ($p in $Element.EnumerateObject()) {
        if ($p.Name -eq $Name) {
            if ($p.Value.ValueKind -eq 'String') { return $p.Value.GetString() }
            return $p.Value.ToString()
        }
    }
    return $null
}

function Get-JsonPropElement {
    param([System.Text.Json.JsonElement]$Element,[string]$Name)
    foreach ($p in $Element.EnumerateObject()) { if ($p.Name -eq $Name) { return $p.Value } }
    return $null
}
#>
# -------------------------- Get-UALGraphFast --------------------------

function Get-UALGraphFast {
    <#
        .SYNOPSIS
        High-throughput Unified Audit Log export via Microsoft Graph (beta/security/auditLog/queries).

        .DESCRIPTION
        Creates an auditLogQuery, polls until running/succeeded, streams records pages via @odata.nextLink,
        and writes to JSON / JSONL / CSV / SOF-ELK with optional file splitting.

        .PARAMETER searchName
        Name for the audit query (required).

        # Other parameters match your original function for parity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$searchName,
        [string]$OutputDir = "Output\UnifiedAuditLog\",
        [string]$Encoding = "UTF8",
        [string]$startDate,
        [string]$endDate,
        [string[]]$RecordType = @(),
        [string]$Keyword = "",
        [string]$Service = "",
        [string[]]$Operations = @(),
        [string[]]$UserIds = @(),
        [string[]]$IPAddress = @(),
        [string[]]$ObjectIDs = @(),
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [double]$MaxEventsPerFile = 250000,
        [ValidateSet("CSV","JSON","JSONL","SOF-ELK")]
        [string]$Output = "JSON",
        [switch]$SplitFiles
    )

    # Logging as in your original
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    Write-LogFile -Message "=== Starting Microsoft Graph Audit Log Retrieval ===" -Color "Cyan" -Level Standard

    # Resolve dates using your existing helpers
    StartDate -Quiet
    EndDate -Quiet
    $dateRange = "$($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-LogFile -Message "Analysis Period: $dateRange" -Level Standard

    if (-not (Test-Path $OutputDir)) { $null = New-Item -ItemType Directory -Force -Path $OutputDir }

    # Build body (use ConvertTo-Json for convenience; Graph accepts it fine)
    $bodyObj = @{
        "@odata.type"            = "#microsoft.graph.security.auditLogQuery"
        displayName              = $searchName
        filterStartDateTime      = $script:startDate
        filterEndDateTime        = $script:endDate
        recordTypeFilters        = $RecordType
        keywordFilter            = $Keyword
        serviceFilter            = $Service
        operationFilters         = $Operations
        userPrincipalNameFilters = $UserIds
        ipAddressFilters         = $IPAddress
        objectIdFilters          = $ObjectIDs
        administrativeUnitIdFilters = @()
        status                   = ""
    }
    $bodyJson = $bodyObj | ConvertTo-Json -Depth 6

    # Create query
    $createUri = "beta/security/auditLog/queries"
    $createDoc = Invoke-GraphPost -Uri $createUri -BodyJson $bodyJson
    try {
        $root = $createDoc.RootElement
        $scanId = Get-JsonPropString -Element $root -Name 'id'
        $status = Get-JsonPropString -Element $root -Name 'status'
    } finally {
        $createDoc.Dispose()
    }
    if (-not $scanId) { throw "Failed to create auditLogQuery (no ID in response)." }

    Write-LogFile -Message "[INFO] Created Unified Audit Log search '$searchName' with ID: $scanId (status: $status)" -Level Minimal

    # Poll until running/succeeded
    $queryUriAbs = "$($script:BaseGraphUri)/beta/security/auditLog/queries/$scanId"
    $lastStatus = $null
    do {
        $qdoc = Invoke-GraphGet -Uri $queryUriAbs
        try {
            $qroot = $qdoc.RootElement
            $status = Get-JsonPropString -Element $qroot -Name 'status'
        } finally { $qdoc.Dispose() }
        if ($status -ne $lastStatus) {
            Write-LogFile -Message "[INFO] Query status: $status" -Level Standard
            $lastStatus = $status
        }
        if ($status -notin @('running','succeeded')) { Start-Sleep -Seconds 5 }
    } while ($status -notin @('running','succeeded'))

    if ($status -eq 'running') {
        Write-LogFile -Message "[INFO] Unified Audit Log search is running..." -Level Standard
        do {
            $qdoc = Invoke-GraphGet -Uri $queryUriAbs
            try {
                $qroot = $qdoc.RootElement
                $status = Get-JsonPropString -Element $qroot -Name 'status'
            } finally { $qdoc.Dispose() }
            Start-Sleep -Seconds 5
        } while ($status -ne 'succeeded')
    }
    Write-LogFile -Message "[INFO] Unified Audit Log search complete." -Level Minimal

    # Prepare outputs / split files
    $dateStamp = (Get-Date).ToString('yyyyMMddHHmmss')
    $baseName  = "$dateStamp-$searchName-UnifiedAuditLog"
    $fileIdx   = 1
    $curCount  = 0
    $total     = 0
    $summary = [ordered]@{
        TotalRecords     = 0
        ExportedFiles    = 0
        StartTime        = Get-Date
        ProcessingTime   = $null
        SearchId         = $scanId
    }

    $WriteOpenBracket = {
        param([string]$path,[string]$enc)
        "[" | Out-File -FilePath $path -Encoding $enc
    }
    $WriteCloseBracket = {
        param([string]$path,[string]$enc)
        "]" | Out-File -FilePath $path -Encoding $enc -Append
    }

    # Initialize first target path
    function New-TargetPath {
        param([string]$ext)
        if ($SplitFiles) { return Join-Path $OutputDir ("$baseName-part$fileIdx.$ext") }
        else { return Join-Path $OutputDir ("$baseName.$ext") }
    }

    $csvBuffer = @()
    $jsonOpened = $false
    switch ($Output) {
        'JSON' {
            $filePath = New-TargetPath -ext 'json'
            & $WriteOpenBracket $filePath $Encoding
            $jsonOpened = $true
            $firstJson = $true
        }
        'CSV' {
            $filePath = New-TargetPath -ext 'csv'
            $csvBuffer = @()
        }
        'JSONL' {
            $filePath = New-TargetPath -ext 'jsonl'
        }
        'SOF-ELK' {
            $filePath = New-TargetPath -ext 'json'
        }
    }

    Write-LogFile -Message "[INFO] Collecting records..." -Level Standard
    $recordsUri = "$($script:BaseGraphUri)/beta/security/auditLog/queries/$scanId/records"
    $page = 0

    do {
        $page++
        $doc = Invoke-GraphGet -Uri $recordsUri
        try {
            $root = $doc.RootElement
            $val  = Get-JsonPropElement -Element $root -Name 'value'
            if ($val.ValueKind -eq 'Array' -and $val.GetArrayLength() -gt 0) {
                $batchCount = $val.GetArrayLength()
                $total += $batchCount
                # iterate array items
                for ($i=0; $i -lt $batchCount; $i++) {
                    $rec = $val[$i]
                    switch ($Output) {
                        'JSON' {
                            if ($SplitFiles -and $curCount -ge $MaxEventsPerFile) {
                                & $WriteCloseBracket $filePath $Encoding
                                $summary.ExportedFiles++
                                $fileIdx++; $curCount = 0
                                $filePath = New-TargetPath -ext 'json'
                                & $WriteOpenBracket $filePath $Encoding
                                $firstJson = $true
                            }
                            if (-not $firstJson) {
                                "," | Out-File -FilePath $filePath -Append -Encoding $Encoding -NoNewline
                                "`r`n" | Out-File -FilePath $filePath -Append -Encoding $Encoding -NoNewline
                            } else { $firstJson = $false }
                            # write raw element text
                            $json = $rec.GetRawText()
                            $json | Out-File -FilePath $filePath -Append -Encoding $Encoding -NoNewline
                            $curCount++; $summary.TotalRecords++
                        }
                        'JSONL' {
                            if ($SplitFiles -and $curCount -ge $MaxEventsPerFile) {
                                $summary.ExportedFiles++
                                $fileIdx++; $curCount = 0
                                $filePath = New-TargetPath -ext 'jsonl'
                            }
                            $line = $rec.GetRawText()
                            $line | Out-File -Append $filePath -Encoding UTF8
                            "`r`n" | Out-File -Append $filePath -Encoding UTF8
                            $curCount++; $summary.TotalRecords++
                        }
                        'SOF-ELK' {
                            if ($SplitFiles -and $curCount -ge $MaxEventsPerFile) {
                                $summary.ExportedFiles++
                                $fileIdx++; $curCount = 0
                                $filePath = New-TargetPath -ext 'json'
                            }
                            $line = $rec.GetRawText()
                            $line | Out-File -Append $filePath -Encoding UTF8
                            $curCount++; $summary.TotalRecords++
                        }
                        'CSV' {
                            # Build a light PSObject per record (flatten auditData to JSON string)
                            $ht = [ordered]@{}
                            foreach ($p in $rec.EnumerateObject()) {
                                $name = $p.Name
                                if ($name -eq 'auditData') {
                                    $ht['auditData'] = $p.Value.GetRawText()
                                } else {
                                    # primitive-ish capture
                                    $ht[$name] = switch ($p.Value.ValueKind) {
                                        'String' { $p.Value.GetString() }
                                        'Number' { try { $p.Value.GetInt64() } catch { $p.Value.GetDouble() } }
                                        'True'   { $true }
                                        'False'  { $false }
                                        default  { $p.Value.ToString() }
                                    }
                                }
                            }
                            $csvBuffer += [pscustomobject]$ht
                            $curCount++; $summary.TotalRecords++
                            if ($SplitFiles -and $curCount -ge $MaxEventsPerFile) {
                                $csvBuffer | Select-Object id, createdDateTime, auditLogRecordType, operation, organizationId, userType, userId, service, objectId, userPrincipalName, clientIp, administrativeUnits, auditData |
                                    Export-Csv -Path $filePath -Append -Encoding $Encoding -NoTypeInformation
                                $summary.ExportedFiles++
                                $csvBuffer = @()
                                $fileIdx++; $curCount = 0
                                $filePath = New-TargetPath -ext 'csv'
                            }
                        }
                    }
                }
                if ($total % 10000 -eq 0 -or $batchCount -lt 100) {
                    Write-LogFile -Message "[INFO] Progress: $total total events processed (page $page)" -Level Standard
                }
            } else {
                if ($total -eq 0) { Write-LogFile -Message "[INFO] No results matched your search." -Color Yellow -Level Minimal }
            }

            # nextLink (PS5-safe)
            $nextLink = $null
            foreach ($p in $root.EnumerateObject()) {
                if ($p.Name -eq '@odata.nextLink') { $nextLink = $p.Value.GetString(); break }
            }
            $recordsUri = $nextLink
        }
        finally { $doc.Dispose() }
    } while ($recordsUri)

    # Finalize outputs
    switch ($Output) {
        'JSON'   { if ($jsonOpened) { & $WriteCloseBracket $filePath $Encoding } }
        'CSV'    { if ($csvBuffer.Count -gt 0) {
                       $csvBuffer | Select-Object id, createdDateTime, auditLogRecordType, operation, organizationId, userType, userId, service, objectId, userPrincipalName, clientIp, administrativeUnits, auditData |
                           Export-Csv -Path $filePath -Append -Encoding $Encoding -NoTypeInformation
                   } }
        default  { }
    }
    if ($curCount -gt 0) { $summary.ExportedFiles++ }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime

    # Summary
    Write-LogFile -Message "`n=== Audit Log Retrieval Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Time Period: $dateRange" -Level Standard
    Write-LogFile -Message "Search Name: $searchName" -Level Standard
    Write-LogFile -Message "Search ID: $($summary.SearchId)" -Level Standard
    Write-LogFile -Message "Total Records Retrieved: $($summary.TotalRecords)" -Level Standard
    if ($summary.TotalRecords -eq 0) { Write-LogFile -Message "No results matched your search criteria." -Color "Yellow" -Level Standard }
    Write-LogFile -Message "Files Created: $($summary.ExportedFiles)" -Level Minimal
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('hh\:mm\:ss'))"  -Color "Green" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
