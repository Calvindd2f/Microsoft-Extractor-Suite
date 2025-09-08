function Get-GraphEntraAuditLogsFast {
<#
.SYNOPSIS
High-throughput export of Entra ID directory audit logs via Graph REST.

.DESCRIPTION
Streams /auditLogs/directoryAudits with $filter + @odata.nextLink. Reuses HttpClient. PS5-safe JSON.

.PARAMETER startDate / endDate
ISO date/time strings. If omitted, StartDateAz/EndDate helpers supply them.

.PARAMETER UserIds
Filter by initiatedBy.user.userPrincipalName startsWith(...). With -All, also OR against targetResources.userPrincipalName equals.

.PARAMETER Output
JSON | SOF-ELK (default JSON)

.PARAMETER MergeOutput
Merge all page files into one (via your Merge-OutputFiles helper).

.PARAMETER OutputDir
Default "Output\EntraID\{yyyyMMdd}-Auditlogs"
#>
    [CmdletBinding()]
    param(
        [string]$startDate,
        [string]$endDate,
        [string]$OutputDir,
        [ValidateSet("JSON","SOF-ELK")]
        [string]$Output = "JSON",
        [string]$Encoding = "UTF8",
        [switch]$MergeOutput,
        [string[]]$UserIds,
        [switch]$All,
        [ValidateSet('None','Minimal','Standard','Debug')]
        [string]$LogLevel = 'Standard'
    )

    # ---- Logging / setup ----
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug

    $summary = [ordered]@{
        TotalRecords   = 0
        StartTime      = Get-Date
        ProcessingTime = $null
        TotalFiles     = 0
    }

    Write-LogFile -Message "=== Starting Directory Audit Log Collection (fast) ===" -Color "Cyan" -Level Standard
    $requiredScopes = @("AuditLog.Read.All","Directory.Read.All")
    $null = Get-GraphAuthType -RequiredScopes $RequiredScopes

    $dateTag = (Get-Date).ToString('yyyyMMdd')
    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $OutputDir = "Output\EntraID\$dateTag-Auditlogs"
    }
    UpsertOutputDirectory $OutputDir

    # Resolve dates
    $StartDate = if ($startDate) { $startDate } else { (StartDateAz -Quiet; $script:StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')) }
    $EndDate   = if ($endDate)   { $endDate   } else { (EndDate    -Quiet; $script:EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')) }

    Write-LogFile -Message "Start Date      : $StartDate" -Level Standard
    Write-LogFile -Message "End Date        : $EndDate" -Level Standard
    Write-LogFile -Message "Output Format   : $Output" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    if ($UserIds) { Write-LogFile -Message "Filtering Users : $($UserIds -join ', ')" -Level Standard }
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

    # Build $filter (efficient, server-side)
    $filterSb = [System.Text.StringBuilder]::new()
    [void]$filterSb.Append("activityDateTime ge $StartDate and activityDateTime le $EndDate")

    if ($UserIds -and $UserIds.Count -gt 0) {
        $uf = $UserIds | ForEach-Object { "startsWith(initiatedBy/user/userPrincipalName, '$_')" }
        [void]$filterSb.Append(" and (")
        [void]$filterSb.Append(($uf -join ' or '))
        [void]$filterSb.Append(")")
        if ($All) {
            $tf = $UserIds | ForEach-Object { "targetResources/any(tr: tr/userPrincipalName eq '$_')" }
            $full = "("+$filterSb.ToString()+") or ("+([string]::Join(' or ',$tf))+")"
            $filterSb.Clear() | Out-Null
            [void]$filterSb.Append($full)
        }
    } else {
        if ($All) { Write-LogFile -Message "[WARNING] '-All' has no effect without UserIds" -Level Standard -Color "Yellow" }
    }

    $encoded = [System.Web.HttpUtility]::UrlEncode($filterSb.ToString())
    $uri = "$($script:BaseGraphUri)/v1.0/auditLogs/directoryAudits?`$filter=$encoded"

    # PS5-safe JSON helpers
    function J-GetElem { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ return $p.Value } } $null }
    function J-GetStr  { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ if($p.Value.ValueKind -eq 'String'){return $p.Value.GetString()} return $p.Value.ToString() } } $null }

    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array' -and $val.GetArrayLength() -gt 0) {
                $ts = (Get-Date).ToString('yyyyMMddHHmmss')
                $filePath = Join-Path $OutputDir "$ts-AuditLogs.json"

                $batchCount = $val.GetArrayLength()
                if ($Output -eq 'JSON') {
                    $val.GetRawText() | Out-File -FilePath $filePath -Encoding $Encoding
                } else {
                    for ($i=0; $i -lt $batchCount; $i++) {
                        $val[$i].GetRawText() | Out-File -FilePath $filePath -Append -Encoding UTF8
                    }
                }

                $summary.TotalRecords += $batchCount
                $summary.TotalFiles++

                # quick min/max time display
                $first = $JFirst = $null
                try {
                    $first = (J-GetStr -E $val[0] -Name 'activityDateTime')
                    $last  = (J-GetStr -E $val[$batchCount-1] -Name 'activityDateTime')
                } catch {}
                Write-LogFile -Message "[INFO] Retrieved $batchCount records ($first .. $last)" -Level Standard -Color "Green"
            }

            # nextLink
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink') { $next = $p.Value.GetString(); break } }
            $uri = $next
        }
        finally { $doc.Dispose() }
    } while ($uri)

    if ($MergeOutput) {
        Write-LogFile -Message "[INFO] Merging output files" -Level Standard
        if ($Output -eq 'JSON') {
            Merge-OutputFiles -OutputDir $OutputDir -OutputType "JSON"   -MergedFileName "AuditLogs-Combined.json"
        } else {
            Merge-OutputFiles -OutputDir $OutputDir -OutputType "SOF-ELK" -MergedFileName "AuditLogs-Combined.json"
        }
    }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    Write-LogFile -Message "`nCollection Summary:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "  Total Records  : $($summary.TotalRecords)" -Level Standard
    Write-LogFile -Message "  Files Created  : $($summary.TotalFiles)" -Level Standard
    Write-LogFile -Message "  Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "  Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Level Standard -Color "Green"
}
