# ===================================================================
# RISKY USERS — FAST
# ===================================================================
function Get-RiskyUsersFast {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\RiskyEvents",
        [string]$Encoding = "UTF8",
        [string[]]$UserIds,
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    Write-LogFile -Message "=== Starting Risky Users Collection (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir
    $null = Get-GraphAuthType -RequiredScopes @('IdentityRiskyUser.Read.All','IdentityRiskEvent.Read.All')

    $results = New-Object System.Collections.Generic.List[object]
    $summary = @{
        High=0; Medium=0; Low=0; None=0;
        AtRisk=0; NotAtRisk=0; Remediated=0; Dismissed=0
    }

    $base = "$($script:BaseGraphUri)/v1.0/identityProtection/riskyUsers"
    $targets = @()
    if ($UserIds -and $UserIds.Count) {
        foreach ($u in $UserIds) { $targets += "$base?`$filter=userPrincipalName eq '$u'" }
    } else { $targets = @($base) }

    foreach ($uri0 in $targets) {
        $uri = $uri0
        do {
            $doc = Invoke-GraphGet -Uri $uri
            try {
                $root = $doc.RootElement
                $val  = J-GetElem -E $root -Name 'value'
                if ($val -and $val.ValueKind -eq 'Array') {
                    for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                        $e = $val[$i]
                        $obj = [pscustomobject]@{
                            Id                      = J-GetStr -E $e -Name 'id'
                            IsDeleted               = J-GetStr -E $e -Name 'isDeleted'
                            IsProcessing            = J-GetStr -E $e -Name 'isProcessing'
                            RiskDetail              = J-GetStr -E $e -Name 'riskDetail'
                            RiskLastUpdatedDateTime = J-GetStr -E $e -Name 'riskLastUpdatedDateTime'
                            RiskLevel               = J-GetStr -E $e -Name 'riskLevel'
                            RiskState               = J-GetStr -E $e -Name 'riskState'
                            UserDisplayName         = J-GetStr -E $e -Name 'userDisplayName'
                            UserPrincipalName       = J-GetStr -E $e -Name 'userPrincipalName'
                        }
                        $results.Add($obj) | Out-Null
                        if ($obj.RiskLevel) { $summary[$obj.RiskLevel]++ }
                        switch ($obj.RiskState) {
                            'atRisk'        { $summary.AtRisk++ }
                            'notAtRisk'     { $summary.NotAtRisk++ }
                            'remediated'    { $summary.Remediated++ }
                            'dismissed'     { $summary.Dismissed++ }
                        }
                    }
                }
                $next = $null
                foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
                $uri = $next
            } finally { $doc.Dispose() }
        } while ($uri)
    }

    $date = (Get-Date).ToString('yyyyMMddHHmm')
    $out  = Join-Path $OutputDir "$date-RiskyUsers.csv"
    if ($results.Count) {
        $results | Export-Csv -NoTypeInformation -Encoding $Encoding -Path $out
        Write-LogFile -Message "[INFO] A total of $($results.Count) Risky Users found" -Level Standard
        Write-LogFile -Message "`nSummary of Risky Users:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  - High: $($summary.High)" -Level Standard
        Write-LogFile -Message "  - Medium: $($summary.Medium)" -Level Standard
        Write-LogFile -Message "  - Low: $($summary.Low)" -Level Standard
        Write-LogFile -Message "States:" -Level Standard
        Write-LogFile -Message "  - At Risk: $($summary.AtRisk)" -Level Standard
        Write-LogFile -Message "  - Not At Risk: $($summary.NotAtRisk)" -Level Standard
        Write-LogFile -Message "  - Remediated: $($summary.Remediated)" -Level Standard
        Write-LogFile -Message "  - Dismissed: $($summary.Dismissed)" -Level Standard
        Write-LogFile -Message "Exported: $out" -Level Standard
    } else {
        Write-LogFile -Message "[INFO] No Risky Users found" -Color "Yellow" -Level Standard
    }
}

# ===================================================================
# RISKY DETECTIONS — FAST
# ===================================================================
function Get-RiskyDetectionsFast {
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\RiskyEvents",
        [string]$Encoding = "UTF8",
        [string[]]$UserIds,
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    Write-LogFile -Message "=== Starting Risky Detections Collection (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir
    $null = Get-GraphAuthType -RequiredScopes @('IdentityRiskEvent.Read.All','IdentityRiskyUser.Read.All')

    $results = New-Object System.Collections.Generic.List[object]
    $summary = @{
        High=0; Medium=0; Low=0; AtRisk=0; NotAtRisk=0; Remediated=0; Dismissed=0
        UniqueUsers=@{}; UniqueCountries=@{}; UniqueCities=@{}
    }

    $base = "$($script:BaseGraphUri)/v1.0/identityProtection/riskDetections"
    $targets = @()
    if ($UserIds -and $UserIds.Count) {
        foreach ($u in $UserIds) { $targets += "$base?`$filter=userPrincipalName eq '$u'" }
    } else { $targets = @($base) }

    foreach ($uri0 in $targets) {
        $uri = $uri0
        do {
            $doc = Invoke-GraphGet -Uri $uri
            try {
                $root = $doc.RootElement
                $val  = J-GetElem -E $root -Name 'value'
                if ($val -and $val.ValueKind -eq 'Array') {
                    for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                        $e = $val[$i]
                        # Location fields can be null — guard with J-GetElem then pull strings
                        $loc = J-GetElem -E $e -Name 'location'
                        $city = $null; $country = $null; $state=$null
                        if ($loc -and $loc.ValueKind -eq 'Object') {
                            $city    = J-GetStr -E $loc -Name 'city'
                            $country = J-GetStr -E $loc -Name 'countryOrRegion'
                            $state   = J-GetStr -E $loc -Name 'state'
                        }
                        $obj = [pscustomobject]@{
                            Activity               = J-GetStr -E $e -Name 'activity'
                            ActivityDateTime       = J-GetStr -E $e -Name 'activityDateTime'
                            AdditionalInfo         = J-GetStr -E $e -Name 'additionalInfo'
                            CorrelationId          = J-GetStr -E $e -Name 'correlationId'
                            DetectedDateTime       = J-GetStr -E $e -Name 'detectedDateTime'
                            IPAddress              = J-GetStr -E $e -Name 'ipAddress'
                            Id                     = J-GetStr -E $e -Name 'id'
                            LastUpdatedDateTime    = J-GetStr -E $e -Name 'lastUpdatedDateTime'
                            City                   = $city
                            CountryOrRegion        = $country
                            State                  = $state
                            RequestId              = J-GetStr -E $e -Name 'requestId'
                            RiskDetail             = J-GetStr -E $e -Name 'riskDetail'
                            RiskEventType          = J-GetStr -E $e -Name 'riskEventType'
                            RiskLevel              = J-GetStr -E $e -Name 'riskLevel'
                            RiskState              = J-GetStr -E $e -Name 'riskState'
                            DetectionTimingType    = J-GetStr -E $e -Name 'detectionTimingType'
                            Source                 = J-GetStr -E $e -Name 'source'
                            TokenIssuerType        = J-GetStr -E $e -Name 'tokenIssuerType'
                            UserDisplayName        = J-GetStr -E $e -Name 'userDisplayName'
                            UserId                 = J-GetStr -E $e -Name 'userId'
                            UserPrincipalName      = J-GetStr -E $e -Name 'userPrincipalName'
                        }
                        $results.Add($obj) | Out-Null
                        if ($obj.RiskLevel) { $summary[$obj.RiskLevel]++ }
                        switch ($obj.RiskState) {
                            'atRisk'        { $summary.AtRisk++ }
                            'confirmedSafe' { $summary.NotAtRisk++ }
                            'remediated'    { $summary.Remediated++ }
                            'dismissed'     { $summary.Dismissed++ }
                        }
                        if ($obj.UserPrincipalName) { $summary.UniqueUsers[$obj.UserPrincipalName] = $true }
                        if ($obj.CountryOrRegion)   { $summary.UniqueCountries[$obj.CountryOrRegion] = $true }
                        if ($obj.City)              { $summary.UniqueCities[$obj.City] = $true }
                    }
                }
                $next = $null
                foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
                $uri = $next
            } finally { $doc.Dispose() }
        } while ($uri)
    }

    $date = (Get-Date).ToString('yyyyMMddHHmm')
    $out  = Join-Path $OutputDir "$date-RiskyDetections.csv"
    if ($results.Count) {
        $results | Export-Csv -NoTypeInformation -Encoding $Encoding -Path $out
        Write-LogFile -Message "`nSummary of Risky Detections:" -Color "Cyan" -Level Standard
        Write-LogFile -Message "  Total: $($results.Count)" -Level Standard
        Write-LogFile -Message "  - High: $($summary.High)" -Level Standard
        Write-LogFile -Message "  - Medium: $($summary.Medium)" -Level Standard
        Write-LogFile -Message "  - Low: $($summary.Low)" -Level Standard
        Write-LogFile -Message "States:" -Level Standard
        Write-LogFile -Message "  - At Risk: $($summary.AtRisk)" -Level Standard
        Write-LogFile -Message "  - Confirmed Safe: $($summary.NotAtRisk)" -Level Standard
        Write-LogFile -Message "  - Remediated: $($summary.Remediated)" -Level Standard
        Write-LogFile -Message "  - Dismissed: $($summary.Dismissed)" -Level Standard
        Write-LogFile -Message "Affected:" -Level Standard
        Write-LogFile -Message "  - Unique Users: $($summary.UniqueUsers.Count)" -Level Standard
        Write-LogFile -Message "  - Unique Countries: $($summary.UniqueCountries.Count)" -Level Standard
        Write-LogFile -Message "Exported: $out" -Level Standard
    } else {
        Write-LogFile -Message "[INFO] No Risky Detections found" -Color "Yellow" -Level Standard
    }
}
