function Get-ConditionalAccessPoliciesFast {
<#
.SYNOPSIS
High-throughput export of Conditional Access policies via Microsoft Graph REST.

.DESCRIPTION
- Uses your cached HttpClient + token.
- Streams /identity/conditionalAccess/policies with @odata.nextLink.
- PS 5.1–safe JSON parsing (no TryGetProperty out params).
- Flattens common CA fields for easy CSV analysis.
- Logs like your existing functions.

.PARAMETER OutputDir
Default: Output\ConditionalAccessPolicies

.PARAMETER Encoding
Default: UTF8

.PARAMETER LogLevel
None | Minimal | Standard | Debug (Default: Standard)

.PARAMETER Output
CSV or JSON (Default: CSV)
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\ConditionalAccessPolicies",
        [string]$Encoding = "UTF8",
        [ValidateSet('None','Minimal','Standard','Debug')]
        [string]$LogLevel = 'Standard',
        [ValidateSet('CSV','JSON')]
        [string]$Output = 'CSV'
    )

    # ---- Logging / setup ----
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    if (-not (Test-Path $OutputDir)) { $null = New-Item -ItemType Directory -Force -Path $OutputDir }

    $dateTag = (Get-Date).ToString('yyyyMMddHHmmss')
    $outPath = Join-Path $OutputDir ("{0}-ConditionalAccessPolicy.{1}" -f $dateTag, $Output.ToLower())

    Write-LogFile -Message "=== Starting Conditional Access Policy Collection (fast) ===" -Color "Cyan" -Level Standard

    # ---- Tiny JSON helpers (PS5-safe) ----
    function J-GetStr {
        param([System.Text.Json.JsonElement]$E,[string]$Name)
        foreach ($p in $E.EnumerateObject()) { if ($p.Name -eq $Name) { if ($p.Value.ValueKind -eq 'String'){ return $p.Value.GetString() } return $p.Value.ToString() } }
        return $null
    }
    function J-GetElem {
        param([System.Text.Json.JsonElement]$E,[string]$Name)
        foreach ($p in $E.EnumerateObject()) { if ($p.Name -eq $Name) { return $p.Value } }
        return $null
    }
    function J-JoinStrArray {
        param([System.Text.Json.JsonElement]$E)
        if ($E.ValueKind -ne 'Array') { return '' }
        $list = New-Object System.Collections.Generic.List[string]
        for ($i=0; $i -lt $E.GetArrayLength(); $i++) {
            $v = $E[$i]
            if ($v.ValueKind -eq 'String') { [void]$list.Add($v.GetString()) }
            else { [void]$list.Add($v.ToString()) }
        }
        return ($list -join '; ')
    }
    function J-GetBool {
        param([System.Text.Json.JsonElement]$E,[string]$Name)
        foreach ($p in $E.EnumerateObject()) { if ($p.Name -eq $Name) {
            if ($p.Value.ValueKind -eq 'True') { return $true }
            if ($p.Value.ValueKind -eq 'False'){ return $false }
            return $null
        }}
        return $null
    }

    # ---- Pull & flatten policies ----
    $policies = New-Object System.Collections.Generic.List[object]

    $uri = "$($script:BaseGraphUri)/$($script:GraphVersion)/identity/conditionalAccess/policies"
    $page = 0
    do {
        $page++
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $p = $val[$i]

                    # Top-level basics
                    $id          = J-GetStr -E $p -Name 'id'
                    $displayName = J-GetStr -E $p -Name 'displayName'
                    $state       = J-GetStr -E $p -Name 'state'
                    $created     = J-GetStr -E $p -Name 'createdDateTime'
                    $modified    = J-GetStr -E $p -Name 'modifiedDateTime'

                    # Conditions
                    $conditions = J-GetElem -E $p -Name 'conditions'
                    $users      = if ($conditions.ValueKind -ne 'Undefined') { J-GetElem -E $conditions -Name 'users' } else { [System.Text.Json.JsonElement]::new() }
                    $apps       = if ($conditions.ValueKind -ne 'Undefined') { J-GetElem -E $conditions -Name 'applications' } else { [System.Text.Json.JsonElement]::new() }
                    $platforms  = if ($conditions.ValueKind -ne 'Undefined') { J-GetElem -E $conditions -Name 'platforms' } else { [System.Text.Json.JsonElement]::new() }
                    $locations  = if ($conditions.ValueKind -ne 'Undefined') { J-GetElem -E $conditions -Name 'locations' } else { [System.Text.Json.JsonElement]::new() }
                    $devices    = if ($conditions.ValueKind -ne 'Undefined') { J-GetElem -E $conditions -Name 'devices' } else { [System.Text.Json.JsonElement]::new() }

                    $includeUsers   = if ($users.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $users -Name 'includeUsers') } else { '' }
                    $excludeUsers   = if ($users.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $users -Name 'excludeUsers') } else { '' }
                    $includeGroups  = if ($users.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $users -Name 'includeGroups') } else { '' }
                    $excludeGroups  = if ($users.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $users -Name 'excludeGroups') } else { '' }
                    $includeRoles   = if ($users.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $users -Name 'includeRoles') } else { '' }
                    $excludeRoles   = if ($users.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $users -Name 'excludeRoles') } else { '' }

                    $includeApps    = if ($apps.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $apps -Name 'includeApplications') } else { '' }
                    $excludeApps    = if ($apps.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $apps -Name 'excludeApplications') } else { '' }
                    $clientAppsV2   = if ($conditions.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $conditions -Name 'clientAppTypes') } else { '' }

                    $includePlatforms = if ($platforms.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $platforms -Name 'includePlatforms') } else { '' }
                    $excludePlatforms = if ($platforms.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $platforms -Name 'excludePlatforms') } else { '' }

                    $includeLocations = if ($locations.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $locations -Name 'includeLocations') } else { '' }
                    $excludeLocations = if ($locations.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $locations -Name 'excludeLocations') } else { '' }

                    $userRiskLevels             = if ($conditions.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $conditions -Name 'userRiskLevels') } else { '' }
                    $signInRiskLevels           = if ($conditions.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $conditions -Name 'signInRiskLevels') } else { '' }
                    $servicePrincipalRiskLevels = if ($conditions.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $conditions -Name 'servicePrincipalRiskLevels') } else { '' }

                    $includeDeviceStates = ''
                    $excludeDeviceStates = ''
                    $deviceFilterMode    = ''
                    $deviceFilterRule    = ''
                    if ($devices.ValueKind -ne 'Undefined') {
                        $includeDeviceStates = J-JoinStrArray (J-GetElem -E $devices -Name 'includeDeviceStates')
                        $excludeDeviceStates = J-JoinStrArray (J-GetElem -E $devices -Name 'excludeDeviceStates')
                        $devFilter = J-GetElem -E $devices -Name 'deviceFilter'
                        if ($devFilter.ValueKind -ne 'Undefined') {
                            $deviceFilterMode = J-GetStr -E $devFilter -Name 'mode'
                            $deviceFilterRule = J-GetStr -E $devFilter -Name 'rule'
                        }
                    }

                    # Grant controls
                    $grant = J-GetElem -E $p -Name 'grantControls'
                    $builtInControls             = if ($grant.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $grant -Name 'builtInControls') } else { '' }
                    $customAuthenticationFactors = if ($grant.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $grant -Name 'customAuthenticationFactors') } else { '' }
                    $grantOperator               = if ($grant.ValueKind -ne 'Undefined') { J-GetStr -E $grant -Name 'operator' } else { '' }
                    $termsOfUse                  = if ($grant.ValueKind -ne 'Undefined') { J-JoinStrArray (J-GetElem -E $grant -Name 'termsOfUse') } else { '' }

                    # Session controls
                    $sess = J-GetElem -E $p -Name 'sessionControls'
                    $applicationEnforcedRestrictions = $null
                    $cloudAppSecurity                = $null
                    $disableResilienceDefaults       = $null
                    $persistentBrowserMode           = ''
                    $signInFreqVal                   = ''
                    if ($sess.ValueKind -ne 'Undefined') {
                        $aer = J-GetElem -E $sess -Name 'applicationEnforcedRestrictions'
                        if ($aer.ValueKind -ne 'Undefined') { $applicationEnforcedRestrictions = J-GetBool -E $aer -Name 'isEnabled' }
                        $cas = J-GetElem -E $sess -Name 'cloudAppSecurity'
                        if ($cas.ValueKind -ne 'Undefined') { $cloudAppSecurity = J-GetBool -E $cas -Name 'isEnabled' }
                        $disableResilienceDefaults = J-GetBool -E $sess -Name 'disableResilienceDefaults'
                        $pb = J-GetElem -E $sess -Name 'persistentBrowser'
                        if ($pb.ValueKind -ne 'Undefined') { $persistentBrowserMode = J-GetStr -E $pb -Name 'mode' }
                        $sif = J-GetElem -E $sess -Name 'signInFrequency'
                        if ($sif.ValueKind -ne 'Undefined') {
                            $v = J-GetStr -E $sif -Name 'value'
                            $t = J-GetStr -E $sif -Name 'type'
                            if ($v -and $t) { $signInFreqVal = "$v $t" }
                        }
                    }

                    $row = [pscustomobject]@{
                        id                               = $id
                        displayName                      = $displayName
                        state                            = $state
                        createdDateTime                  = $created
                        modifiedDateTime                 = $modified
                        includeUsers                     = $includeUsers
                        excludeUsers                     = $excludeUsers
                        includeGroups                    = $includeGroups
                        excludeGroups                    = $excludeGroups
                        includeRoles                     = $includeRoles
                        excludeRoles                     = $excludeRoles
                        includeApplications              = $includeApps
                        excludeApplications              = $excludeApps
                        includePlatforms                 = $includePlatforms
                        excludePlatforms                 = $excludePlatforms
                        includeLocations                 = $includeLocations
                        excludeLocations                 = $excludeLocations
                        userRiskLevels                   = $userRiskLevels
                        signInRiskLevels                 = $signInRiskLevels
                        servicePrincipalRiskLevels       = $servicePrincipalRiskLevels
                        includeDeviceStates              = $includeDeviceStates
                        excludeDeviceStates              = $excludeDeviceStates
                        deviceFilterMode                 = $deviceFilterMode
                        deviceFilterRule                 = $deviceFilterRule
                        builtInControls                  = $builtInControls
                        customAuthenticationFactors      = $customAuthenticationFactors
                        grantOperator                    = $grantOperator
                        termsOfUse                       = $termsOfUse
                        applicationEnforcedRestrictions  = $applicationEnforcedRestrictions
                        cloudAppSecurity                 = $cloudAppSecurity
                        disableResilienceDefaults        = $disableResilienceDefaults
                        persistentBrowser                = $persistentBrowserMode
                        signInFrequency                  = $signInFreqVal
                        clientAppsV2                     = $clientAppsV2
                    }
                    if ($isDebug) { Write-LogFile -Message "[DEBUG] Policy flattened: $displayName ($id)" -Level Debug }
                    [void]$policies.Add($row)
                }
            }

            # nextLink (PS5-safe)
            $next = $null
            foreach ($p2 in $root.EnumerateObject()) {
                if ($p2.Name -eq '@odata.nextLink') { $next = $p2.Value.GetString(); break }
            }
            $uri = $next
        }
        finally { $doc.Dispose() }
    } while ($uri)

    # ---- Export ----
    if ($Output -eq 'CSV') {
        $policies | Export-Csv -NoTypeInformation -Path $outPath -Encoding $Encoding
    } else {
        $policies | ConvertTo-Json -Depth 6 | Out-File -FilePath $outPath -Encoding $Encoding
    }

    # ---- Summary ----
    $enabled = 0; $disabled = 0
    foreach ($r in $policies) {
        if ($r.state -eq 'enabled') { $enabled++ }
        elseif ($r.state -eq 'disabled') { $disabled++ }
    }
    Write-LogFile -Message "`n=== Conditional Access Policy Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Total Policies : $($policies.Count)" -Level Standard
    Write-LogFile -Message "Enabled        : $enabled" -Level Standard
    Write-LogFile -Message "Disabled       : $disabled" -Level Standard
    Write-LogFile -Message "Output         : $outPath" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
