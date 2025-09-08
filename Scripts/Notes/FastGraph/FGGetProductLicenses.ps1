# ===== PS5-safe JSON helpers (same as before) =====
function J-GetElem { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ return $p.Value } } $null }
function J-GetStr  { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ if($p.Value.ValueKind -eq 'String'){return $p.Value.GetString()} return $p.Value.ToString() } } $null }
function J-HasName { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ return $true } } $false }

# ──────────────────────────────────────────────────────────────────────────────
function Get-LicensesFast {
<#
.SYNOPSIS
High-throughput tenant SKU export with retention/premium hints (REST + HttpClient).

.OUTPUT
CSV to Output\Licenses\<timestamp>-TenantLicenses.csv and a formatted table to console.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    Write-LogFile -Message "=== Starting License Collection (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir

    # Ensure auth
    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Pull /subscribedSkus paged
    $results = New-Object System.Collections.Generic.List[object]
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $skuPart = J-GetStr -E $e -Name 'skuPartNumber'
                    $cap     = J-GetStr -E $e -Name 'capabilityStatus'
                    $applies = J-GetStr -E $e -Name 'appliesTo'
                    $consumed= 0
                    foreach ($p in $e.EnumerateObject()) { if ($p.Name -eq 'consumedUnits') { try{ $consumed = $p.Value.GetInt32() }catch{ $consumed = [int]$p.Value.GetDouble() }; break } }

                    # servicePlans → list of names
                    $svcPlans = @()
                    foreach ($p in $e.EnumerateObject()) {
                        if ($p.Name -eq 'servicePlans' -and $p.Value.ValueKind -eq 'Array') {
                            for ($j=0; $j -lt $p.Value.GetArrayLength(); $j++) {
                                $sp = $p.Value[$j]
                                $name = J-GetStr -E $sp -Name 'servicePlanName'
                                if ($name) { $svcPlans += $name }
                            }
                        }
                    }

                    # Keep your original heuristics
                    $svcSet = $svcPlans
                    $retention = if ($skuPart -match 'E5') { '365 days' } elseif ($skuPart -match 'E3') { '180 days' } else { '90 days' }
                    $E3 = @('M365ENTERPRISE','ENTERPRISEPACK','STANDARD_EDU') -contains $skuPart ? 'Yes' : 'No'
                    $E5 = @('SPE_E5','ENTERPRISEPREMIUM') -contains $skuPart ? 'Yes' : 'No'
                    $P1 = ($svcSet -contains 'AAD_PREMIUM') ? 'Yes' : 'No'
                    $P2 = ($svcSet -contains 'AAD_PREMIUM_P2') ? 'Yes' : 'No'
                    $DefID    = ($svcSet -contains 'MDE_ATP') ? 'Yes' : 'No'
                    $Def365P1 = ($svcSet -contains 'ATP_ENTERPRISE') ? 'Yes' : 'No'
                    $Def365P2 = ($svcSet -contains 'ATP_ENTERPRISE_PLUS') ? 'Yes' : 'No'

                    [void]$results.Add([pscustomobject]@{
                        Sku           = $skuPart
                        Status        = $cap
                        Scope         = $applies
                        Units         = $consumed
                        Retention     = $retention
                        E3            = $E3
                        E5            = $E5
                        P1            = $P1
                        P2            = $P2
                        DefenderID    = $DefID
                        Defender365P1 = $Def365P1
                        Defender365P2 = $Def365P2
                        ServicePlans  = ($svcPlans -join '; ')
                    })
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    if ($results.Count -eq 0) {
        Write-LogFile -Message "[ERROR] No licenses found in the tenant." -Color "Red" -Level Minimal
        return
    }

    $date = (Get-Date).ToString('yyyyMMddHHmmss')
    $out = Join-Path $OutputDir "$date-TenantLicenses.csv"
    $results | Sort-Object Units -Descending | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
    Write-LogFile -Message "[INFO] License information saved to: $out" -Color "Green" -Level Standard

    $results |
        Sort-Object Units -Descending |
        Format-Table -AutoSize -Property @(
            @{Label='License Name'; Expression={$_.Sku}; Width=30},
            @{Label='Status';       Expression={$_.Status}; Width=10},
            @{Label='Units';        Expression={$_.Units};  Width=8; Alignment='Right'},
            @{Label='Retention';    Expression={$_.Retention}; Width=12},
            'E3','E5','P1','P2','DefenderID','Defender365P1','Defender365P2'
        )
}

# ──────────────────────────────────────────────────────────────────────────────
function Get-LicenseCompatibilityFast {
<#
.SYNOPSIS
Checks presence of E5/E3/P1/P2 (fast REST) and prints capability notes.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard',
        [string]$OutputDir = "Output\Licenses"
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    UpsertOutputDirectory $OutputDir
    Write-LogFile -Message "=== Starting License Compatibility Check (fast) ===" -Color "Cyan" -Level Standard

    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Pull all SKUs once
    $svcPlansAll = New-Object System.Collections.Generic.List[string]
    $e5 = $false; $e3 = $false
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $skuPart = J-GetStr -E $e -Name 'skuPartNumber'
                    if ($skuPart -match 'E5') { $e5 = $true }
                    if ($skuPart -match 'E3') { $e3 = $true }
                    foreach ($p in $e.EnumerateObject()) {
                        if ($p.Name -eq 'servicePlans' -and $p.Value.ValueKind -eq 'Array') {
                            for ($j=0; $j -lt $p.Value.GetArrayLength(); $j++) {
                                $sp = $p.Value[$j]
                                $n = J-GetStr -E $sp -Name 'servicePlanName'
                                if ($n) { $svcPlansAll.Add($n) }
                            }
                        }
                    }
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    $p1 = $svcPlansAll -contains 'AAD_PREMIUM'
    $p2 = $svcPlansAll -contains 'AAD_PREMIUM_P2'

    Write-LogFile -Message "`nLicense Status:" -Color "Cyan" -Level Standard
    Write-LogFile -Message ("E5: " + ($(if($e5){"Present"}else{"Not Present"}))) -Color ($(if($e5){"Green"}else{"Yellow"})) -Level Standard
    if (-not $e5) {
        Write-LogFile -Message ("E3: " + ($(if($e3){"Present"}else{"Not Present"}))) -Color ($(if($e3){"Green"}else{"Yellow"})) -Level Standard
    }
    Write-LogFile -Message ("P2: " + ($(if($p2){"Present"}else{"Not Present"}))) -Color ($(if($p2){"Green"}else{"Yellow"})) -Level Standard
    if (-not ($p2 -or $e5)) {
        Write-LogFile -Message ("P1: " + ($(if($p1){"Present"}else{"Not Present"}))) -Color ($(if($p1){"Green"}else{"Yellow"})) -Level Standard
    }

    Write-LogFile -Message "`nFeature Compatibility:" -Color "Cyan" -Level Standard
    $features = @(
        @{Feature='Get-Sessions';             Required='E5';        Ok=$e5}
        @{Feature='Get-MessageIDs';           Required='E5';        Ok=$e5}
        @{Feature='Get-GraphEntraAuditLogs';  Required='E5';        Ok=$e5}
        @{Feature='Get-RiskyUsers';           Required='E5 or P2';  Ok=($e5 -or $p2)}
    )
    foreach ($f in $features) {
        Write-LogFile -Message ("{0} ({1}): {2}" -f $f.Feature,$f.Required,($(if($f.Ok){"Available"}else{"Not Available"}))) -Color ($(if($f.Ok){"Green"}else{"Yellow"})) -Level Standard
    }

    Write-LogFile -Message "`nRetention Information:" -Color "Cyan" -Level Standard
    if ($e3 -or $e5 -or $p1 -or $p2) {
        Write-LogFile -Message "Audit Log retention: 30 days" -Color "Green" -Level Standard
        Write-LogFile -Message "Sign-in Log retention: 30 days" -Color "Green" -Level Standard
    } else {
        Write-LogFile -Message "Audit Log retention: 7 days" -Color "Yellow" -Level Standard
        Write-LogFile -Message "Sign-in Log retention: 7 days" -Color "Yellow" -Level Standard
    }
}

# ──────────────────────────────────────────────────────────────────────────────
function Get-EntraSecurityDefaultsFast {
<#
.SYNOPSIS
Reads the tenant security defaults policy quickly via REST and prints guidance.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    UpsertOutputDirectory $OutputDir
    Write-LogFile -Message "=== Starting Security Defaults Check (fast) ===" -Color "Cyan" -Level Standard

    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Pull security defaults policy
    $doc = Invoke-GraphGet -Uri "$($script:BaseGraphUri)/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    $isEnabled = $false
    try {
        $root = $doc.RootElement
        $isEnabled = [bool]::Parse((J-GetStr -E $root -Name 'isEnabled'))
    } finally { $doc.Dispose() }

    # We’d like to know premium context too
    $hasPremium = $false
    $svcPlansAll = New-Object System.Collections.Generic.List[string]
    $e5=$false;$e3=$false;$p1=$false;$p2=$false
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $d2 = Invoke-GraphGet -Uri $uri
        try {
            $root2 = $d2.RootElement
            $val  = J-GetElem -E $root2 -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $skuPart = J-GetStr -E $e -Name 'skuPartNumber'
                    if ($skuPart -match 'E5') { $e5 = $true }
                    if ($skuPart -match 'E3') { $e3 = $true }
                    foreach ($p in $e.EnumerateObject()) {
                        if ($p.Name -eq 'servicePlans' -and $p.Value.ValueKind -eq 'Array') {
                            for ($j=0; $j -lt $p.Value.GetArrayLength(); $j++) {
                                $sp = $p.Value[$j]
                                $n = J-GetStr -E $sp -Name 'servicePlanName'
                                if ($n) { $svcPlansAll.Add($n) }
                            }
                        }
                    }
                }
            }
            $next = $null
            foreach ($p in $root2.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $d2.Dispose() }
    } while ($uri)
    $p1 = $svcPlansAll -contains 'AAD_PREMIUM'
    $p2 = $svcPlansAll -contains 'AAD_PREMIUM_P2'
    $hasPremium = ($e5 -or $e3 -or $p1 -or $p2)

    Write-LogFile -Message "`nSecurity Defaults Status:" -Color "Cyan" -Level Standard
    Write-LogFile -Message ("Security Defaults: " + ($(if($isEnabled){"Enabled"}else{"Disabled"}))) -Color ($(if($isEnabled){"Green"}else{"Yellow"})) -Level Standard

    Write-LogFile -Message "`nLicense Context:" -Color "Cyan" -Level Standard
    if ($hasPremium) {
        Write-LogFile -Message "Premium License(s) Detected:" -Level Standard
        if ($e5) { Write-LogFile -Message "  - E5" -Level Standard }
        if ($e3 -and -not $e5) { Write-LogFile -Message "  - E3" -Level Standard }
        if ($p2 -and -not $e5) { Write-LogFile -Message "  - P2" -Level Standard }
        if ($p1 -and -not ($p2 -or $e5)) { Write-LogFile -Message "  - P1" -Level Standard }
    } else {
        Write-LogFile -Message "No Premium Licenses Detected" -Level Standard
    }

    Write-LogFile -Message "`nRecommendations:" -Color "Cyan" -Level Standard
    if ($hasPremium) {
        if ($isEnabled) {
            Write-LogFile -Message "[!] With Premium, consider disabling Security Defaults and enforcing MFA/controls via Conditional Access." -Color "Yellow" -Level Standard
        } else {
            Write-LogFile -Message "Current configuration aligns with Microsoft recommendations for Premium tenants." -Color "Green" -Level Standard
        }
    } else {
        if ($isEnabled) {
            Write-LogFile -Message "Security Defaults is appropriate for basic licenses." -Color "Green" -Level Standard
        } else {
            Write-LogFile -Message "[!] With Basic licensing, enable Security Defaults for baseline protection." -Color "Red" -Level Minimal
        }
    }

    # Optional CSV drop like your original
    $date = (Get-Date).ToString('yyyyMMddHHmmss')
    $out = Join-Path $OutputDir "$date-EntraSecurityDefaults.csv"
    [pscustomobject]@{
        SecurityDefaultsEnabled     = $(if ($isEnabled) {'Yes'} else {'No'})
        HasPremiumLicense           = $(if ($hasPremium) {'Yes'} else {'No'})
        RecommendedState            = $(if ($hasPremium) {'Disabled'} else {'Enabled'})
        AlignedWithRecommendations  = $(if (($hasPremium -and -not $isEnabled) -or (-not $hasPremium -and $isEnabled)) {'Yes'} else {'No'})
        CheckDate                   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
    Write-LogFile -Message "`nOutput file: $out" -Level Standard
}

# ──────────────────────────────────────────────────────────────────────────────
function Get-LicensesByUserFast {
<#
.SYNOPSIS
Tenant-wide user license assignments using Graph $batch for /users/{id}/licenseDetails (20/request).

.OUTPUT
CSV: Output\Licenses\<timestamp>-UserLicenses.csv
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    UpsertOutputDirectory $OutputDir
    Write-LogFile -Message "=== Starting User License Collection (fast) ===" -Color "Cyan" -Level Standard

    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Map SkuId -> SkuPartNumber
    $skuMap = @{}
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $id  = J-GetStr -E $e -Name 'skuId'
                    $pn  = J-GetStr -E $e -Name 'skuPartNumber'
                    if ($id) { $skuMap[$id] = $pn }
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    # Get users (id, displayName, userPrincipalName)
    $users = New-Object System.Collections.Generic.List[object]
    $uri = "$($script:BaseGraphUri)/v1.0/users?`$select=id,displayName,userPrincipalName&`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e   = $val[$i]
                    $id  = J-GetStr -E $e -Name 'id'
                    $dn  = J-GetStr -E $e -Name 'displayName'
                    $upn = J-GetStr -E $e -Name 'userPrincipalName'
                    if ($id) { [void]$users.Add([pscustomobject]@{ id=$id; displayName=$dn; upn=$upn }) }
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    if ($users.Count -eq 0) {
        Write-LogFile -Message "[ERROR] No users retrieved." -Color "Red" -Level Minimal
        return
    }

    $date = (Get-Date).ToString('yyyyMMddHHmmss')
    $out = Join-Path $OutputDir "$date-UserLicenses.csv"
    $sw = New-Object System.IO.StreamWriter($out,$false,[System.Text.Encoding]::UTF8)
    try {
        $sw.WriteLine('DisplayName,UserPrincipalName,SkuPartNumber')

        # Batch licenseDetails 20 at a time
        for ($i=0; $i -lt $users.Count; $i+=20) {
            $chunk = $users[$i..([Math]::Min($i+19,$users.Count-1))]
            $reqs = New-Object System.Collections.Generic.List[object]
            foreach ($u in $chunk) { $reqs.Add(@{ id = $u.id; method='GET'; url="users/$($u.id)/licenseDetails" }) }
            $resp = Invoke-GffBatch -Requests $reqs

            foreach ($r in $resp.responses) {
                $uid = $r.id
                $u = $chunk | Where-Object { $_.id -eq $uid } | Select-Object -First 1
                if (-not $u) { continue }

                if ($r.status -ge 200 -and $r.status -lt 300 -and $r.body) {
                    $vals = $r.body.value
                    if ($vals -and $vals.Count -gt 0) {
                        foreach ($ld in $vals) {
                            $pn = $skuMap[[string]$ld.skuId]
                            if (-not $pn) { $pn = [string]$ld.skuId }
                            $sw.WriteLine(("{0},{1},{2}" -f ($u.displayName -replace ',',''), $u.upn, ($pn -replace ',','')))
                        }
                    } else {
                        $sw.WriteLine(("{0},{1},{2}" -f ($u.displayName -replace ',',''), $u.upn, 'None'))
                    }
                } else {
                    # On error, still emit a line to keep accounting
                    $sw.WriteLine(("{0},{1},{2}" -f ($u.displayName -replace ',',''), $u.upn, 'Error'))
                    Write-LogFile -Message "[WARNING] licenseDetails request failed for $($u.upn) (status=$($r.status))" -Level Standard -Color "Yellow"
                }
            }
        }
    } finally { $sw.Flush(); $sw.Dispose() }

    # Quick summary to console (read back once)
    $csv = Import-Csv -Path $out
    $totalUsers = $users.Count
    $licensedUsers = ($csv | Where-Object { $_.SkuPartNumber -ne 'None' -and $_.SkuPartNumber -ne 'Error' } | Select-Object -Unique UserPrincipalName).Count
    $unlicensed   = $totalUsers - $licensedUsers
    $assignments  = ($csv | Where-Object { $_.SkuPartNumber -ne 'None' -and $_.SkuPartNumber -ne 'Error' }).Count
    $dist = $csv | Where-Object { $_.SkuPartNumber -notin @('None','Error') } | Group-Object SkuPartNumber | Sort-Object Count -Descending

    Write-LogFile -Message "`nUser License Summary:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Total Users: $totalUsers" -Level Standard
    Write-LogFile -Message "  - Total License Assignments: $assignments" -Level Standard
    Write-LogFile -Message "  - Licensed Users: $licensedUsers" -Level Standard
    Write-LogFile -Message "  - Unlicensed Users: $unlicensed" -Level Standard

    Write-LogFile -Message "`nLicense Type Distribution:" -Color "Cyan" -Level Standard
    foreach ($d in $dist) {
        Write-LogFile -Message ("  - {0}: {1} assignments" -f $d.Name,$d.Count) -Level Standard
    }
    Write-LogFile -Message "`nExported File:`n  - File: $out" -Level Standard
}
# ===== PS5-safe JSON helpers (same as before) =====
function J-GetElem { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ return $p.Value } } $null }
function J-GetStr  { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ if($p.Value.ValueKind -eq 'String'){return $p.Value.GetString()} return $p.Value.ToString() } } $null }
function J-HasName { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ return $true } } $false }

# ──────────────────────────────────────────────────────────────────────────────
function Get-LicensesFast {
<#
.SYNOPSIS
High-throughput tenant SKU export with retention/premium hints (REST + HttpClient).

.OUTPUT
CSV to Output\Licenses\<timestamp>-TenantLicenses.csv and a formatted table to console.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    Write-LogFile -Message "=== Starting License Collection (fast) ===" -Color "Cyan" -Level Standard
    UpsertOutputDirectory $OutputDir

    # Ensure auth
    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Pull /subscribedSkus paged
    $results = New-Object System.Collections.Generic.List[object]
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $skuPart = J-GetStr -E $e -Name 'skuPartNumber'
                    $cap     = J-GetStr -E $e -Name 'capabilityStatus'
                    $applies = J-GetStr -E $e -Name 'appliesTo'
                    $consumed= 0
                    foreach ($p in $e.EnumerateObject()) { if ($p.Name -eq 'consumedUnits') { try{ $consumed = $p.Value.GetInt32() }catch{ $consumed = [int]$p.Value.GetDouble() }; break } }

                    # servicePlans → list of names
                    $svcPlans = @()
                    foreach ($p in $e.EnumerateObject()) {
                        if ($p.Name -eq 'servicePlans' -and $p.Value.ValueKind -eq 'Array') {
                            for ($j=0; $j -lt $p.Value.GetArrayLength(); $j++) {
                                $sp = $p.Value[$j]
                                $name = J-GetStr -E $sp -Name 'servicePlanName'
                                if ($name) { $svcPlans += $name }
                            }
                        }
                    }

                    # Keep your original heuristics
                    $svcSet = $svcPlans
                    $retention = if ($skuPart -match 'E5') { '365 days' } elseif ($skuPart -match 'E3') { '180 days' } else { '90 days' }
                    $E3 = @('M365ENTERPRISE','ENTERPRISEPACK','STANDARD_EDU') -contains $skuPart ? 'Yes' : 'No'
                    $E5 = @('SPE_E5','ENTERPRISEPREMIUM') -contains $skuPart ? 'Yes' : 'No'
                    $P1 = ($svcSet -contains 'AAD_PREMIUM') ? 'Yes' : 'No'
                    $P2 = ($svcSet -contains 'AAD_PREMIUM_P2') ? 'Yes' : 'No'
                    $DefID    = ($svcSet -contains 'MDE_ATP') ? 'Yes' : 'No'
                    $Def365P1 = ($svcSet -contains 'ATP_ENTERPRISE') ? 'Yes' : 'No'
                    $Def365P2 = ($svcSet -contains 'ATP_ENTERPRISE_PLUS') ? 'Yes' : 'No'

                    [void]$results.Add([pscustomobject]@{
                        Sku           = $skuPart
                        Status        = $cap
                        Scope         = $applies
                        Units         = $consumed
                        Retention     = $retention
                        E3            = $E3
                        E5            = $E5
                        P1            = $P1
                        P2            = $P2
                        DefenderID    = $DefID
                        Defender365P1 = $Def365P1
                        Defender365P2 = $Def365P2
                        ServicePlans  = ($svcPlans -join '; ')
                    })
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    if ($results.Count -eq 0) {
        Write-LogFile -Message "[ERROR] No licenses found in the tenant." -Color "Red" -Level Minimal
        return
    }

    $date = (Get-Date).ToString('yyyyMMddHHmmss')
    $out = Join-Path $OutputDir "$date-TenantLicenses.csv"
    $results | Sort-Object Units -Descending | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
    Write-LogFile -Message "[INFO] License information saved to: $out" -Color "Green" -Level Standard

    $results |
        Sort-Object Units -Descending |
        Format-Table -AutoSize -Property @(
            @{Label='License Name'; Expression={$_.Sku}; Width=30},
            @{Label='Status';       Expression={$_.Status}; Width=10},
            @{Label='Units';        Expression={$_.Units};  Width=8; Alignment='Right'},
            @{Label='Retention';    Expression={$_.Retention}; Width=12},
            'E3','E5','P1','P2','DefenderID','Defender365P1','Defender365P2'
        )
}

# ──────────────────────────────────────────────────────────────────────────────
function Get-LicenseCompatibilityFast {
<#
.SYNOPSIS
Checks presence of E5/E3/P1/P2 (fast REST) and prints capability notes.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard',
        [string]$OutputDir = "Output\Licenses"
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    UpsertOutputDirectory $OutputDir
    Write-LogFile -Message "=== Starting License Compatibility Check (fast) ===" -Color "Cyan" -Level Standard

    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Pull all SKUs once
    $svcPlansAll = New-Object System.Collections.Generic.List[string]
    $e5 = $false; $e3 = $false
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $skuPart = J-GetStr -E $e -Name 'skuPartNumber'
                    if ($skuPart -match 'E5') { $e5 = $true }
                    if ($skuPart -match 'E3') { $e3 = $true }
                    foreach ($p in $e.EnumerateObject()) {
                        if ($p.Name -eq 'servicePlans' -and $p.Value.ValueKind -eq 'Array') {
                            for ($j=0; $j -lt $p.Value.GetArrayLength(); $j++) {
                                $sp = $p.Value[$j]
                                $n = J-GetStr -E $sp -Name 'servicePlanName'
                                if ($n) { $svcPlansAll.Add($n) }
                            }
                        }
                    }
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    $p1 = $svcPlansAll -contains 'AAD_PREMIUM'
    $p2 = $svcPlansAll -contains 'AAD_PREMIUM_P2'

    Write-LogFile -Message "`nLicense Status:" -Color "Cyan" -Level Standard
    Write-LogFile -Message ("E5: " + ($(if($e5){"Present"}else{"Not Present"}))) -Color ($(if($e5){"Green"}else{"Yellow"})) -Level Standard
    if (-not $e5) {
        Write-LogFile -Message ("E3: " + ($(if($e3){"Present"}else{"Not Present"}))) -Color ($(if($e3){"Green"}else{"Yellow"})) -Level Standard
    }
    Write-LogFile -Message ("P2: " + ($(if($p2){"Present"}else{"Not Present"}))) -Color ($(if($p2){"Green"}else{"Yellow"})) -Level Standard
    if (-not ($p2 -or $e5)) {
        Write-LogFile -Message ("P1: " + ($(if($p1){"Present"}else{"Not Present"}))) -Color ($(if($p1){"Green"}else{"Yellow"})) -Level Standard
    }

    Write-LogFile -Message "`nFeature Compatibility:" -Color "Cyan" -Level Standard
    $features = @(
        @{Feature='Get-Sessions';             Required='E5';        Ok=$e5}
        @{Feature='Get-MessageIDs';           Required='E5';        Ok=$e5}
        @{Feature='Get-GraphEntraAuditLogs';  Required='E5';        Ok=$e5}
        @{Feature='Get-RiskyUsers';           Required='E5 or P2';  Ok=($e5 -or $p2)}
    )
    foreach ($f in $features) {
        Write-LogFile -Message ("{0} ({1}): {2}" -f $f.Feature,$f.Required,($(if($f.Ok){"Available"}else{"Not Available"}))) -Color ($(if($f.Ok){"Green"}else{"Yellow"})) -Level Standard
    }

    Write-LogFile -Message "`nRetention Information:" -Color "Cyan" -Level Standard
    if ($e3 -or $e5 -or $p1 -or $p2) {
        Write-LogFile -Message "Audit Log retention: 30 days" -Color "Green" -Level Standard
        Write-LogFile -Message "Sign-in Log retention: 30 days" -Color "Green" -Level Standard
    } else {
        Write-LogFile -Message "Audit Log retention: 7 days" -Color "Yellow" -Level Standard
        Write-LogFile -Message "Sign-in Log retention: 7 days" -Color "Yellow" -Level Standard
    }
}

# ──────────────────────────────────────────────────────────────────────────────
function Get-EntraSecurityDefaultsFast {
<#
.SYNOPSIS
Reads the tenant security defaults policy quickly via REST and prints guidance.
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    UpsertOutputDirectory $OutputDir
    Write-LogFile -Message "=== Starting Security Defaults Check (fast) ===" -Color "Cyan" -Level Standard

    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Pull security defaults policy
    $doc = Invoke-GraphGet -Uri "$($script:BaseGraphUri)/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    $isEnabled = $false
    try {
        $root = $doc.RootElement
        $isEnabled = [bool]::Parse((J-GetStr -E $root -Name 'isEnabled'))
    } finally { $doc.Dispose() }

    # We’d like to know premium context too
    $hasPremium = $false
    $svcPlansAll = New-Object System.Collections.Generic.List[string]
    $e5=$false;$e3=$false;$p1=$false;$p2=$false
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $d2 = Invoke-GraphGet -Uri $uri
        try {
            $root2 = $d2.RootElement
            $val  = J-GetElem -E $root2 -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $skuPart = J-GetStr -E $e -Name 'skuPartNumber'
                    if ($skuPart -match 'E5') { $e5 = $true }
                    if ($skuPart -match 'E3') { $e3 = $true }
                    foreach ($p in $e.EnumerateObject()) {
                        if ($p.Name -eq 'servicePlans' -and $p.Value.ValueKind -eq 'Array') {
                            for ($j=0; $j -lt $p.Value.GetArrayLength(); $j++) {
                                $sp = $p.Value[$j]
                                $n = J-GetStr -E $sp -Name 'servicePlanName'
                                if ($n) { $svcPlansAll.Add($n) }
                            }
                        }
                    }
                }
            }
            $next = $null
            foreach ($p in $root2.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $d2.Dispose() }
    } while ($uri)
    $p1 = $svcPlansAll -contains 'AAD_PREMIUM'
    $p2 = $svcPlansAll -contains 'AAD_PREMIUM_P2'
    $hasPremium = ($e5 -or $e3 -or $p1 -or $p2)

    Write-LogFile -Message "`nSecurity Defaults Status:" -Color "Cyan" -Level Standard
    Write-LogFile -Message ("Security Defaults: " + ($(if($isEnabled){"Enabled"}else{"Disabled"}))) -Color ($(if($isEnabled){"Green"}else{"Yellow"})) -Level Standard

    Write-LogFile -Message "`nLicense Context:" -Color "Cyan" -Level Standard
    if ($hasPremium) {
        Write-LogFile -Message "Premium License(s) Detected:" -Level Standard
        if ($e5) { Write-LogFile -Message "  - E5" -Level Standard }
        if ($e3 -and -not $e5) { Write-LogFile -Message "  - E3" -Level Standard }
        if ($p2 -and -not $e5) { Write-LogFile -Message "  - P2" -Level Standard }
        if ($p1 -and -not ($p2 -or $e5)) { Write-LogFile -Message "  - P1" -Level Standard }
    } else {
        Write-LogFile -Message "No Premium Licenses Detected" -Level Standard
    }

    Write-LogFile -Message "`nRecommendations:" -Color "Cyan" -Level Standard
    if ($hasPremium) {
        if ($isEnabled) {
            Write-LogFile -Message "[!] With Premium, consider disabling Security Defaults and enforcing MFA/controls via Conditional Access." -Color "Yellow" -Level Standard
        } else {
            Write-LogFile -Message "Current configuration aligns with Microsoft recommendations for Premium tenants." -Color "Green" -Level Standard
        }
    } else {
        if ($isEnabled) {
            Write-LogFile -Message "Security Defaults is appropriate for basic licenses." -Color "Green" -Level Standard
        } else {
            Write-LogFile -Message "[!] With Basic licensing, enable Security Defaults for baseline protection." -Color "Red" -Level Minimal
        }
    }

    # Optional CSV drop like your original
    $date = (Get-Date).ToString('yyyyMMddHHmmss')
    $out = Join-Path $OutputDir "$date-EntraSecurityDefaults.csv"
    [pscustomobject]@{
        SecurityDefaultsEnabled     = $(if ($isEnabled) {'Yes'} else {'No'})
        HasPremiumLicense           = $(if ($hasPremium) {'Yes'} else {'No'})
        RecommendedState            = $(if ($hasPremium) {'Disabled'} else {'Enabled'})
        AlignedWithRecommendations  = $(if (($hasPremium -and -not $isEnabled) -or (-not $hasPremium -and $isEnabled)) {'Yes'} else {'No'})
        CheckDate                   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    } | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
    Write-LogFile -Message "`nOutput file: $out" -Level Standard
}

# ──────────────────────────────────────────────────────────────────────────────
function Get-LicensesByUserFast {
<#
.SYNOPSIS
Tenant-wide user license assignments using Graph $batch for /users/{id}/licenseDetails (20/request).

.OUTPUT
CSV: Output\Licenses\<timestamp>-UserLicenses.csv
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\Licenses",
        [ValidateSet('None','Minimal','Standard','Debug')] [string]$LogLevel = 'Standard'
    )
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug
    UpsertOutputDirectory $OutputDir
    Write-LogFile -Message "=== Starting User License Collection (fast) ===" -Color "Cyan" -Level Standard

    $reqScopes = @('Directory.Read.All')
    $null = Get-GraphAuthType -RequiredScopes $reqScopes

    # Map SkuId -> SkuPartNumber
    $skuMap = @{}
    $uri = "$($script:BaseGraphUri)/v1.0/subscribedSkus?`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $id  = J-GetStr -E $e -Name 'skuId'
                    $pn  = J-GetStr -E $e -Name 'skuPartNumber'
                    if ($id) { $skuMap[$id] = $pn }
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    # Get users (id, displayName, userPrincipalName)
    $users = New-Object System.Collections.Generic.List[object]
    $uri = "$($script:BaseGraphUri)/v1.0/users?`$select=id,displayName,userPrincipalName&`$top=999"
    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e   = $val[$i]
                    $id  = J-GetStr -E $e -Name 'id'
                    $dn  = J-GetStr -E $e -Name 'displayName'
                    $upn = J-GetStr -E $e -Name 'userPrincipalName'
                    if ($id) { [void]$users.Add([pscustomobject]@{ id=$id; displayName=$dn; upn=$upn }) }
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink'){ $next = $p.Value.GetString(); break } }
            $uri = $next
        } finally { $doc.Dispose() }
    } while ($uri)

    if ($users.Count -eq 0) {
        Write-LogFile -Message "[ERROR] No users retrieved." -Color "Red" -Level Minimal
        return
    }

    $date = (Get-Date).ToString('yyyyMMddHHmmss')
    $out = Join-Path $OutputDir "$date-UserLicenses.csv"
    $sw = New-Object System.IO.StreamWriter($out,$false,[System.Text.Encoding]::UTF8)
    try {
        $sw.WriteLine('DisplayName,UserPrincipalName,SkuPartNumber')

        # Batch licenseDetails 20 at a time
        for ($i=0; $i -lt $users.Count; $i+=20) {
            $chunk = $users[$i..([Math]::Min($i+19,$users.Count-1))]
            $reqs = New-Object System.Collections.Generic.List[object]
            foreach ($u in $chunk) { $reqs.Add(@{ id = $u.id; method='GET'; url="users/$($u.id)/licenseDetails" }) }
            $resp = Invoke-GffBatch -Requests $reqs

            foreach ($r in $resp.responses) {
                $uid = $r.id
                $u = $chunk | Where-Object { $_.id -eq $uid } | Select-Object -First 1
                if (-not $u) { continue }

                if ($r.status -ge 200 -and $r.status -lt 300 -and $r.body) {
                    $vals = $r.body.value
                    if ($vals -and $vals.Count -gt 0) {
                        foreach ($ld in $vals) {
                            $pn = $skuMap[[string]$ld.skuId]
                            if (-not $pn) { $pn = [string]$ld.skuId }
                            $sw.WriteLine(("{0},{1},{2}" -f ($u.displayName -replace ',',''), $u.upn, ($pn -replace ',','')))
                        }
                    } else {
                        $sw.WriteLine(("{0},{1},{2}" -f ($u.displayName -replace ',',''), $u.upn, 'None'))
                    }
                } else {
                    # On error, still emit a line to keep accounting
                    $sw.WriteLine(("{0},{1},{2}" -f ($u.displayName -replace ',',''), $u.upn, 'Error'))
                    Write-LogFile -Message "[WARNING] licenseDetails request failed for $($u.upn) (status=$($r.status))" -Level Standard -Color "Yellow"
                }
            }
        }
    } finally { $sw.Flush(); $sw.Dispose() }

    # Quick summary to console (read back once)
    $csv = Import-Csv -Path $out
    $totalUsers = $users.Count
    $licensedUsers = ($csv | Where-Object { $_.SkuPartNumber -ne 'None' -and $_.SkuPartNumber -ne 'Error' } | Select-Object -Unique UserPrincipalName).Count
    $unlicensed   = $totalUsers - $licensedUsers
    $assignments  = ($csv | Where-Object { $_.SkuPartNumber -ne 'None' -and $_.SkuPartNumber -ne 'Error' }).Count
    $dist = $csv | Where-Object { $_.SkuPartNumber -notin @('None','Error') } | Group-Object SkuPartNumber | Sort-Object Count -Descending

    Write-LogFile -Message "`nUser License Summary:" -Color "Cyan" -Level Standard
    Write-LogFile -Message "Total Users: $totalUsers" -Level Standard
    Write-LogFile -Message "  - Total License Assignments: $assignments" -Level Standard
    Write-LogFile -Message "  - Licensed Users: $licensedUsers" -Level Standard
    Write-LogFile -Message "  - Unlicensed Users: $unlicensed" -Level Standard

    Write-LogFile -Message "`nLicense Type Distribution:" -Color "Cyan" -Level Standard
    foreach ($d in $dist) {
        Write-LogFile -Message ("  - {0}: {1} assignments" -f $d.Name,$d.Count) -Level Standard
    }
    Write-LogFile -Message "`nExported File:`n  - File: $out" -Level Standard
}
