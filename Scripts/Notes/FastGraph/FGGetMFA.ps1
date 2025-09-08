function Get-MFAFast {
<#
.SYNOPSIS
High-throughput MFA status export using Graph REST, reusable HttpClient, and Graph $batch.

.DESCRIPTION
- Pulls users (optionally filtered by -UserIds).
- Batches per-user calls to /users/{id}/authentication/methods (20/request).
- Streams results to CSV (no pipeline churn).
- Collects /reports/authenticationMethods/userRegistrationDetails and (optionally) appends phone columns.

.PARAMETER OutputDir
Default: Output\MFA

.PARAMETER Encoding
CSV encoding. Default UTF8.

.PARAMETER UserIds
Explicit list (UPNs or IDs). When set, only those users are processed.

.PARAMETER LogLevel
None | Minimal | Standard | Debug

.PARAMETER IncludePhoneNumbers
If set, also fetches phone methods; phone columns get appended to the registration CSV.

.NOTES
Required scopes:
- UserAuthenticationMethod.Read.All (auth methods)
- User.Read.All (users list)
- Reports.Read.All (userRegistrationDetails)
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\MFA",
        [string]$Encoding = "UTF8",
        [string[]]$UserIds,
        [ValidateSet('None','Minimal','Standard','Debug')]
        [string]$LogLevel = 'Standard',
        [switch]$IncludePhoneNumbers
    )

    # ── Setup / logging ─────────────────────────────────────────────────────────
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebug = $script:LogLevel -eq [LogLevel]::Debug

    Write-LogFile -Message "=== Starting MFA Status Collection (fast) ===" -Color "Cyan" -Level Standard
    $requiredScopes = @("UserAuthenticationMethod.Read.All","User.Read.All","Reports.Read.All")
    $null = Get-GraphAuthType -RequiredScopes $RequiredScopes

    UpsertOutputDirectory $OutputDir
    $dateTag = (Get-Date).ToString('yyyyMMddHHmm')

    # Summary counters
    $summary = [ordered]@{
        TotalUsers            = 0
        MFAEnabled            = 0
        MFADisabled           = 0
        MethodCounts          = [ordered]@{
            Email                 = 0
            Fido2                 = 0
            App                   = 0
            Phone                 = 0
            SoftwareOath          = 0
            HelloBusiness         = 0
            TemporaryAccessPass   = 0
            CertificateBasedAuth  = 0
        }
        PhoneNumberUsers      = 0
        StartTime             = Get-Date
        ProcessingTime        = $null
    }

    # ── PS5-safe JSON helpers ──────────────────────────────────────────────────
    function J-GetElem { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ return $p.Value } } $null }
    function J-GetStr  { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ if($p.Value.ValueKind -eq 'String'){return $p.Value.GetString()} return $p.Value.ToString() } } $null }
    function J-HasName { param([System.Text.Json.JsonElement]$E,[string]$Name) foreach($p in $E.EnumerateObject()){ if($p.Name -eq $Name){ return $true } } $false }

    # ── Get users (minimal select) ──────────────────────────────────────────────
    Write-LogFile -Message "[INFO] Enumerating users..." -Level Standard

    $users = New-Object System.Collections.Generic.List[object]
    if ($UserIds -and $UserIds.Count) {
        foreach ($uid in $UserIds) {
            $u = $null
            try {
                $doc = Invoke-GraphGet -Uri ("$($script:BaseGraphUri)/v1.0/users/{0}?`$select=id,userPrincipalName" -f [Uri]::EscapeDataString($uid))
                try {
                    $root = $doc.RootElement
                    $id   = J-GetStr -E $root -Name 'id'
                    $upn  = J-GetStr -E $root -Name 'userPrincipalName'
                    if ($id) { [void]$users.Add([pscustomobject]@{ id=$id; userPrincipalName=$upn }) }
                } finally { $doc.Dispose() }
            } catch {
                Write-LogFile -Message "[WARNING] User not found: $uid" -Level Standard -Color "Yellow"
            }
        }
    } else {
        # Paged
        $uri = "$($script:BaseGraphUri)/v1.0/users?`$select=id,userPrincipalName&`$top=999"
        do {
            $doc = Invoke-GraphGet -Uri $uri
            try {
                $root = $doc.RootElement
                $val  = J-GetElem -E $root -Name 'value'
                if ($val -and $val.ValueKind -eq 'Array') {
                    for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                        $e = $val[$i]
                        $id  = J-GetStr -E $e -Name 'id'
                        $upn = J-GetStr -E $e -Name 'userPrincipalName'
                        if ($id) { [void]$users.Add([pscustomobject]@{ id=$id; userPrincipalName=$upn }) }
                    }
                }
                $next = $null
                foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink') { $next = $p.Value.GetString(); break } }
                $uri = $next
            } finally { $doc.Dispose() }
        } while ($uri)
    }

    $summary.TotalUsers = $users.Count
    Write-LogFile -Message "[INFO] Found $($summary.TotalUsers) users to process" -Level Standard
    if ($summary.TotalUsers -eq 0) {
        Write-LogFile -Message "[INFO] No users to process. Exiting." -Level Standard
        return
    }

    # ── Auth methods CSV (stream writer to avoid huge arrays) ──────────────────
    $methodsCsvPath = Join-Path $OutputDir "$dateTag-MFA-AuthenticationMethods.csv"
    $sw = New-Object System.IO.StreamWriter($methodsCsvPath,$false,[System.Text.Encoding]::GetEncoding($Encoding))
    try {
        $header = @(
            'user','MFAstatus','email','fido2','app','password','phone',
            'softwareoath','hellobusiness','temporaryAccessPass','certificateBasedAuthConfiguration'
        ) -join ','
        $sw.WriteLine($header)

        # Optional phone cache for later registration CSV enrichment
        $phoneCache = @{}  # upn -> list of phones (each is @{phoneNumber; phoneType; smsSignInState})

        # Batch in chunks of 20
        for ($offset=0; $offset -lt $users.Count; $offset += 20) {
            $chunk = $users[$offset..([Math]::Min($offset+19, $users.Count-1))]

            $reqs = New-Object System.Collections.Generic.List[object]
            foreach ($u in $chunk) {
                $url = "users/$($u.id)/authentication/methods"
                $reqs.Add(@{ id = $u.id; method = 'GET'; url = "$url" })
            }

            $resp = Invoke-GffBatch -Requests $reqs
            if (-not $resp.responses) { continue }

            foreach ($r in $resp.responses) {
                # r.id == user.id
                $uid = $r.id
                $user = $chunk | Where-Object { $_.id -eq $uid } | Select-Object -First 1
                if (-not $user) { continue }

                $flags = @{
                    email = $false; fido2 = $false; app = $false; password = $false; phone = $false;
                    softwareoath = $false; hellobusiness = $false; temporaryAccessPass = $false; certificateBasedAuthConfiguration = $false
                }
                $mfaEnabled = $false

                if ($r.status -ge 200 -and $r.status -lt 300 -and $r.body) {
                    # r.body is already deserialized (ConvertFrom-Json) by Invoke-GffBatch; if not, handle raw:
                    $methods = $r.body.value
                    foreach ($m in $methods) {
                        $t = $m.'@odata.type'
                        switch ($t) {
                            '#microsoft.graph.emailAuthenticationMethod' {
                                $flags.email = $true; $mfaEnabled = $true; $summary.MethodCounts.Email++ }
                            '#microsoft.graph.fido2AuthenticationMethod' {
                                $flags.fido2 = $true; $mfaEnabled = $true; $summary.MethodCounts.Fido2++ }
                            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                                $flags.app = $true; $mfaEnabled = $true; $summary.MethodCounts.App++ }
                            '#microsoft.graph.passwordAuthenticationMethod' {
                                $flags.password = $true }
                            '#microsoft.graph.phoneAuthenticationMethod' {
                                $flags.phone = $true; $mfaEnabled = $true; $summary.MethodCounts.Phone++
                                if ($IncludePhoneNumbers) {
                                    if (-not $phoneCache.ContainsKey($user.userPrincipalName)) { $phoneCache[$user.userPrincipalName] = @() }
                                    $phoneCache[$user.userPrincipalName] += @{
                                        phoneNumber   = $m.phoneNumber
                                        phoneType     = $m.phoneType
                                        smsSignInState= $m.smsSignInState
                                    }
                                }
                            }
                            '#microsoft.graph.softwareOathAuthenticationMethod' {
                                $flags.softwareoath = $true; $mfaEnabled = $true; $summary.MethodCounts.SoftwareOath++ }
                            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                                $flags.hellobusiness = $true; $mfaEnabled = $true; $summary.MethodCounts.HelloBusiness++ }
                            '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                                $flags.temporaryAccessPass = $true; $mfaEnabled = $true; $summary.MethodCounts.TemporaryAccessPass++ }
                            '#microsoft.graph.certificateBasedAuthConfiguration' {
                                $flags.certificateBasedAuthConfiguration = $true; $mfaEnabled = $true; $summary.MethodCounts.CertificateBasedAuth++ }
                            default { # ignore unknowns
                            }
                        }
                    }
                } else {
                    Write-LogFile -Message "[WARNING] Methods request failed for user $($user.userPrincipalName) (status=$($r.status))" -Level Standard -Color "Yellow"
                }

                if ($mfaEnabled) { $summary.MFAEnabled++ } else { $summary.MFADisabled++ }

                # Write CSV row quickly (no Export-Csv overhead)
                $row = @(
                    $user.userPrincipalName,
                    ($mfaEnabled ? 'Enabled' : 'Disabled'),
                    $flags.email,$flags.fido2,$flags.app,$flags.password,$flags.phone,
                    $flags.softwareoath,$flags.hellobusiness,$flags.temporaryAccessPass,$flags.certificateBasedAuthConfiguration
                ) | ForEach-Object { ($_ -is [bool]) ? ([string]$_) : ($_ -replace '"','""') }
                $sw.WriteLine(($row -join ','))
            }
        }

        if ($IncludePhoneNumbers) {
            # post-process phone cache for user counts
            foreach ($kv in $phoneCache.GetEnumerator()) {
                if ($kv.Value.Count -gt 0) { $summary.PhoneNumberUsers++ }
            }
        }
    }
    finally {
        $sw.Flush(); $sw.Dispose()
    }

    # ── User registration details (paged), then optional phone merge ───────────
    Write-LogFile -Message "[INFO] Retrieving user registration details..." -Level Standard
    $regCsvPath = Join-Path $OutputDir "$dateTag-MFA-UserRegistrationDetails.csv"

    # We'll collect into an ArrayList (fields are heterogeneous). For most tenants this is fine.
    $reg = New-Object System.Collections.ArrayList
    $uri = "$($script:BaseGraphUri)/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=999"

    do {
        $doc = Invoke-GraphGet -Uri $uri
        try {
            $root = $doc.RootElement
            $val  = J-GetElem -E $root -Name 'value'
            if ($val -and $val.ValueKind -eq 'Array') {
                for ($i=0; $i -lt $val.GetArrayLength(); $i++) {
                    $e = $val[$i]
                    $upn = J-GetStr -E $e -Name 'userPrincipalName'
                    if ($UserIds -and $UserIds.Count -gt 0) {
                        if (-not ($UserIds -contains $upn)) { continue }
                    }
                    # Flatten a curated subset to keep columns sane and fast
                    $obj = [ordered]@{
                        id                                = J-GetStr -E $e -Name 'id'
                        userPrincipalName                 = $upn
                        userDisplayName                   = J-GetStr -E $e -Name 'userDisplayName'
                        defaultMfaMethod                  = J-GetStr -E $e -Name 'defaultMfaMethod'
                        isMfaRegistered                   = J-GetStr -E $e -Name 'isMfaRegistered'
                        isSsprRegistered                  = J-GetStr -E $e -Name 'isSsprRegistered'
                        isSsprEnabled                     = J-GetStr -E $e -Name 'isSsprEnabled'
                        methodsRegisteredCount            = J-GetStr -E $e -Name 'methodsRegisteredCount'
                        methodsRegistered                 = $null
                    }

                    # methodsRegistered can be an array; keep as semi-colon list
                    $mr = $null
                    foreach ($p in $e.EnumerateObject()) {
                        if ($p.Name -eq 'methodsRegistered' -and $p.Value.ValueKind -eq 'Array') {
                            $tmp = New-Object System.Collections.Generic.List[string]
                            for ($j=0; $j -lt $p.Value.GetArrayLength(); $j++) { $tmp.Add($p.Value[$j].GetString()) }
                            $mr = [string]::Join('; ',$tmp)
                            break
                        }
                    }
                    $obj.methodsRegistered = $mr

                    if ($IncludePhoneNumbers) {
                        $phones = $null; $ptypes=$null; $sms=$null
                        if ($phoneCache.ContainsKey($upn)) {
                            $phList = $phoneCache[$upn]
                            if ($phList.Count -gt 0) {
                                $phones = [string]::Join('; ', ($phList | ForEach-Object { $_.phoneNumber }))
                                $ptypes = [string]::Join('; ', ($phList | ForEach-Object { $_.phoneType }))
                                $sms    = [string]::Join('; ', ($phList | ForEach-Object { $_.smsSignInState }))
                            }
                        }
                        $obj['MfaPhoneNumbers']   = $phones
                        $obj['MfaPhoneTypes']     = $ptypes
                        $obj['MfaSmsSignInStates']= $sms
                    }

                    [void]$reg.Add([pscustomobject]$obj)
                }
            }
            $next = $null
            foreach ($p in $root.EnumerateObject()) { if ($p.Name -eq '@odata.nextLink') { $next = $p.Value.GetString(); break } }
            $uri = $next
        }
        finally { $doc.Dispose() }
    } while ($uri)

    # Export registration CSV
    $reg | Export-Csv -Path $regCsvPath -NoTypeInformation -Encoding $Encoding

    # ── Summary ────────────────────────────────────────────────────────────────
    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    Write-LogFile -Message "`n=== MFA Status Analysis Summary ===" -Color "Cyan" -Level Standard
    Write-LogFile -Message "  Total Users   : $($summary.TotalUsers)" -Level Standard
    $pct = if ($summary.TotalUsers -gt 0) { [math]::Round($summary.MFAEnabled*100.0/$summary.TotalUsers,1) } else { 0 }
    Write-LogFile -Message "  MFA Enabled   : $($summary.MFAEnabled) users ($pct`%)" -Level Standard
    $pct2 = if ($summary.TotalUsers -gt 0) { [math]::Round($summary.MFADisabled*100.0/$summary.TotalUsers,1) } else { 0 }
    Write-LogFile -Message "  MFA Disabled  : $($summary.MFADisabled) users ($pct2`%)" -Level Standard
    if ($IncludePhoneNumbers) {
        Write-LogFile -Message "  Users with Phone MFA: $($summary.PhoneNumberUsers)" -Level Standard
    }
    Write-LogFile -Message "`nAuthentication Methods (counts):" -Level Standard
    Write-LogFile -Message "  Email                : $($summary.MethodCounts.Email)" -Level Standard
    Write-LogFile -Message "  Fido2                : $($summary.MethodCounts.Fido2)" -Level Standard
    Write-LogFile -Message "  Microsoft Auth App   : $($summary.MethodCounts.App)" -Level Standard
    Write-LogFile -Message "  Phone                : $($summary.MethodCounts.Phone)" -Level Standard
    Write-LogFile -Message "  Software OATH        : $($summary.MethodCounts.SoftwareOath)" -Level Standard
    Write-LogFile -Message "  Hello for Business   : $($summary.MethodCounts.HelloBusiness)" -Level Standard
    Write-LogFile -Message "  Temporary Access Pass: $($summary.MethodCounts.TemporaryAccessPass)" -Level Standard
    Write-LogFile -Message "  Cert Based Auth      : $($summary.MethodCounts.CertificateBasedAuth)" -Level Standard

    Write-LogFile -Message "`nOutput Files:" -Level Standard
    Write-LogFile -Message "  Authentication Methods: $methodsCsvPath" -Level Standard
    Write-LogFile -Message "  Registration Details  : $regCsvPath" -Level Standard
    Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}
